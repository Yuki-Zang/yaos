#include "../../include/pkg/voter.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"
#include "util.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor
 */
VoterClient::VoterClient(std::shared_ptr<NetworkDriver> network_driver,
                         std::shared_ptr<CryptoDriver> crypto_driver,
                         VoterConfig voter_config, CommonConfig common_config) {
  // Make shared variables.
  this->voter_config = voter_config;
  this->common_config = common_config;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();
  initLogger();

  // Load election public key
  try {
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading arbiter public keys; "
                                    "application may be non-functional.");
  }

  // Load registrar public key
  try {
    LoadRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading registrar public key; "
                                    "application may be non-functional.");
  }

  // Load tallyer public key
  try {
    LoadRSAPublicKey(common_config.tallyer_verification_key_path,
                     this->RSA_tallyer_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading tallyer public key; application may be non-functional.");
  }

  // Load vote info (vote, zkp, registrar signature, and blind)
  // This is info voter should generate or receive after registering
  try {
    Vote_Ciphertext vote;
    LoadVote(this->voter_config.voter_vote_path, vote);
    this->vote = vote;

    VoteZKP_Struct zkp;
    LoadVoteZKP(this->voter_config.voter_vote_zkp_path, zkp);
    this->vote_zkp = zkp;

    CryptoPP::Integer registrar_signature;
    LoadInteger(this->voter_config.voter_registrar_signature_path,
                registrar_signature);
    this->registrar_signature = registrar_signature;

    CryptoPP::Integer blind;
    LoadInteger(this->voter_config.voter_blind_path, blind);
    this->blind = blind;
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading vote info; voter may still need to register.");
  }
}

/**
 * Run REPL
 */
void VoterClient::run() {
  // Start REPL
  REPLDriver<VoterClient> repl = REPLDriver<VoterClient>(this);
  repl.add_action("register", "register <address> <port> {0, 1}",
                  &VoterClient::HandleRegister);
  repl.add_action("vote", "vote <address> <port>", &VoterClient::HandleVote);
  repl.add_action("verify", "verify", &VoterClient::HandleVerify);
  repl.run();
}

/**
 * Key exchange with either registrar or tallyer
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
VoterClient::HandleKeyExchange(CryptoPP::RSA::PublicKey verification_key) {
  // Generate private/public DH values
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^a
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> user_public_value_data;
  user_public_value_s.serialize(user_public_value_data);
  this->network_driver->send(user_public_value_data);

  // 2) Receive m = (g^a, g^b) signed by the server
  std::vector<unsigned char> server_public_value_data =
      this->network_driver->read();
  ServerToUser_DHPublicValue_Message server_public_value_s;
  server_public_value_s.deserialize(server_public_value_data);

  // Verify signature
  bool verified = this->crypto_driver->RSA_verify(
      verification_key,
      concat_byteblocks(server_public_value_s.server_public_value,
                        server_public_value_s.user_public_value),
      server_public_value_s.server_signature);
  if (!verified) {
    this->cli_driver->print_warning("Signature verification failed");
    throw std::runtime_error("Voter: failed to verify server signature.");
  }
  if (server_public_value_s.user_public_value != std::get<2>(dh_values)) {
    this->cli_driver->print_warning("Session validation failed");
    throw std::runtime_error(
        "Voter: inconsistencies in voter public DH value.");
  }

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      server_public_value_s.server_public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle registering with the registrar. This function:
 * 1) Handle key exchange.
 * 2) ElGamal encrypt the raw vote and generate a ZKP for it
 *    through `ElectionClient::GenerateVote`.
 * 2) Blind the vote and send it to the registrar.
 * 3) Receive the blind signature from the registrar and save it.
//  * 3) Receives and saves the signature from the server.
 */
void VoterClient::HandleRegister(std::string input) {
  // Parse input and connect to registrar
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 4) {
    this->cli_driver->print_warning("usage: register <address> <port> <vote>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // Load some info from config into variables
  std::string voter_id = this->voter_config.voter_id;
  CryptoPP::Integer raw_vote = CryptoPP::Integer(std::stoi(args[3]));
  
  // TODO: implement me!
  // Step 1: Handle Key Exchange
  auto[AES_key, HMAC_key] = HandleKeyExchange(this->RSA_registrar_verification_key);
  std::cout << "In Voter HandleRegister: HandleKeyExchange OK" << std::endl;
  // Step 2: ElGamal encrypt the raw vote and generate ZKP
  // CHECK: if the public key is used correctly!
  auto[vote_cipher, vote_zkp] = ElectionClient::GenerateVote(raw_vote, this->EG_arbiter_public_key /*check if this is the correct key*/);
  std::cout << "In Voter HandleRegister: GenerateVote OK" << std::endl;
  // Step 3: blind the vote and send it to the registrar
  // should be the registrar's verification key
  auto[blinded_vote, blind_factor] = this->crypto_driver->RSA_BLIND_blind(this->RSA_registrar_verification_key, vote_cipher);
  std::cout << "In Voter HandleRegister: RSA_BLIND_blind OK" << std::endl;
  //prepare and send

  VoterToRegistrar_Register_Message v2r_register_msg;
  v2r_register_msg.id = this->voter_config.voter_id; //this->id
  v2r_register_msg.vote = blinded_vote;
  std::vector<unsigned char> params_v2r_register_msg = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &v2r_register_msg);
  this->network_driver->send(params_v2r_register_msg);
  std::cout << "In Voter HandleRegister: send OK" << std::endl;

  // Step 4: receive the blind signature from the registrar and save it

  RegistrarToVoter_Blind_Signature_Message r2v_blind_sig_msg;
  auto[params_blind, isFromReg] = crypto_driver -> decrypt_and_verify(AES_key, HMAC_key, network_driver->read());
  r2v_blind_sig_msg.deserialize(params_blind);
  if (! isFromReg){
    throw std::runtime_error("Not from registrar!");
  }
  std::cout << "In Voter HandleRegister: receive OK" << std::endl;
  // r: blind factor; signature: from blind signature

  // Save the ElGamal encrypted vote, ZKP, registrar signature, and blind
  // to both memory and disk
  // [STUDENTS] You may have named the RHS variables below differently.
  // Rename them to match your code.
  this->vote = vote_cipher;
  this->vote_zkp = vote_zkp;
  this->registrar_signature = r2v_blind_sig_msg.registrar_signature;
  this->blind = blind_factor;
  SaveVote(this->voter_config.voter_vote_path, vote_cipher);
  SaveVoteZKP(this->voter_config.voter_vote_zkp_path, vote_zkp);
  SaveInteger(this->voter_config.voter_registrar_signature_path,
              r2v_blind_sig_msg.registrar_signature);
  SaveInteger(this->voter_config.voter_blind_path, blind_factor);

  this->cli_driver->print_info(
      "Voter registered! Vote saved at " + this->voter_config.voter_vote_path +
      " and vote zkp saved at " + this->voter_config.voter_vote_zkp_path);
  this->network_driver->disconnect();
  std::cout << "In Voter HandleRegister: handle registration OK" << std::endl;
}

/**
 * Handle voting with the tallyer. This function:
 * 1) Handles key exchange.
 * 2) Unblinds the registrar signature that is stored in `this->registrar_signature`. 
 * 3) Sends the vote, ZKP, and unblinded signature to the tallyer
 */
void VoterClient::HandleVote(std::string input) {
  // Parse input and connect to tallyer
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 3) {
    this->cli_driver->print_warning("usage: vote <address> <port>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // TODO: implement me!
  // --------------------------------
  // Step 1: Handle Key Exchange
  auto[AES_key, HMAC_key] = HandleKeyExchange(this->RSA_tallyer_verification_key);
  std::cout << "In Voter handle vote: key exchange okay" << std::endl;
  // Step 2: Unblinds the registrar signature 
  CryptoPP::Integer unblinded_s = this->crypto_driver->RSA_BLIND_unblind(this->RSA_registrar_verification_key, this->registrar_signature, this->blind);
  std::cout << "In Voter handle vote: unblind okay" << std::endl;

  // Step 3: Sends info to tallyer
  VoterToTallyer_Vote_Message v2t_vote_msg;
  v2t_vote_msg.vote = this->vote;
  v2t_vote_msg.unblinded_signature = unblinded_s;
  v2t_vote_msg.zkp = this->vote_zkp;

  std::vector<unsigned char> params_v2t_vote_msg = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &v2t_vote_msg);
  this->network_driver->send(params_v2t_vote_msg);

  std::cout << "In Voter handle vote: send info okay" << std::endl;
  // Exit cleanly.
  this->network_driver->disconnect();
}

/**
 * Handle verifying the results of the election.
 */
void VoterClient::HandleVerify(std::string input) {
  // Verify
  this->cli_driver->print_info("Verifying election results...");
  auto result = this->DoVerify();

  // Error if election failed
  if (!std::get<2>(result)) {
    this->cli_driver->print_warning("Election failed!");
    throw std::runtime_error("Election failed!");
  }

  // Print results
  this->cli_driver->print_success("Election succeeded!");
  this->cli_driver->print_success("Number of votes for 0: " +
                                  CryptoPP::IntToString(std::get<0>(result)));
  this->cli_driver->print_success("Number of votes for 1: " +
                                  CryptoPP::IntToString(std::get<1>(result)));
}

/**
 * Handle verifying the results of the election. This function
 * 1) Verifies all vote ZKPs and their signatures
 * 2) Verifies all partial decryption ZKPs
 * 3) Combines the partial decryptions to retrieve the final result
 * 4) Returns a tuple of <0-votes, 1-votes, success>
 * If a vote is invalid, simply *ignore* it: do not throw an error.
 */
std::tuple<CryptoPP::Integer, CryptoPP::Integer, bool> VoterClient::DoVerify() {
  // TODO: implement me!
  std::vector<VoteRow> allVotes = this->db_driver->all_votes();
  std::vector<PartialDecryptionRow> allParDec = this->db_driver->all_partial_decryptions();
  std::vector<VoteRow> allValidRow;

  for (VoteRow vote : allVotes){
    bool voteVer = ElectionClient::VerifyVoteZKP(std::make_pair(vote.vote, vote.zkp), this->EG_arbiter_public_key);
    std::vector<unsigned char> concat_to_be_signed = concat_vote_zkp_and_signature(vote.vote, vote.zkp, vote.unblinded_signature);
    bool tallySign = this->crypto_driver->RSA_verify(this->RSA_tallyer_verification_key, concat_to_be_signed, vote.tallyer_signature);
    bool registerSig = this->crypto_driver->RSA_BLIND_verify(this->RSA_registrar_verification_key, vote.vote, vote.unblinded_signature);
    std::cout << "In do verfiy: RSA_BLIND_verify OK" << std::endl;
    
    if (voteVer && tallySign && registerSig){
        allValidRow.push_back(vote);
    }
  }
  //combine the partial dec
  Vote_Ciphertext combined_vote_cipher = ElectionClient::CombineVotes(allValidRow);

  for (PartialDecryptionRow dec : allParDec){
    CryptoPP::Integer pkj;
    LoadInteger(dec.arbiter_vk_path, pkj);
    bool ifValidDec = ElectionClient::VerifyPartialDecryptZKP(dec, pkj);
    if (!ifValidDec){
        std::tuple<CryptoPP::Integer, CryptoPP::Integer, bool> result(CryptoPP::Integer::Zero(), CryptoPP::Integer::Zero(), false);
        return result;
    }
  }

  //combine the partial dec
  CryptoPP::Integer combined_results /*num 1-votes*/ = ElectionClient::CombineResults(combined_vote_cipher, allParDec);

  std::tuple<CryptoPP::Integer, CryptoPP::Integer, bool> result(allValidRow.size() - combined_results, combined_results, true);
  return result;
}
