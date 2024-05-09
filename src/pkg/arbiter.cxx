#include "../../include/pkg/arbiter.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"

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
ArbiterClient::ArbiterClient(ArbiterConfig arbiter_config,
                             CommonConfig common_config) {
  // Make shared variables.
  this->arbiter_config = arbiter_config;
  this->common_config = common_config;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = std::make_shared<CryptoDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();

  // Load arbiter keys.
  try {
    LoadInteger(arbiter_config.arbiter_secret_key_path,
                this->EG_arbiter_secret_key);
    LoadInteger(arbiter_config.arbiter_public_key_path,
                this->EG_arbiter_public_key_i);
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find arbiter keys; you might consider generating some!");
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
}

void ArbiterClient::run() {
  // Start REPL
  REPLDriver<ArbiterClient> repl = REPLDriver<ArbiterClient>(this);
  repl.add_action("keygen", "keygen", &ArbiterClient::HandleKeygen);
  repl.add_action("adjudicate", "adjudicate", &ArbiterClient::HandleAdjudicate);
  repl.run();
}

/**
 * Handle generating election keys
 */
void ArbiterClient::HandleKeygen(std::string _) {
  // Generate keys
  this->cli_driver->print_info("Generating keys, this may take some time...");
  std::pair<CryptoPP::Integer, CryptoPP::Integer> keys =
      this->crypto_driver->EG_generate();

  // Save keys
  SaveInteger(this->arbiter_config.arbiter_secret_key_path, keys.first);
  SaveInteger(this->arbiter_config.arbiter_public_key_path, keys.second);
  LoadInteger(arbiter_config.arbiter_secret_key_path,
              this->EG_arbiter_secret_key);
  LoadInteger(arbiter_config.arbiter_public_key_path,
              this->EG_arbiter_public_key_i);
  LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                        this->EG_arbiter_public_key);
  this->cli_driver->print_success("Keys succesfully generated and saved!");
}

/**
 * Handle partial decryption. This function:
 * 1) Updates the ElectionPublicKey to the most up to date (done for you).
 * 2) Gets all of the votes from the database.
 * 3) Verifies all of the vote ZKPs and their signatures.
 *    If a vote is invalid, simply ignore it.
 * 4) Combines all valid votes into one vote via `Election::CombineVotes`.
 * 5) Partially decrypts the combined vote.
 * 6) Publishes the decryption and zkp to the database.
 */
void ArbiterClient::HandleAdjudicate(std::string _) {
  // Step 1 ----------------------------------
  // Ensure we have the most up-to-date election key
  LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                        this->EG_arbiter_public_key);
  // TODO: implement me!

  // Step 2 ----------------------------------
  // Get all of the votes from the database
  std::vector<VoteRow> allVotes = this->db_driver->all_votes();
  
  // Step 3 ----------------------------------
  // Verifies all vote ZKPs and their signatures
  std::vector<VoteRow> validVotes;
  for (VoteRow vote : allVotes){
    bool registerSig = this->crypto_driver->RSA_BLIND_verify(this->RSA_registrar_verification_key, vote.vote, vote.unblinded_signature);
    std::vector<unsigned char> concat_to_be_signed = concat_vote_zkp_and_signature(vote.vote, vote.zkp, vote.unblinded_signature);
    bool tallySign = this->crypto_driver->RSA_verify(this->RSA_tallyer_verification_key, concat_to_be_signed, vote.tallyer_signature);
    bool voteVer = ElectionClient::VerifyVoteZKP(std::make_pair(vote.vote, vote.zkp), this->EG_arbiter_public_key);

    if (registerSig && tallySign && voteVer){
        validVotes.push_back(vote);
    }
  }

  // Step 4 ----------------------------------
  // Combine all valid votes
  Vote_Ciphertext validCombo_cipher = ElectionClient::CombineVotes(validVotes);
  
  // Step 5 ----------------------------------
  // Partially Decrypts
  auto[partialDecrpt_struct, decryptionZKP_struct] = ElectionClient::PartialDecrypt(validCombo_cipher, this->EG_arbiter_public_key_i, this->EG_arbiter_secret_key);
  
  // Step 6 ----------------------------------
  // Publish the decryption and zkp to the database
  ArbiterToWorld_PartialDecryption_Message a2w_partialDecrypt_msg;
  a2w_partialDecrypt_msg.arbiter_id = this->arbiter_config.arbiter_id;
  a2w_partialDecrypt_msg.arbiter_vk_path = this->arbiter_config.arbiter_public_key_path;
  a2w_partialDecrypt_msg.dec = partialDecrpt_struct;
  a2w_partialDecrypt_msg.zkp = decryptionZKP_struct;

  this->db_driver->insert_partial_decryption(a2w_partialDecrypt_msg);
}