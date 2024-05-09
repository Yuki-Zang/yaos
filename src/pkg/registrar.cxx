#include "../../include/pkg/registrar.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"

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
RegistrarClient::RegistrarClient(RegistrarConfig registrar_config,
                                 CommonConfig common_config) {
  // Make shared variables.
  this->registrar_config = registrar_config;
  this->common_config = common_config;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();

  // Load registrar keys.
  try {
    LoadRSAPrivateKey(registrar_config.registrar_signing_key_path,
                      this->RSA_registrar_signing_key);
    LoadRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find registrar keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.RSA_generate_keys();
    this->RSA_registrar_signing_key = keys.first;
    this->RSA_registrar_verification_key = keys.second;

    SaveRSAPrivateKey(registrar_config.registrar_signing_key_path,
                      this->RSA_registrar_signing_key);
    SaveRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  }

  // Load election public key
  try {
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading arbiter public keys; "
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

void RegistrarClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&RegistrarClient::ListenForConnections, this,
                              port);
  listener_thread.detach();

  // Wait for a sign to exit.
  std::string message;
  this->cli_driver->print_info("enter \"exit\" to exit");
  while (std::getline(std::cin, message)) {
    if (message == "exit") {
      this->db_driver->close();
      return;
    }
  }
}

/**
 * Listen for new connections
 */
void RegistrarClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&RegistrarClient::HandleRegister, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle key exchange with voter
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
RegistrarClient::HandleKeyExchange(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver) {
  // Generate private/public DH keys
  auto dh_values = crypto_driver->DH_initialize();

  // Listen for g^a
  std::vector<unsigned char> user_public_value = network_driver->read();
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.deserialize(user_public_value);

  // Respond with m = (g^b, g^a) signed with our private RSA key
  ServerToUser_DHPublicValue_Message public_value_s;
  public_value_s.server_public_value = std::get<2>(dh_values);
  public_value_s.user_public_value = user_public_value_s.public_value;
  public_value_s.server_signature = crypto_driver->RSA_sign(
      this->RSA_registrar_signing_key,
      concat_byteblocks(public_value_s.server_public_value,
                        public_value_s.user_public_value));

  // Sign and send message
  std::vector<unsigned char> message_bytes;
  public_value_s.serialize(message_bytes);
  network_driver->send(message_bytes);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      user_public_value_s.public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle new registration. This function:
 * 1) Handles key exchange.
 * 2) Gets user info and verifies that the user hasn't already registered.
 *    (if already registered, return existing signature).
 * 3) Blindly signs the user's message and sends it to the user.
 * 4) Adds the user to the database and disconnects.
 * Disconnect and throw an error if any MACs are invalid.
 */
void RegistrarClient::HandleRegister(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver) {
  // TODO: implement me!
  // --------------------------------
  // Step 1: Handles key exchange
  auto[AES_key, HMAC_key] = HandleKeyExchange(network_driver, crypto_driver);
  
  // Step 2: Gets user info and verifies that the user hasn't already registered
  VoterToRegistrar_Register_Message v2r_register_msg;
  std::cout << "here okay" << std::endl;
  auto[params_voter, isFromVoter] = crypto_driver -> decrypt_and_verify(AES_key, HMAC_key, network_driver->read());
  std::cout << "receive okay" << std::endl;
  if (! isFromVoter){
    network_driver->disconnect();
    throw std::runtime_error("Voter-Registrar HandleRegister: Not from Voter!");
  }
  v2r_register_msg.deserialize(params_voter);
  std::cout << "In Register HandleRegister: receive blinded vote OK" << std::endl;

  // Step 3: blindly sign and send back
  VoterRow voter = this->db_driver->find_voter(v2r_register_msg.id);
  RegistrarToVoter_Blind_Signature_Message r2v_blind_sig_msg;
  std::cout << "In Register HandleRegister: voter_id:" << voter.id << std::endl;
  if (voter.id != ""){//has already signed
    r2v_blind_sig_msg = voter;
    std::cout << "In Register HandleRegister: retrieve voter okay:" << voter.id << std::endl;
  } else{//new voter
    CryptoPP::Integer blind_sign = crypto_driver->RSA_BLIND_sign(this->RSA_registrar_signing_key, v2r_register_msg.vote);
    r2v_blind_sig_msg.id = v2r_register_msg.id;
    r2v_blind_sig_msg.registrar_signature = blind_sign;
    std::cout << "In Register HandleRegister: add new voter okay:" << voter.id << std::endl;
  }
  // Step 4: Add user and disconnect
  std::vector<unsigned char> params_r2v_blind_sign = crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &r2v_blind_sig_msg);
  network_driver->send(params_r2v_blind_sign);
  std::cout << "In Register HandleRegister: send blinded sign okay:" << voter.id << std::endl;
  this->db_driver->insert_voter(r2v_blind_sig_msg);
  std::cout << "In Register HandleRegister: insert blinded sign okay:" << voter.id << std::endl;
  network_driver->disconnect();
  std::cout << "In Register HandleRegister: function okay" << voter.id << std::endl;
}
