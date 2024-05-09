#include <iostream>
#include <stdexcept>
#include <string>

#include "crypto++/base64.h"
#include "crypto++/dsa.h"
#include "crypto++/osrng.h"
#include "crypto++/rsa.h"
#include <crypto++/cryptlib.h>
#include <crypto++/elgamal.h>
#include <crypto++/files.h>
#include <crypto++/hkdf.h>
#include <crypto++/nbtheory.h>
#include <crypto++/queue.h>
#include <crypto++/sha.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/ot_driver.hpp"

/*
 * Constructor
 */
OTDriver::OTDriver(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->AES_key = keys.first;
  this->HMAC_key = keys.second;
  this->cli_driver = std::make_shared<CLIDriver>();
}

/*
 * Send either m0 or m1 using OT. This function should:
 * 1) Sample a public DH value and send it to the receiver
 * 2) Receive the receiver's public value
 * 3) Encrypt m0 and m1 using different keys
 * 4) Send the encrypted values
 * You may find `byteblock_to_integer` and `integer_to_byteblock` useful
 * Disconnect and throw errors only for invalid MACs
 */
void OTDriver::OT_send(std::string m0, std::string m1) {
  // TODO: implement me!

  // Step 1: sample and send over public dh value
  auto[dh_obj, a, A] = this->crypto_driver->DH_initialize();
  SenderToReceiver_OTPublicValue_Message s2r_ot_pval_msg;
  s2r_ot_pval_msg.public_value  = A;
  std::vector<unsigned char> s2r_ot_pval_params = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &s2r_ot_pval_msg);
  this->network_driver->send(s2r_ot_pval_params);
  
  // Step 2: receive the receiver's public value
  ReceiverToSender_OTPublicValue_Message r2s_ot_pval_msg;
  auto[r2s_ot_pval_params, ifValid] = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, this->network_driver->read());
  if (!ifValid){
    this->network_driver->disconnect();
    throw std::runtime_error("Receiver identity authentication failed! Aborted.");
  }
  r2s_ot_pval_msg.deserialize(r2s_ot_pval_params);
  CryptoPP::SecByteBlock B = r2s_ot_pval_msg.public_value;
   
  // Step 3: encrypt m0 and m1 using different keys
  // CryptoPP::SecByteBlock k0 = this->crypto_driver->AES_generate_key(integer_to_byteblock(CryptoPP::ModularExponentiation(byteblock_to_integer(B), byteblock_to_integer(a), DL_P)));
  // CryptoPP::SecByteBlock k1 = this->crypto_driver->AES_generate_key(integer_to_byteblock(CryptoPP::ModularExponentiation(
    // a_times_b_mod_c(byteblock_to_integer(B),CryptoPP::EuclideanMultiplicativeInverse(byteblock_to_integer(A), DL_P), DL_P), byteblock_to_integer(a), DL_P)));

  CryptoPP::SecByteBlock k0 = this->crypto_driver->AES_generate_key(this->crypto_driver->DH_generate_shared_key(dh_obj, a, B));
  CryptoPP::SecByteBlock BAinv = integer_to_byteblock(a_times_b_mod_c(byteblock_to_integer(B),CryptoPP::EuclideanMultiplicativeInverse(byteblock_to_integer(A), DL_P), DL_P));
  CryptoPP::SecByteBlock k1 = this->crypto_driver->AES_generate_key(this->crypto_driver->DH_generate_shared_key(dh_obj, a, BAinv));
  //encrypt
  auto[e0, iv0] = this->crypto_driver->AES_encrypt(k0, m0);
  auto[e1, iv1] = this->crypto_driver->AES_encrypt(k1, m1);

  // Step 4: send the encrypted values
  SenderToReceiver_OTEncryptedValues_Message s2r_ot_encrypteed_msg;
  s2r_ot_encrypteed_msg.e0 = e0;
  s2r_ot_encrypteed_msg.e1 = e1;
  s2r_ot_encrypteed_msg.iv0 = iv0;
  s2r_ot_encrypteed_msg.iv1 = iv1;

  std::vector<unsigned char> s2r_ot_encrypteed_pamras = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &s2r_ot_encrypteed_msg);
  this->network_driver->send(s2r_ot_encrypteed_pamras);
}

/*
 * Receive m_c using OT. This function should:
 * 1) Read the sender's public value
 * 2) Respond with our public value that depends on our choice bit
 * 3) Generate the appropriate key and decrypt the appropriate ciphertext
 * You may find `byteblock_to_integer` and `integer_to_byteblock` useful
 * Disconnect and throw errors only for invalid MACs
 */
std::string OTDriver::OT_recv(int choice_bit) {
  // TODO: implement me!
  
  // Step 1: read the sender's public value
  SenderToReceiver_OTPublicValue_Message s2r_ot_pval_msg;
  auto[s2r_ot_pval_params, ifValid] = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, this->network_driver->read());
  if (!ifValid){
    this->network_driver->disconnect();
    throw std::runtime_error("Sender identity authentication failed! Aborted.");
  }
  s2r_ot_pval_msg.deserialize(s2r_ot_pval_params);
  CryptoPP::SecByteBlock A = s2r_ot_pval_msg.public_value;

  // Step 2: respond with our public value that depends on our choice bit
  auto[dh_obj, b, gb] = this->crypto_driver->DH_initialize();
  CryptoPP::SecByteBlock B;
  if (choice_bit == 0){
    B = gb;
  }else{
    B = integer_to_byteblock(a_times_b_mod_c(byteblock_to_integer(A), byteblock_to_integer(gb), DL_P));
  }
  ReceiverToSender_OTPublicValue_Message r2s_ot_pval_msg;
  r2s_ot_pval_msg.public_value = B;
  std::vector<unsigned char> r2s_ot_pval_params = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &r2s_ot_pval_msg);
  this->network_driver->send(r2s_ot_pval_params);

  // Step 3: generate the appropriate key and decrypt the appropriate ciphertext
  CryptoPP::SecByteBlock kc = this->crypto_driver->AES_generate_key(this->crypto_driver->DH_generate_shared_key(dh_obj, b, A));

  SenderToReceiver_OTEncryptedValues_Message s2r_ot_encrypteed_msg;
  auto[s2r_ot_encrypteed_params, ifValid1] = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, this->network_driver->read());
  if (!ifValid1){
    this->network_driver->disconnect();
    throw std::runtime_error("Sender identity authentication failed! Aborted.");  
  }
  s2r_ot_encrypteed_msg.deserialize(s2r_ot_encrypteed_params);

  //decrypt
  if (choice_bit == 0){
    return this->crypto_driver->AES_decrypt(kc, s2r_ot_encrypteed_msg.iv0, s2r_ot_encrypteed_msg.e0);
  }else{
    return this->crypto_driver->AES_decrypt(kc, s2r_ot_encrypteed_msg.iv1, s2r_ot_encrypteed_msg.e1);
  }
}