#include "../../include/pkg/evaluator.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor. Note that the OT_driver is left uninitialized.
 */
EvaluatorClient::EvaluatorClient(Circuit circuit,
                                 std::shared_ptr<NetworkDriver> network_driver,
                                 std::shared_ptr<CryptoDriver> crypto_driver) {
  this->circuit = circuit;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  initLogger(logging::trivial::severity_level::trace);
}

/**
 * Handle key exchange with evaluator
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
EvaluatorClient::HandleKeyExchange() {
  // Generate private/public DH keys
  auto dh_values = this->crypto_driver->DH_initialize();

  // Listen for g^b
  std::vector<unsigned char> garbler_public_value_data = network_driver->read();
  DHPublicValue_Message garbler_public_value_s;
  garbler_public_value_s.deserialize(garbler_public_value_data);

  // Send g^a
  DHPublicValue_Message evaluator_public_value_s;
  evaluator_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> evaluator_public_value_data;
  evaluator_public_value_s.serialize(evaluator_public_value_data);
  network_driver->send(evaluator_public_value_data);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      garbler_public_value_s.public_value);
  CryptoPP::SecByteBlock AES_key =
      this->crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      this->crypto_driver->HMAC_generate_key(DH_shared_key);
  auto keys = std::make_pair(AES_key, HMAC_key);
  this->ot_driver =
      std::make_shared<OTDriver>(network_driver, crypto_driver, keys);
  return keys;
}

/**
 * run. This function should:
 * 1) Receive the garbled circuit and the garbler's input
 * 2) Reconstruct the garbled circuit and input the garbler's inputs
 * 3) Retrieve evaluator's inputs using OT
 * 4) Evaluate gates in order (use `evaluate_gate` to help!)
 * 5) Send final labels to the garbler
 * 6) Receive final output
 * `input` is the evaluator's input for each gate
 * You may find `resize` useful before running OT
 * You may also find `string_to_byteblock` useful for converting OT output to
 * wires Disconnect and throw errors only for invalid MACs
 */
std::string EvaluatorClient::run(std::vector<int> input) {
  // Key exchange
  auto [AES_key, HMAC_key] = this->HandleKeyExchange();

  // TODO: implement me!
  // Step garbled_wires.resize(num_wire);
  // Step 1: receive garbled circuit and the garbler's input
  GarblerToEvaluator_GarbledTables_Message g2e_garbledTables_msg;
  auto[g2e_garbledTables_params, ifValid] = this->crypto_driver->decrypt_and_verify(AES_key, HMAC_key, this->network_driver->read());
  if (!ifValid){
    this->network_driver->disconnect();
    throw std::runtime_error("Garbler identity authentication failed! Aborted.");
  } 
  g2e_garbledTables_msg.deserialize(g2e_garbledTables_params);
  std::vector<GarbledGate> garbled_tables = g2e_garbledTables_msg.garbled_tables; 
  
  GarblerToEvaluator_GarblerInputs_Message g2e_garblerInput_msg;
  auto[g2e_garblerInput_params, ifValid1] = this->crypto_driver->decrypt_and_verify(AES_key, HMAC_key, this->network_driver->read());
  if (!ifValid1){
    this->network_driver->disconnect();
    throw std::runtime_error("Garbler identity authentication failed! Aborted.");
  } 
  g2e_garblerInput_msg.deserialize(g2e_garblerInput_params);
  std::vector<GarbledWire> garbler_inputs = g2e_garblerInput_msg.garbler_inputs; 

  // Step 2: reconstruct the vector of garbledWires
  std::vector<GarbledWire> gwires_all;
  //fill in the input from garbler
  for (GarbledWire gw_garbler: garbler_inputs){
    gwires_all.push_back(gw_garbler);
  }

  // Step 3: Retrieve evaluator's input using OT
  for (int i: input){
    SecByteBlock inputlabel = string_to_byteblock(this->ot_driver->OT_recv(i));
    GarbledWire gw_evaluator;
    gw_evaluator.value = inputlabel;
    gwires_all.push_back(gw_evaluator);
  }

  // Step 4: Evaluate gates in order
  gwires_all.resize(this->circuit.num_wire);
  for (int i = 0; i<garbled_tables.size(); i++){
    // if (this->circuit.gates[i].type == 1 || this->circuit.gates[i].type == 2){//this is an AND/OR gate
    //     GarbledWire gw_output = evaluate_gate(garbled_tables[i], gwires_all[this->circuit.gates[i].lhs], gwires_all[this->circuit.gates[i].rhs]);
    //     gwires_all[this->circuit.gates[i].output] = gw_output;
    // }
    if (this->circuit.gates[i].type == 1){//this is an AND gate
        GarbledWire gw_output = evaluate_gate(garbled_tables[i], gwires_all[this->circuit.gates[i].lhs], gwires_all[this->circuit.gates[i].rhs]);
        gwires_all[this->circuit.gates[i].output] = gw_output;
    } else if (this->circuit.gates[i].type == 2){//OR gate
        SecByteBlock decrypted_entry(LABEL_LENGTH);
        CryptoPP::xorbuf(decrypted_entry, gwires_all[this->circuit.gates[i].lhs].value, gwires_all[this->circuit.gates[i].rhs].value, LABEL_LENGTH);
        GarbledWire gw_output;
        gw_output.value = decrypted_entry;
        gwires_all[this->circuit.gates[i].output] = gw_output;
    }
    else if (this->circuit.gates[i].type == 3){//NOT gate
        GarbledWire dummy;
        dummy.value = DUMMY_RHS;
        GarbledWire gw_output = evaluate_gate(garbled_tables[i], gwires_all[this->circuit.gates[i].lhs], dummy);
        gwires_all[this->circuit.gates[i].output] = gw_output;
    }else{
        throw std::runtime_error("Invalid gate type!");
    }
    // gwires_all.push_back(gw_output);
  }
  
  // Step 5: Send final labels to the garbler
  EvaluatorToGarbler_FinalLabels_Message e2g_finalLabel_msg;
  std::vector<GarbledWire> gwires_output;
  for (int j = 0; j<this->circuit.output_length; j++){
    gwires_output.push_back(gwires_all[this->circuit.num_wire - this->circuit.output_length +j]);
  }
  e2g_finalLabel_msg.final_labels = gwires_output;
  std::vector<unsigned char> e2g_finalLabel_params = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &e2g_finalLabel_msg);
  this->network_driver->send(e2g_finalLabel_params);

  // Step 6: Receive final output
  GarblerToEvaluator_FinalOutput_Message g2e_finaloutput_msg;
  auto[g2e_finaloutput_params, ifValid2] = this->crypto_driver->decrypt_and_verify(AES_key, HMAC_key, this->network_driver->read());
  if (!ifValid2){
    this->network_driver->disconnect();
    throw std::runtime_error("Garbler identity authentication failed! Aborted.");
  }  
  g2e_finaloutput_msg.deserialize(g2e_finaloutput_params);
  return g2e_finaloutput_msg.final_output;
}

/**
 * Evaluate gate.
 * You may find CryptoPP::xorbuf and CryptoDriver::hash_inputs useful.
 * To determine if a decryption is valid, use verify_decryption.
 * To retrieve the label from a decryption, use snip_decryption.
 */
GarbledWire EvaluatorClient::evaluate_gate(GarbledGate gate, GarbledWire lhs,
                                           GarbledWire rhs) {
  // TODO: implement me!
  GarbledWire gw;
  for (CryptoPP::SecByteBlock encryption: gate.entries){
    //for each encryption:
    CryptoPP::SecByteBlock decrypt_key = this->crypto_driver->hash_inputs(lhs.value, rhs.value);
    CryptoPP::SecByteBlock decryption(2*LABEL_TAG_LENGTH); 
    CryptoPP::xorbuf(decryption, encryption, decrypt_key, 2*LABEL_TAG_LENGTH);

    //verify and extract
    if(verify_decryption(decryption)){//true
        gw.value = snip_decryption(decryption);
        return gw;
    }
  }
//   throw std::runtime_error("No valid decryption.");
  return gw;
}

/**
 * Verify decryption. A valid dec should end with LABEL_TAG_LENGTH bits of 0s.
 */
bool EvaluatorClient::verify_decryption(CryptoPP::SecByteBlock decryption) {
  CryptoPP::SecByteBlock trail(decryption.data() + LABEL_LENGTH,
                               LABEL_TAG_LENGTH);
  return byteblock_to_integer(trail) == CryptoPP::Integer::Zero();
}

/**
 * Returns the first LABEL_LENGTH bits of a decryption.
 */
CryptoPP::SecByteBlock
EvaluatorClient::snip_decryption(CryptoPP::SecByteBlock decryption) {
  CryptoPP::SecByteBlock head(decryption.data(), LABEL_LENGTH);
  return head;
}
