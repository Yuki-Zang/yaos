#include <algorithm>
#include <crypto++/misc.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/garbler.hpp"

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
GarblerClient::GarblerClient(Circuit circuit,
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
GarblerClient::HandleKeyExchange() {
  // Generate private/public DH keys
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^b
  DHPublicValue_Message garbler_public_value_s;
  garbler_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> garbler_public_value_data;
  garbler_public_value_s.serialize(garbler_public_value_data);
  network_driver->send(garbler_public_value_data);

  // Listen for g^a
  std::vector<unsigned char> evaluator_public_value_data =
      network_driver->read();
  DHPublicValue_Message evaluator_public_value_s;
  evaluator_public_value_s.deserialize(evaluator_public_value_data);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      evaluator_public_value_s.public_value);
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
 * 1) Generate a garbled circuit from the given circuit in this->circuit
 * 2) Send the garbled circuit to the evaluator
 * 3) Send garbler's input labels to the evaluator
 * 4) Send evaluator's input labels using OT
 * 5) Receive final labels, and use this to get the final output 
 (compare the final label with all possibles in ones/zeros to match)
 * `input` is the garbler's input for each gate
 * Final output should be a string containing only "0"s or "1"s
 * Throw errors only for invalid MACs
 */
std::string GarblerClient::run(std::vector<int> input) {
  // Key exchange
  auto [AES_key, HMAC_key] = this->HandleKeyExchange();

  // TODO: implement me!
  // Step 1: generate a garbled circuit
  GarbledLabels glabels = generate_labels(this->circuit);
  std::vector<GarbledGate> garbledGates = generate_gates(this->circuit, glabels);

  // Step 2: send the garbled circuit to the evaluator
  GarblerToEvaluator_GarbledTables_Message g2e_garbledTables_msg;
  g2e_garbledTables_msg.garbled_tables = garbledGates;
  std::vector<unsigned char> g2e_garbledTables_params = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &g2e_garbledTables_msg);
  this->network_driver->send(g2e_garbledTables_params);

  // Step 3: send the garbler's input to the evaluator
  GarblerToEvaluator_GarblerInputs_Message g2e_garblerinput_msg;
  std::vector<GarbledWire> inputWires = get_garbled_wires(glabels, input, 0);
  g2e_garblerinput_msg.garbler_inputs = inputWires;
  std::vector<unsigned char> g2e_garblerinput_params = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &g2e_garblerinput_msg);
  this->network_driver->send(g2e_garblerinput_params);

  // Step 4: send evaluator's input labels using OT
  for (int i = this->circuit.garbler_input_length; i < this->circuit.garbler_input_length + this->circuit.evaluator_input_length; i++){
    this->ot_driver->OT_send(byteblock_to_string(glabels.zeros[i].value), byteblock_to_string(glabels.ones[i].value));
  }

  // Step 5: receive final labels, and use this to get the final output
  EvaluatorToGarbler_FinalLabels_Message e2g_finalLabel_msg;
  auto[e2g_finalLabel_params, ifValid] = this->crypto_driver->decrypt_and_verify(AES_key, HMAC_key, this->network_driver->read());
  if (!ifValid){
    this->network_driver->disconnect();
    throw std::runtime_error("Evaluator identity authentication failed! Aborted.");
  }  
  e2g_finalLabel_msg.deserialize(e2g_finalLabel_params);
  std::vector<GarbledWire> final_labels = e2g_finalLabel_msg.final_labels;
  std::string final_output;
  for (GarbledWire gw: final_labels){
    for (int j = this->circuit.garbler_input_length + this->circuit.evaluator_input_length; j< this->circuit.num_wire; j++){
        if (glabels.zeros[j].value == gw.value){
            final_output += "0";
        }else if(glabels.ones[j].value == gw.value){
            final_output += "1";
        }else{
            std::cerr << "Warning: no matching" << std::endl;
        }
    }
  }

  // send the result to the evaluator
  GarblerToEvaluator_FinalOutput_Message g2e_finaloutput_msg;
  g2e_finaloutput_msg.final_output = final_output;
  std::vector<unsigned char> g2e_finaloutput_params = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &g2e_finaloutput_msg);
  this->network_driver->send(g2e_finaloutput_params);
  
  return final_output;
}

/**
 * Generate garbled gates for the circuit by encrypting each entry.
 * You may find `std::random_shuffle` useful
 */
std::vector<GarbledGate> GarblerClient::generate_gates(Circuit circuit,
                                                       GarbledLabels labels) {
  // TODO: implement me!
  std::vector<GarbledGate> garbledGates;

  //loop through each gate
  for (Gate gate: circuit.gates) {
    GarbledWire x0 = labels.zeros[gate.lhs];
    GarbledWire y0 = labels.zeros[gate.rhs];
    GarbledWire z0 = labels.zeros[gate.output];
    GarbledWire x1 = labels.ones[gate.lhs];
    GarbledWire y1 = labels.ones[gate.rhs];
    GarbledWire z1 = labels.ones[gate.output];
    
    CryptoPP::SecByteBlock c00;
    CryptoPP::SecByteBlock c01;
    CryptoPP::SecByteBlock c10;
    CryptoPP::SecByteBlock c11;
    if (gate.type == 1){//this is an AND gate
        c00 = encrypt_label(x0, y0, z0);
        c01 = encrypt_label(x0, y1, z0);
        c10 = encrypt_label(x1, y0, z0);
        c11 = encrypt_label(x1, y1, z1);
    }else if(gate.type == 2){//this is an XOR gate
        c00 = encrypt_label(x0, y0, z0);
        c01 = encrypt_label(x0, y1, z1);
        c10 = encrypt_label(x1, y0, z1);
        c11 = encrypt_label(x1, y1, z0);    
    }else if (gate.type == 3){//this is a NOT gate
        GarbledWire dummy;
        dummy.value = DUMMY_RHS;
        c00 = encrypt_label(x0, dummy, z1);
        c11 = encrypt_label(x1, dummy, z0);
    }else{
        throw std::runtime_error("Invalid gate type! Aborted.");
    }

    GarbledGate ggate;
    std::vector<CryptoPP::SecByteBlock> e;
    e.push_back(c00);
    e.push_back(c11);

    if (gate.type != 3){
        e.push_back(c01);
        e.push_back(c10);
    }
    //random shuffle
    std::srand(unsigned(std::time(0)));
    std::random_shuffle(e.begin(), e.end());

    ggate.entries = e;
    garbledGates.push_back(ggate);
  }
  return garbledGates;
}

/**
 * Generate labels for *every* wire in the circuit.
 * To generate an individual label, use `generate_label`.
 */
GarbledLabels GarblerClient::generate_labels(Circuit circuit) {
  // TODO: implement me!
  GarbledLabels glabels;
  std::vector<GarbledWire> zeros;
  std::vector<GarbledWire> ones;

  // ================= edits to delta, for FREE XOR ========================
  // delta should be universal across all labels
  // set last bit to 1 to enable point and permute
  CryptoPP::SecByteBlock delta = generate_label();
  CryptoPP:: Integer delta_int = byteblock_to_integer(delta);
  delta_int.SetBit(delta_int.BitCount() - 1, true);
  delta  = integer_to_byteblock(delta_int);
  // ================= edits to delta, for FREE XOR ========================

  for (int i = 0; i < circuit.num_wire; i++) {
    GarbledWire gw0;
    GarbledWire gw1;
    gw0.value = generate_label();
    CryptoPP::SecByteBlock label1(LABEL_LENGTH);
    CryptoPP::xorbuf(label1, gw0.value, delta, LABEL_LENGTH);
    gw1.value = label1;
    // gw1.value = generate_label();
    zeros.push_back(gw0);
    ones.push_back(gw1);
  }

  glabels.zeros = zeros;
  glabels.ones = ones;

  return glabels;
}
// namespace GateType {
// enum T { AND_GATE = 1, XOR_GATE = 2, NOT_GATE = 3 };
// };

// struct Gate {
//   GateType::T type;
//   int lhs;    // index corresponding to lhs wire
//   int rhs;    // index corresponding to rhs wire
//   int output; // index corresponding to output wire
// };

// struct Circuit {
//   int num_gate, num_wire, garbler_input_length, evaluator_input_length,
//       output_length;
//   std::vector<Gate> gates;
// };
// Circuit parse_circuit(std::string filename);

// ================================================
// GARBLED CIRCUIT
// ================================================

// struct GarbledWire {
//   CryptoPP::SecByteBlock value;
// };

// struct GarbledGate {
//   std::vector<CryptoPP::SecByteBlock> entries;
// };

// struct GarbledLabels {
//   std::vector<GarbledWire> zeros;
//   std::vector<GarbledWire> ones;
// };


/**
 * Generate the encrypted label given the lhs, rhs, and output of that gate.
 * Remember to tag LABEL_TAG_LENGTH trailing 0s to end before encrypting.
 * You may find CryptoDriver::hash_inputs, CryptoPP::SecByteBlock::CleanGrow,
 * and CryptoPP::xorbuf useful.
 */
CryptoPP::SecByteBlock GarblerClient::encrypt_label(GarbledWire lhs,
                                                    GarbledWire rhs,
                                                    GarbledWire output) {
  // TODO: implement me!
  CryptoPP::SecByteBlock left = this->crypto_driver->hash_inputs(lhs.value, rhs.value);
  CryptoPP::SecByteBlock right = output.value;
  right.CleanGrow(2*LABEL_TAG_LENGTH);
  CryptoPP::SecByteBlock result(2*LABEL_TAG_LENGTH); 
  CryptoPP::xorbuf(result, left, right, 2*LABEL_TAG_LENGTH);

  return result;
}

/**
 * Generate label.
 */
CryptoPP::SecByteBlock GarblerClient::generate_label() {
  CryptoPP::SecByteBlock label(LABEL_LENGTH);
  CryptoPP::OS_GenerateRandomBlock(false, label, label.size());
  return label;
}

/*
 * Given a set of 0/1 labels and an input vector of 0's and 1's, returns the
 * labels corresponding to the inputs starting at begin.
 */
std::vector<GarbledWire>
GarblerClient::get_garbled_wires(GarbledLabels labels, std::vector<int> input,
                                 int begin) {
  std::vector<GarbledWire> res;
  for (int i = 0; i < input.size(); i++) {
    switch (input[i]) {
    case 0:
      res.push_back(labels.zeros[begin + i]);
      break;
    case 1:
      res.push_back(labels.ones[begin + i]);
      break;
    default:
      std::cerr << "INVALID INPUT CHARACTER" << std::endl;
    }
  }
  return res;
}
