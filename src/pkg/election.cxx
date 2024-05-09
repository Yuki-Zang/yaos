#include "../../include/pkg/election.hpp"
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
 * Generate Vote and ZKP.
 */
std::pair<Vote_Ciphertext, VoteZKP_Struct>
ElectionClient::GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk) {
  initLogger();
  // TODO: implement me!
  // calculate the ciphertext
  // vote cipher only stores the ElGamal for the actual vote
  Vote_Ciphertext vote_cipher;
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::Integer r(rng, 2, DL_Q - 1); //yes should be [2, DL_Q-1]

  // ElGamal ciphertext (a, b) := (g^r, pk^r * g^v)
  CryptoPP::Integer c1 = ModularExponentiation(DL_G, r, DL_P);
  // c_2 = pk^r if v=0; =pk^r g if v=1
  CryptoPP::Integer c2 = a_times_b_mod_c(ModularExponentiation(pk, r, DL_P), ModularExponentiation(DL_G, vote, DL_P), DL_P);
  vote_cipher.a = c1;
  vote_cipher.b = c2;

  //now construct the zkp proof
  VoteZKP_Struct zkp_struct;
  CryptoPP::Integer ginv = CryptoPP::EuclideanMultiplicativeInverse(DL_G, DL_P);
  if (vote == 0){
    //simulate zkp for 1
    CryptoPP::Integer r1p(rng, 2, DL_Q - 1);
    CryptoPP::Integer sigma1(rng, 2, DL_Q - 1);
    CryptoPP::Integer invC1Sigma1 = CryptoPP::EuclideanMultiplicativeInverse(ModularExponentiation(c1, sigma1, DL_P), DL_P);
    CryptoPP::Integer invC2Sigma1 = CryptoPP::EuclideanMultiplicativeInverse(ModularExponentiation(a_times_b_mod_c(c2, ginv, DL_P), sigma1, DL_P), DL_P);
    CryptoPP::Integer gr1p = CryptoPP::ModularExponentiation(DL_G, r1p, DL_P);
    CryptoPP::Integer pkr1p = CryptoPP::ModularExponentiation(pk, r1p, DL_P);
    CryptoPP::Integer A1 = a_times_b_mod_c(gr1p, invC1Sigma1, DL_P);
    CryptoPP::Integer B1 = a_times_b_mod_c(pkr1p, invC2Sigma1, DL_P);
    
    //compute zkp for 0
    CryptoPP::Integer r0(rng, 2, DL_Q - 1);
    CryptoPP::Integer A0 = CryptoPP::ModularExponentiation(DL_G, r0, DL_P);
    CryptoPP::Integer B0 = CryptoPP::ModularExponentiation(pk, r0, DL_P);
    //now hash sigma and compute sigma0
    CryptoPP::Integer sigma = hash_vote_zkp(pk, c1, c2, A0, B0, A1, B1);
    CryptoPP::Integer sigma0 = (sigma - sigma1) % DL_Q;
    CryptoPP::Integer r0p = (r0 + a_times_b_mod_c(sigma0, r, DL_Q)) % DL_Q;

    zkp_struct.a0 = A0;
    zkp_struct.a1 = A1;
    zkp_struct.b0 = B0;
    zkp_struct.b1 = B1;
    zkp_struct.c0 = sigma0;
    zkp_struct.c1 = sigma1;
    zkp_struct.r0 = r0p;
    zkp_struct.r1 = r1p;

  }else{// in this case, we know that vote == 1 and simulate 0
    //simulate zkp for 0
    CryptoPP::Integer r0p(rng, 2, DL_Q - 1);
    CryptoPP::Integer sigma0(rng, 2, DL_Q - 1);
    CryptoPP::Integer invC1Sigma0 = CryptoPP::EuclideanMultiplicativeInverse(ModularExponentiation(c1, sigma0, DL_P), DL_P);
    CryptoPP::Integer invC2Sigma0 = CryptoPP::EuclideanMultiplicativeInverse(ModularExponentiation(c2, sigma0, DL_P), DL_P);
    CryptoPP::Integer gr0p = CryptoPP::ModularExponentiation(DL_G, r0p, DL_P);
    CryptoPP::Integer pkr0p = CryptoPP::ModularExponentiation(pk, r0p, DL_P);
    CryptoPP:: Integer A0 = a_times_b_mod_c(gr0p, invC1Sigma0, DL_P);
    CryptoPP:: Integer B0 = a_times_b_mod_c(pkr0p, invC2Sigma0, DL_P);

    //compute zkp for 1
    CryptoPP::Integer r1(rng, 2, DL_Q - 1);
    CryptoPP::Integer A1 = CryptoPP::ModularExponentiation(DL_G, r1, DL_P);
    CryptoPP::Integer B1 = CryptoPP::ModularExponentiation(pk, r1, DL_P);
    //now hash sigma and compute sigma0
    CryptoPP::Integer sigma = hash_vote_zkp(pk, c1, c2, A0, B0, A1, B1);
    CryptoPP::Integer sigma1 = (sigma - sigma0) % DL_Q; 
    CryptoPP::Integer r1p = (r1 + a_times_b_mod_c(sigma1, r, DL_Q)) % DL_Q;

    zkp_struct.a0 = A0;
    zkp_struct.a1 = A1;
    zkp_struct.b0 = B0;
    zkp_struct.b1 = B1;
    zkp_struct.c0 = sigma0;
    zkp_struct.c1 = sigma1;
    zkp_struct.r0 = r0p;
    zkp_struct.r1 = r1p;
  }
  return std::make_pair(vote_cipher, zkp_struct);
}

/**
 * Verify vote zkp.
 */
bool ElectionClient::VerifyVoteZKP(
    std::pair<Vote_Ciphertext, VoteZKP_Struct> vote, CryptoPP::Integer pk) {
  initLogger();
  // TODO: implement me!
  Vote_Ciphertext vote_cipher = vote.first;
  VoteZKP_Struct zkp = vote.second;
  CryptoPP::Integer c1 = vote_cipher.a;
  CryptoPP::Integer c2 = vote_cipher.b;
  CryptoPP::Integer sigma0 = zkp.c0;
  CryptoPP::Integer sigma1 = zkp.c1;

  //verify sigma0 + sigma1 = sigma
  //generate sigma from the hash oracle
  CryptoPP::Integer sigma = hash_vote_zkp(pk, c1, c2, zkp.a0, zkp.b0, zkp.a1, zkp.b1);
  bool sigmaMatch = (sigma0 + sigma1) % DL_Q == sigma;

  //verify encryption of 0 
  CryptoPP::Integer c1sigma0 = CryptoPP::ModularExponentiation(c1, sigma0, DL_P);
  CryptoPP::Integer gr0p = CryptoPP::ModularExponentiation(DL_G, zkp.r0, DL_P);
  bool gr0Match = gr0p == a_times_b_mod_c(zkp.a0, c1sigma0, DL_P);
  CryptoPP::Integer c2sigma0 = CryptoPP::ModularExponentiation(c2, sigma0, DL_P);
  CryptoPP::Integer pkr0p = CryptoPP::ModularExponentiation(pk, zkp.r0, DL_P);
  bool pkr0Match = pkr0p == a_times_b_mod_c(zkp.b0, c2sigma0, DL_P);

  //verify encryption of 1
  CryptoPP::Integer c1sigma1 = CryptoPP::ModularExponentiation(c1, sigma1, DL_P);
  CryptoPP::Integer gr1p = CryptoPP::ModularExponentiation(DL_G, zkp.r1, DL_P);
  bool gr1Match = gr1p == a_times_b_mod_c(zkp.a1, c1sigma1, DL_P);
  CryptoPP::Integer invc2g = CryptoPP::EuclideanMultiplicativeInverse(DL_G, DL_P);
  // (c2/g)^sigma1
  CryptoPP::Integer c2sigma1 = CryptoPP::ModularExponentiation(a_times_b_mod_c(c2, invc2g, DL_P), sigma1, DL_P);
  CryptoPP::Integer pkr1p = CryptoPP::ModularExponentiation(pk, zkp.r1, DL_P);
  bool pkr1Match = pkr1p == a_times_b_mod_c(zkp.b1, c2sigma1, DL_P);

  return sigmaMatch & gr0Match & pkr0Match & gr1Match & pkr1Match;
}

/**
 * Generate partial decryption and zkp.
 */
std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
ElectionClient::PartialDecrypt(Vote_Ciphertext combined_vote,
                               CryptoPP::Integer pk /*when called, input pk_i*/, CryptoPP::Integer sk) {
  initLogger();
  // TODO: implement me!
  // ElGamal ciphertext (a, b) := (g^r, pk^r * g^v)
  CryptoPP::Integer d = ModularExponentiation(combined_vote.a /*c_1*/, sk, DL_P);
  PartialDecryption_Struct pds;
  pds.d = d;
  pds.aggregate_ciphertext = combined_vote;

  // generate zkp
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::Integer r(rng, 2, DL_Q - 1);
  //Note: the order is reversed!
  CryptoPP::Integer A /*u*/ = ModularExponentiation(combined_vote.a, r, DL_P);
  CryptoPP::Integer B /*v*/ = ModularExponentiation(DL_G, r, DL_P);

  //assuming pk is the partial public key
  CryptoPP::Integer sigma = hash_dec_zkp(pk/*pk_i*/, combined_vote.a/*c1*/, combined_vote.b/*c2*/, A/*u*/, B/*v*/);
  CryptoPP::Integer s = (r + sigma * sk) % DL_Q; 

  DecryptionZKP_Struct dZkp;
  dZkp.u = A; dZkp.v = B; dZkp.s = s;
  return std::make_pair(pds, dZkp);
}

/**
 * Verify partial decryption zkp.
 */
bool ElectionClient::VerifyPartialDecryptZKP(
    ArbiterToWorld_PartialDecryption_Message a2w_dec_s, CryptoPP::Integer pki) {
  initLogger();
  // TODO: implement me!
  // following the notation from the doc
  CryptoPP::Integer a = a2w_dec_s.dec.aggregate_ciphertext.a;
  CryptoPP::Integer b = a2w_dec_s.dec.aggregate_ciphertext.b;
  CryptoPP::Integer d = a2w_dec_s.dec.d;
  CryptoPP::Integer u = a2w_dec_s.zkp.u;
  CryptoPP::Integer v = a2w_dec_s.zkp.v;
  CryptoPP::Integer s = a2w_dec_s.zkp.s;
  CryptoPP::Integer sigma = hash_dec_zkp(pki, a, b, u, v);

  //begin verify
  //check if g^s = A*pki^sigma
  CryptoPP::Integer udc = a_times_b_mod_c(u, CryptoPP::ModularExponentiation(d, sigma, DL_P), DL_P);
  CryptoPP::Integer as = CryptoPP::ModularExponentiation(a, s, DL_P);
  CryptoPP::Integer vpkc = a_times_b_mod_c(v, CryptoPP::ModularExponentiation(pki, sigma, DL_P), DL_P);
  CryptoPP::Integer gs = CryptoPP::ModularExponentiation(DL_G, s, DL_P);

  return udc == as & vpkc == gs;
}

/**
 * Combine votes into one using homomorphic encryption.
 */
Vote_Ciphertext ElectionClient::CombineVotes(std::vector<VoteRow> all_votes) {
  initLogger();
  // TODO: implement me!
  CryptoPP::Integer cumulativeA(1);
  CryptoPP::Integer cumulativeB(1);
  for (VoteRow voteRecord : all_votes) {
    cumulativeA = a_times_b_mod_c(cumulativeA, voteRecord.vote.a, DL_P);
    cumulativeB = a_times_b_mod_c(cumulativeB, voteRecord.vote.b, DL_P);
  }

  Vote_Ciphertext combined_vote;
  combined_vote.a = cumulativeA;
  combined_vote.b = cumulativeB;

  return combined_vote;
}

/**
 * Combine partial decryptions into final result.
 */
CryptoPP::Integer ElectionClient::CombineResults(
    Vote_Ciphertext combined_vote,
    std::vector<PartialDecryptionRow> all_partial_decryptions) {
  initLogger();
  // TODO: implement me!
  CryptoPP::Integer cumulativeD = CryptoPP::Integer::One();
  for (PartialDecryptionRow partDecrypt: all_partial_decryptions){
    cumulativeD = a_times_b_mod_c(cumulativeD, partDecrypt.dec.d, DL_P);
  }
  // ElGamal ciphertext (a, b) := (g^r, pk^r * g^v)
  CryptoPP::Integer c1 = combined_vote.a;
  CryptoPP::Integer c2 = combined_vote.b;
  
  //want to get m in g^m = c2/c1^sk
  CryptoPP::Integer invc1sk = CryptoPP::EuclideanMultiplicativeInverse(cumulativeD, DL_P);
  CryptoPP::Integer gm = a_times_b_mod_c(c2, invc1sk, DL_P);
  for (int m = 0; m < DL_Q; m++){ 
    if (CryptoPP::ModularExponentiation(DL_G, m, DL_P) == gm){
        return m;
    }
  }
  throw std::runtime_error("No matching m! Threshold Decryption Failed!");
}
