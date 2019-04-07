#include "./cryptopp810/cryptlib.h"
#include "./cryptopp810/integer.h"
#include "./cryptopp810/nbtheory.h"
#include "./cryptopp810/osrng.h"
#include "./cryptopp810/rsa.h"
#include "./cryptopp810/sha.h"
using namespace CryptoPP;

#include <iostream>
#include <stdexcept>
using std::cout;
using std::endl;
using std::runtime_error;

int main(int argc, char* argv[])
{
    // Bob artificially small key pair
    AutoSeededRandomPool prng;
    RSA::PrivateKey privKey;

    privKey.GenerateRandomWithKeySize(prng, 64);
    RSA::PublicKey pubKey(privKey);

    // Convenience
    const Integer& n = pubKey.GetModulus();
    const Integer& e = pubKey.GetPublicExponent();
    const Integer& d = privKey.GetPrivateExponent();

    // Print params
    cout << "Pub mod: " << std::hex << pubKey.GetModulus() << endl;
    cout << "Pub exp: " << std::hex << e << endl;
    cout << "Priv mod: " << std::hex << privKey.GetModulus() << endl;
    cout << "Priv exp: " << std::hex << d << endl;

    // For sizing the hashed message buffer. This should be SHA256 size.
    const size_t SIG_SIZE = UnsignedMin(SHA256::BLOCKSIZE, n.ByteCount());

    // Scratch
    SecByteBlock buff1, buff2, buff3;

    // Alice original message to be signed by Bob
    SecByteBlock orig((const byte*)"secret", 6);
    Integer m(orig.data(), orig.size());
    cout << "Message: " << std::hex << m << endl;

    // Hash message per Rabin (1979)
    buff1.resize(SIG_SIZE);
    SHA256 hash1;
    hash1.CalculateTruncatedDigest(buff1, buff1.size(), orig, orig.size());

    // H(m) as Integer
    Integer hm(buff1.data(), buff1.size());
    cout << "H(m): " << std::hex << hm << endl;

    // Alice blinding
    Integer r;
    do {
        r.Randomize(prng, Integer::One(), n - Integer::One());
    } while (!RelativelyPrime(r, n));

    // Blinding factor
    Integer b = a_exp_b_mod_c(r, e, n);
    cout << "Random: " << std::hex << b << endl;

    // Alice blinded message
    Integer mm = a_times_b_mod_c(hm, b, n);
    cout << "Blind msg: " << std::hex << mm << endl;

    // Bob sign
    Integer ss = privKey.CalculateInverse(prng, mm);
    cout << "Blind sign: " << ss << endl;

    // Alice checks s(s'(x)) = x. This is from Chaum's paper
    Integer c = pubKey.ApplyFunction(ss);
    cout << "Check sign: " << c << endl;
    if (c != mm)
        throw runtime_error("Alice cross-check failed");

    // Alice remove blinding
    Integer s = a_times_b_mod_c(ss, r.InverseMod(n), n);
    cout << "Unblind sign: " << s << endl;

    // Eve verifies
    Integer v = pubKey.ApplyFunction(s);    
    cout << "Verify: " << std::hex << v << endl;

    // Convert to a string
    size_t req = v.MinEncodedSize();
    buff2.resize(req);
    v.Encode(&buff2[0], buff2.size());

    // Hash message per Rabin (1979)
    buff3.resize(SIG_SIZE);
    SHA256 hash2;
    hash2.CalculateTruncatedDigest(buff3, buff3.size(), orig, orig.size());

    // Constant time compare
    bool equal = buff2.size() == buff3.size() && VerifyBufsEqual(
        buff2.data(), buff3.data(), buff3.size());

    if (!equal)
        throw runtime_error("Eve verified failed");

    cout << "Verified signature" << endl;

    return 0;
}
