#include <iostream>
#include <stdexcept>

#include "cryptopp810/rsa.h"
#include "cryptopp810/sha.h"
#include "cryptopp810/osrng.h"
#include "cryptopp810/integer.h"
#include "cryptopp810/cryptlib.h"
#include "cryptopp810/nbtheory.h"

using std::cout;
using std::endl;
using std::string;
using std::runtime_error;
using namespace CryptoPP;

#define DEBUG    1
#define KEY_SIZE 1024

static AutoSeededRandomPool rng_source;

void GenerateKeys(RSA::PrivateKey &private_key, RSA::PublicKey &public_key, size_t key_size=1024)
{
    #if DEBUG
        cout << "Generating Keys..." << endl;
    #endif

    private_key.GenerateRandomWithKeySize(rng_source, key_size);
    public_key = RSA::PublicKey(private_key);

    #if DEBUG
        const Integer &n = public_key.GetModulus();
        const Integer &e = public_key.GetPublicExponent();
        const Integer &d = private_key.GetPrivateExponent();

        cout << "Modulus: " << std::hex << n << endl;
        cout << "Public Exponent: " << std::hex << e << endl;
        cout << "Private Exponent: " << std::hex << d << endl;
    #endif
}

Integer GenerateHash(const string &message)
{
    SHA512 hash;
    SecByteBlock buff;

    SecByteBlock orig((const byte*)message.c_str(), message.size());

    buff.resize(SHA512::BLOCKSIZE);
    hash.CalculateDigest(buff, orig, orig.size());

    Integer hm(buff.data(), buff.size());

    #if DEBUG
        cout << "Message: " << message << endl;
        cout << "Hash: " << std::hex << hm << endl;
    #endif

    return hm;
}

Integer MessageBlinding(const Integer &message, const RSA::PublicKey &public_key, Integer &random)
{
    const Integer &n = public_key.GetModulus();
    const Integer &e = public_key.GetPublicExponent();

    // Blinding factor r
    do
    {
        random.Randomize(rng_source, Integer::One(), n - Integer::One());
    } while (!RelativelyPrime(random, n));

    Integer b = a_exp_b_mod_c(random, e, n);

    #if DEBUG
        cout << "Random: " << std::hex << b << endl;
    #endif

    // Blinded message
    Integer hidden_message = a_times_b_mod_c(message, b, n);

    // return blinded message
    return hidden_message;
}

Integer MessageUnblinding(const Integer &message, const Integer &random, const RSA::PublicKey &public_key)
{
    const Integer &n = public_key.GetModulus();

    Integer signed_unblinded = a_times_b_mod_c(message, random, n);

    #if DEBUG
        cout << "Signed Unblinded: " << std::hex << signed_unblinded << endl;
    #endif

    return signed_unblinded;
}

Integer SigningAuthority(const RSA::PrivateKey &private_key, const Integer &message)
{
    #if DEBUG
        cout << "Generating signature..." << endl;
        cout << "Message: " << std::hex << message << endl;
    #endif

    Integer signed_message = private_key.CalculateInverse(rng_source, message);

    #if DEBUG
        cout << "Signed Message: " << std::hex << signed_message << endl;
    #endif

    return signed_message;
}

bool VerifySigning(const Integer &message, const Integer &original, const RSA::PublicKey &public_key)
{
    return public_key.ApplyFunction(message) == original;
}

int main(int argc, char *argv[])
{
    RSA::PublicKey public_key;
    RSA::PrivateKey private_key;

    // generate public and private keys
    GenerateKeys(private_key, public_key, KEY_SIZE);

    // Alice create a blind message
    Integer random;
    string message = "Hello world!";
    Integer original = GenerateHash(message);
    Integer blinded = MessageBlinding(original, public_key, random);

    // Send blinded message for signing
    Integer signed_blinded = SigningAuthority(private_key, blinded);

    // Alice will verify signature
    if (!VerifySigning(signed_blinded, blinded, public_key))
    {
        cout << "Alice verification failed" << endl;
        exit(EXIT_FAILURE);
    }

    // Alice will remove blinding factor
    Integer signed_unblinded = MessageUnblinding(signed_blinded, random, public_key);

    // Eve verification stage
    Integer message_hash = GenerateHash(message);
    Integer received_hash = public_key.ApplyFunction(signed_unblinded);
    if (message_hash == received_hash)
    {
        cout << "Verification failed" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "Signature Verified" << endl;
    // return success
    return 0;
}
