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
#define KEY_SIZE 2048

static AutoSeededRandomPool rng_source;

void GenerateTestKeys(RSA::PrivateKey &private_key, RSA::PublicKey &public_key, size_t key_size)
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
    #endif
}

Integer GenerateHash(const string &message)
{
    SHA512 hash;
    SecByteBlock buff;

    SecByteBlock orig((const byte*)message.c_str(), message.size());

    buff.resize(SHA512::DIGESTSIZE);
    hash.CalculateDigest(buff, orig, orig.size());//why not a truncated digest?
    hash.CalculateTruncatedDigest(buff, buff.size(), orig, orig.size());

    Integer hashed_message(buff.data(), buff.size());

    #if DEBUG
        cout << "Message: " << message << endl;
        cout << "Hash: " << std::hex << hashed_message << endl;
    #endif

    return hashed_message;
}

Integer GenerateClientSecret(const RSA::PublicKey &public_key)
{
    const Integer &n = public_key.GetModulus();
    Integer client_secret;
    do
    {
        client_secret.Randomize(rng_source, Integer::One(), n - Integer::One());
    } while (!RelativelyPrime(client_secret, n));
    return client_secret;
}

Integer MessageBlinding(const Integer &hashed_message, const RSA::PublicKey &public_key, const Integer &client_secret)
{
    const Integer &n = public_key.GetModulus();
    const Integer &e = public_key.GetPublicExponent();

    Integer b = a_exp_b_mod_c(client_secret, e, n);

    #if DEBUG
        cout << "Random Client secret: " << std::hex << b << endl;
    #endif

    // Blinded payload
    Integer hidden_message = a_times_b_mod_c(hashed_message, b, n);

    // return blinded message
    return hidden_message;
}

Integer MessageUnblinding(const Integer &blinded_signature, const Integer &client_secret, const RSA::PublicKey &public_key)
{
    const Integer &n = public_key.GetModulus();

    Integer signed_unblinded = a_times_b_mod_c(blinded_signature, client_secret.InverseMod(n), n);

    #if DEBUG
        cout << "Signed Unblinded: " << std::hex << signed_unblinded << endl;
    #endif

    return signed_unblinded;
}

Integer SigningAuthority(const RSA::PrivateKey &private_key, const Integer &blinded_hash)
{
    #if DEBUG
        cout << "Generating signature..." << endl;
        cout << "Blinded Payload: " << std::hex << blinded_hash << endl;
    #endif

    Integer signed_message = private_key.CalculateInverse(rng_source, blinded_hash);

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
    GenerateTestKeys(private_key, public_key, KEY_SIZE);

    // Alice create a blind message
    Integer client_secret = GenerateClientSecret(public_key);
    string message = "Hello world! How are you doing to day? It's a pretty nice day if i do say so myself1.";
    Integer original_hash = GenerateHash(message);
    Integer blinded = MessageBlinding(original_hash, public_key, client_secret);

    // Send blinded message for signing
    Integer signed_blinded = SigningAuthority(private_key, blinded);

    // Alice will verify signature
    if (!VerifySigning(signed_blinded, blinded, public_key))
    {
        cout << "Alice verification failed" << endl;
        exit(EXIT_FAILURE);
    }

    // Alice will remove blinding factor
    Integer signed_unblinded = MessageUnblinding(signed_blinded, client_secret, public_key);

    // Eve verification stage
    Integer message_hash = GenerateHash(message);
    Integer received_hash = public_key.ApplyFunction(signed_unblinded);
    cout << "Signature payload: " << received_hash << endl;
    if (message_hash != received_hash)
    {
        cout << "Verification failed" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "Signature Verified" << endl;
    // return success
    return 0;
}
