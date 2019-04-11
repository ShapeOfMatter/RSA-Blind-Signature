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

