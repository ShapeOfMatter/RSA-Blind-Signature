#define DEBUG 1
#include "includes.h"

using namespace CryptoPP;

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
    Integer client_secret = GenerateClientSecret(public_key, rng_source);
    string message = "Hello world! How are you doing to day? It's a pretty nice day if i do say so myself1.";
    Integer original_hash = GenerateHash(message);
    Integer blinded = MessageBlinding(original_hash, public_key, client_secret);

    // Send blinded message for signing
    Integer signed_blinded = SignBlindedMessage(private_key, blinded, rng_source);

    // Alice will remove blinding factor
    Integer signed_unblinded = SignatureUnblinding(signed_blinded, public_key, client_secret);

    // Eve verification stage
    Integer message_hash = GenerateHash(message);
    Integer received_hash = public_key.ApplyFunction(signed_unblinded);
    cout << "Signature payload: " << received_hash << endl;
    if (!VerifySignature(signed_unblinded, message_hash, public_key))
    {
        cout << "Verification failed" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "Signature Verified" << endl;
    // return success
    return EXIT_SUCCESS;
}

