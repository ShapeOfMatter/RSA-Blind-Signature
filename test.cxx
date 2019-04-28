#define DEBUG 1
#include "includes.h"

using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

void GenerateTestKeys(RSA::PrivateKey &private_key, RSA::PublicKey &public_key, size_t key_size)
{
    #if DEBUG
        std::cout << "Generating Keys..." << std::endl;
    #endif

    private_key.GenerateRandomWithKeySize(rng_source, key_size);
    public_key = RSA::PublicKey(private_key);

    #if DEBUG
        const Integer &n = public_key.GetModulus();
        const Integer &e = public_key.GetPublicExponent();
        const Integer &d = private_key.GetPrivateExponent();

        std::cout << "Modulus: " << std::hex << n << std::endl;
        std::cout << "Public Exponent: " << std::hex << e << std::endl;
    #endif
}
int main(int argc, char *argv[])
{
    RSA::PublicKey public_key;
    RSA::PrivateKey private_key;

    // generate public and private keys
    GenerateTestKeys(private_key, public_key, 2048);

    // Alice create a blind message
    Integer client_secret = GenerateClientSecret(public_key, rng_source);
    std::string message = "Hello world! How are you doing to day? It's a pretty nice day if i do say so myself1.";
    Integer original_hash = GenerateHash(message);
    Integer blinded = MessageBlinding(original_hash, public_key, client_secret);

    // Send blinded message for signing
    Integer signed_blinded = SignBlindedMessage(blinded, private_key, rng_source);

    // Alice will remove blinding factor
    Integer signed_unblinded = SignatureUnblinding(signed_blinded, public_key, client_secret);

    // Eve verification stage
    Integer message_hash = GenerateHash(message);
    Integer received_hash = public_key.ApplyFunction(signed_unblinded);
    std::cout << "Signature payload: " << received_hash << std::endl;
    if (!VerifySignature(signed_unblinded, message_hash, public_key))
    {
        std::cout << "Verification failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Signature Verified" << std::endl;
    // return success
    return EXIT_SUCCESS;
}

