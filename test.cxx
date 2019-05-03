#define DEBUG 1
#include "includes.h"

using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

int main(int argc, char *argv[])
{
    if(0 == std::system(NULL)
            || 0 != std::system("which openssl")
            || 0 != std::system("which rm")){
        std::cerr << "The test script will not work on this system." << std::endl;
        exit(EXIT_FAILURE);
    }

    std::system("openssl genrsa -out scratch/._blsig_test_rsa_key_priv.pem 2048");
    std::system("openssl rsa -in scratch/._blsig_test_rsa_key_priv.pem -out scratch/._blsig_test_rsa_key_pub.pem -pubout");

    FileSource public_key_file("scratch/._blsig_test_rsa_key_pub.pem", true);
    FileSource private_key_file("scratch/._blsig_test_rsa_key_priv.pem", true);
    RSA::PublicKey public_key;
    RSA::PrivateKey private_key;
    PEM_Load(public_key_file, public_key);
    PEM_Load(private_key_file, private_key);

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

