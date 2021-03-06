#include "includes.h"

using namespace CryptoPP;

#define DOCUMENTATION "Un-blinds the pre-signature using the same client_secret used to generate the blinded-hash. Also verifies the signature. The client secret should not be stored once it has served its purpose once."
#define USEAGE "blsig_get_unblinded_signature blind_signature blinded_hash client_secret public_key.pem"
#define ARGUMENT_COUNT 4

static Integer blinded_signature;
static Integer blinded_hash;
static Integer client_secret;
static RSA::PublicKey public_key;

int main(int argc, char *argv[])
{
    if(ARGUMENT_COUNT != --argc){
        std::cerr << "Incorrect useage of " << argv[0]
            << ". Expected " << ARGUMENT_COUNT << " arguments; given " << argc << "." << std::endl
            << "Useage: \n\t" << USEAGE << std::endl
            << DOCUMENTATION << std::endl;
        return EXIT_FAILURE;
    }

    try{
        blinded_signature = Integer(argv[1]);
        blinded_hash = Integer(argv[2]);
        client_secret = Integer(argv[3]);
        public_key = ReadPEMPublicKey(argv[4]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    if(PreverifySignature(blinded_signature, blinded_hash, public_key))
    {
        Integer unblinded_signature = SignatureUnblinding(blinded_signature, public_key, client_secret);

        std::cout << std::hex << unblinded_signature << std::endl;
        return EXIT_SUCCESS;
    }
    else
    {
        std::cerr << "There is a problem with the provided signature: it does not match the blinded hash." << std::endl;
        return EXIT_FAILURE;
    }
}



