#include "includes.h"

using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

#define DOCUMENTATION "Generates a \"pre-signature\" (or hashed signature or whatever you want to call it) without any knowledge of the message, the message-hash, or the client secret."
#define USEAGE "blsig_get_blind_signature blinded_hash private_key.pem"
#define ARGUMENT_COUNT 2

static Integer blinded_hash;
static RSA::PrivateKey private_key;

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
        blinded_hash = Integer(argv[1]);
        private_key = ReadPEMPrivateKey(argv[2]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    
    Integer signed_message = SignBlindedMessage(blinded_hash, private_key, rng_source);
    
    std::cout << std::hex << signed_message << std::endl;
    return EXIT_SUCCESS;
}

