#include "includes.h"

using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

#define ARGUMENT_COUNT 2
static Integer blinded_hash;
static RSA::PrivateKey private_key;

int main(int argc, char *argv[])
{
    if(ARGUMENT_COUNT != --argc){
        std::cerr << "Incorrect useage of " << argv[0] << ". Expected " << ARGUMENT_COUNT << "  arguments; given " << argc << ".";
        return EXIT_FAILURE;
    }

    try{
        blinded_hash = Integer(argv[1]);
        private_key = ReadPEMPrivateKey(argv[2]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what();
        return EXIT_FAILURE;
    }
    
    Integer signed_message = SignBlindedMessage(blinded_hash, private_key, rng_source);
    
    std::cout << std::hex << signed_message;
    return EXIT_SUCCESS;
}

