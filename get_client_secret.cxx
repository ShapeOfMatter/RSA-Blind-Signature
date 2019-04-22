#include "includes.h"

using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

#define ARGUMENT_COUNT 2 

int main(int argc, char *argv[])
{
    if(ARGUMENT_COUNT != argc){
        std::cerr << "Incorrect useage of " << argv[0] << ". Expected " << ARGUMENT_COUNT << "  arguments; given " << argc << ".";
        return EXIT_FAILURE;
    }
	
	RSA::PublicKey public_key;
    try{
        public_key = ReadPEMPublicKey(argv[1]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what();
        return EXIT_FAILURE;
    }

    Integer client_secret = GenerateClientSecret(public_key, rng_source);
    
    std::cout << std::hex << client_secret;
    return EXIT_SUCCESS;
}

