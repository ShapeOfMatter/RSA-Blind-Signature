#include "includes.h"

using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

#define ARGUMENT_COUNT 1
static RSA::PublicKey public_key;

int main(int argc, char *argv[])
{
    if(ARGUMENT_COUNT != --argc){
        std::cerr << "Incorrect useage of " << argv[0] << ". Expected " << ARGUMENT_COUNT << "  arguments; given " << argc << "." << std::endl;
        return EXIT_FAILURE;
    }
	
    try{
        public_key = ReadPEMPublicKey(argv[1]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    Integer client_secret = GenerateClientSecret(public_key, rng_source);
    
    std::cout << std::hex << client_secret << std::endl;
    return EXIT_SUCCESS;
}

