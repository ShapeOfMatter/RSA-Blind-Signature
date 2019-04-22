#include "blsig_includes.h"

using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

int main(int argc, char *argv[])
{
    if(1 != argc){
        fprintf(std::cerr, "Incorrect useage of %s. Expected %i arguments; given %i.", argv[0], 1, argc);
        return EXIT FAILURE;
    }

    try{
        RSA::PublicKey public_key = ReadPEMPublicKey(argv[1]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what();
        return EXIT_FAILURE;
    }

    Integer client_secret = GenerateClientSecret(public_key, rng_source);
    
    std::cout << std::hex << of client_secret;
    return EXIT_SUCCESS;
}

