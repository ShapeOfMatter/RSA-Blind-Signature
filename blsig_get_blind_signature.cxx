#include "blsig_includes.h"

using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

int main(int argc, char *argv[])
{
    if(2 != argc){
        fprintf(std::cerr, "Incorrect useage of %s. Expected %i arguments; given %i.", argv[0], 2, argc);
        return EXIT FAILURE;
    }

    try{
        std::string blinded_hash = argv[1];
        RSA::PublicKey public_key = ReadPEMPublicKey(argv[2]);
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

