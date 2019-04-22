#include "includes.h"

using namespace CryptoPP;

int main(int argc, char *argv[])
{
    if(4 != argc){
        fprintf(std::cerr, "Incorrect useage of %s. Expected %i arguments; given %i.", argv[0], 4, argc);
        return EXIT FAILURE;
    }

    try{
        Integer unblinded_signature = Integer(argv[1]);
        std::string message = argv[2];
        RSA::PublicKey public_key = ReadPEMPublicKey(argv[3]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what();
        return EXIT_FAILURE;
    }

    Integer hashed_message = GenerateHash(message);

    if(VerifySignature(unblinded_signature, hashed_message, public_key))
    {
        std::cout << "true" << std::endl;
        return EXIT_SUCCESS;
    }
    else
    {
        std::cerr << "That is not a valid signature for the provided message." << std::endl;
        return EXIT_FAILURE;
    }
}
