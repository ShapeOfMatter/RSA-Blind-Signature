#include "blsig_includes.h"

using namespace CryptoPP;

int main(int argc, char *argv[])
{
    if(3 != argc){
        fprintf(std::cerr, "Incorrect useage of %s. Expected %i arguments; given %i.", argv[0], 3, argc);
        return EXIT FAILURE;
    }

    try{
        std::string message = argv[1];
        Integer client_secret = Integer(argv[2]);
        RSA::PublicKey public_key = ReadPEMPublicKey(argv[3]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what();
        return EXIT_FAILURE;
    }
    
    Integer hashed_message = GenerateHash(message);
    Integer hidden_message = MessageBlinding(hashed_message, public_key, client_secret);

    std::cout << std::hex << hidden_message;
    return EXIT_SUCCESS;
}
