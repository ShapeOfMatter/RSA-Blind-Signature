#include "includes.h"

using namespace CryptoPP;

#define ARGUMENT_COUNT 3
static std::string message;
static Integer client_secret;
static RSA::PublicKey public_key;

int main(int argc, char *argv[])
{
    if(ARGUMENT_COUNT != --argc){
        std::cerr << "Incorrect useage of " << argv[0] << ". Expected " << ARGUMENT_COUNT << "  arguments; given " << argc << "." << std::endl;
        return EXIT_FAILURE;
    }
    
    try{
        message = argv[1];
        client_secret = Integer(argv[2]);
        public_key = ReadPEMPublicKey(argv[3]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    
    Integer hashed_message = GenerateHash(message);
    Integer hidden_message = MessageBlinding(hashed_message, public_key, client_secret);

    std::cout << std::hex << hidden_message << std::endl;
    return EXIT_SUCCESS;
}
