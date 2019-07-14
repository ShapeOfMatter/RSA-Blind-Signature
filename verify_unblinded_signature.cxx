#include "includes.h"

using namespace CryptoPP;

#define DOCUMENTATION "Confirms that a provided signature is a valid signature, by the corresponding private-key, of the provided message. Prints true for success."
#define USEAGE "blsig_verify_unblinded_signature unblinded_signature message public_key.pem"
#define ARGUMENT_COUNT 3

static Integer unblinded_signature;
static std::string message;
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
        unblinded_signature = Integer(argv[1]);
        message = argv[2];
        public_key = ReadPEMPublicKey(argv[3]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what() << std::endl;
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
