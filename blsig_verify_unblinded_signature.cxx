#include "blsig_includes.h"

using namespace CryptoPP;

int main(int argc, char *argv[])
{
    Integer unblinded_signature; //Populate this from argv[1]
    std::string message; //Populate this from argv[2]
    RSA::PublicKey public_key; //Populate this from argv[3]
    
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
