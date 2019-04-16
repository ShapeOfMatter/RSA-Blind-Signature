#include "blsig_includes.h"

using namespace CryptoPP;

int main(int argc, char *argv[])
{
    std::string message; //Populate this from argv[1]
    Integer client_secret; //Populate this from argv[2]
    RSA::PublicKey public_key; //Populate this from argv[3]

    Integer hashed_message = GenerateHash(message);
    Integer hidden_message = MessageBlinding(hashed_message, public_key, client_secret);

    // std::cout << safe string version of blinded hash.
    return EXIT_SUCCESS;
}
