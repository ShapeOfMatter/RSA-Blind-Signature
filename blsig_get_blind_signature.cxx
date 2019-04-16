#include "blsig_includes.h"

using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

int main(int argc, char *argv[])
{
    std::string blinded_hash; //Populate this from argv[1]
    RSA::PublicKey public_key; //Populate this from argv[2]

    Integer signed_message = SignBlindedMessage(blinded_hash, private_key, rng_source);
    
    //std::cout << safe std::string version of signed_message.
    return EXIT_SUCCESS;
}

