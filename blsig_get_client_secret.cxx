#include "blsig_includes.h"

using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

int main(int argc, char *argv[])
{
    RSA::PublicKey public_key; //Populate this from argv[1]

    Integer client_secret = GenerateClientSecret(public_key, rng_source);
    
    //cout << safe string version of client_secret.
    return 0;
}
