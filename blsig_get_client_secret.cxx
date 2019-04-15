#include <iostream>
#include <stdexcept>

#include "cryptopp810/rsa.h"
#include "cryptopp810/sha.h"
#include "cryptopp810/osrng.h"
#include "cryptopp810/integer.h"
#include "cryptopp810/cryptlib.h"
#include "cryptopp810/nbtheory.h"

#define DEBUG 0
#include "blsig_common_functions.h"
#include "blsig_inner_functions.h"

using std::cout;
using std::endl;
using std::string;
using std::runtime_error;
using namespace CryptoPP;

static AutoSeededRandomPool rng_source;

int main(int argc, char *argv[])
{
    RSA::PublicKey public_key; //Populate this from argv[1]

    Integer client_secret = GenerateClientSecret(public_key, rng_source);
    
    //cout << safe string version of client_secret.
    return 0;
}
