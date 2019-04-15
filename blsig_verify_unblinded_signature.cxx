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

int main(int argc, char *argv[])
{
    Integer unblinded_signature; //Populate this from argv[1]
    Integer hashed_message; //Populate this from argv[2]
    RSA::PublicKey public_key; //Populate this from argv[3]
    
    if(VerifySignature(unblinded_signature, hashed_message, public_key))
    {
        cout << "true" << endl;
        return EXIT_SUCCESS;
    }
    else
    {
        std::cerr << "That is not a valid signature for the provided message." << endl;
        return EXIT_FAILURE;
    }
}
