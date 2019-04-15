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
    string message; //Populate this from argv[1]
    Integer client_secret; //Populate this from argv[2]
    RSA::PublicKey public_key; //Populate this from argv[3]

    Integer hashed_message = GenerateHash(message);
    Integer hidden_message = MessageBlinding(hashed_message, public_key, client_secret);

    // cout << safe string version of blinded hash.
    return 0;
}
