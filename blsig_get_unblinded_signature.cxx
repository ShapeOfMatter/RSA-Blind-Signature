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
    Integer blinded_signature; //Populate this from argv[1]
    Integer blinded_hash; //Populate this from argv[2]
    Integer client_secret; //Populate this from argv[3]
    RSA::PublicKey public_key; //Populate this from argv[4]

    if(PreverifySignature(blinded_signature, blinded_hash, public_key))
    {
        Integer unblinded_signature = SignatureUnblinding(blinded_signature, public_key, client_secret);

        //cout<<...
        return EXIT_SUCCESS;
    }
    else
    {
        std::cerr << "There is a problem with the provided signature: it does not match the blinded hash." << endl;
        return EXIT_FAILURE;
    }
}



