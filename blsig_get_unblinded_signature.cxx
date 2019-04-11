#include <iostream>
#include <stdexcept>

#include "cryptopp810/rsa.h"
#include "cryptopp810/sha.h"
#include "cryptopp810/osrng.h"
#include "cryptopp810/integer.h"
#include "cryptopp810/cryptlib.h"
#include "cryptopp810/nbtheory.h"

using std::cout;
using std::endl;
using std::string;
using std::runtime_error;
using namespace CryptoPP;

int main(int argc, char *argv[])
{
    // Alice will verify signature
    if (!VerifySigning(signed_blinded, blinded, public_key))
    {
        cout << "Alice verification failed" << endl;
        exit(EXIT_FAILURE);
    }

    // Alice will remove blinding factor
    Integer signed_unblinded = MessageUnblinding(signed_blinded, client_secret, public_key);
    // return success
    return 0;
}

