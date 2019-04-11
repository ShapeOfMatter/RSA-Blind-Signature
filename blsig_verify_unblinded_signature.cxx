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
    // Eve verification stage
    Integer message_hash = GenerateHash(message);
    Integer received_hash = public_key.ApplyFunction(signed_unblinded);
    cout << "Signature payload: " << received_hash << endl;
    if (message_hash != received_hash)
    {
        cout << "Verification failed" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "Signature Verified" << endl;
    // return success
    return 0;
}
