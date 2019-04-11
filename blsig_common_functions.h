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

Integer GenerateHash(const string &message)
{
    SHA512 hash;
    SecByteBlock buff;

    SecByteBlock orig((const byte*)message.c_str(), message.size());

    buff.resize(SHA512::DIGESTSIZE);
    hash.CalculateDigest(buff, orig, orig.size());//why not a truncated digest?
    hash.CalculateTruncatedDigest(buff, buff.size(), orig, orig.size());

    Integer hashed_message(buff.data(), buff.size());

    #if DEBUG
        cout << "Message: " << message << endl;
        cout << "Hash: " << std::hex << hashed_message << endl;
    #endif

    return hashed_message;
}

