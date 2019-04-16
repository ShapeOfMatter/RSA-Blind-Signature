#ifndef BLSIG_COMMON_H_INCLUDED
# define BLSIG_COMMON_H_INCLUDED
# include "blsig_includes.h"

using namespace CryptoPP;

Integer GenerateHash(const std::string &message)
{
    SHA512 hash;
    SecByteBlock buff;

    SecByteBlock orig((const byte*)message.c_str(), message.size());

    buff.resize(SHA512::DIGESTSIZE);
    hash.CalculateTruncatedDigest(buff, buff.size(), orig, orig.size());

    Integer hashed_message(buff.data(), buff.size());

    #if DEBUG
        std::cout << "Message: " << message << std::endl;
        std::cout << "Hash: " << std::hex << hashed_message << std::endl;
    #endif

    return hashed_message;
}

#endif

