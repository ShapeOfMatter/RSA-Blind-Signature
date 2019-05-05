#ifndef BLSIG_COMMON_H_INCLUDED
# define BLSIG_COMMON_H_INCLUDED
# include "includes.h"

using namespace CryptoPP;

static const std::regex PEM_Key_Regex_Public(
    "-----BEGIN (?:RSA )?PUBLIC KEY-----[\\r\\n]+([^-]*)[\\r\\n]+-----END (?:RSA )?PUBLIC KEY-----");
static const std::regex PEM_Key_Regex_Private(
    "-----BEGIN (?:RSA )?PRIVATE KEY-----[\\r\\n]+([^-]*)[\\r\\n]+-----END (?:RSA )?PRIVATE KEY-----");

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

RSA::PublicKey ReadPEMPublicKey(std::string file_name)
{
    RSA::PublicKey public_key;
    FileSource public_key_file(file_name.c_str(), true);
    PEM_Load(public_key_file, public_key);
    return public_key;
}

RSA::PrivateKey ReadPEMPrivateKey(std::string file_name)
{
        RSA::PrivateKey private_key;
        FileSource private_key_file(file_name.c_str(), true);
        PEM_Load(private_key_file, private_key);
        return private_key;
}

#endif

