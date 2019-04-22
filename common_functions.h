#ifndef BLSIG_COMMON_H_INCLUDED
# define BLSIG_COMMON_H_INCLUDED
# include "blsig_includes.h"

using namespace CryptoPP;

static const std::regex PEM_Key_Regex_Public(
    "-----BEGIN (?:RSA )?PUBLIC KEY-----[\r\n]+([^-]*)[\r\n]+-----END (?:RSA )?PUBLIC KEY-----");
static const std::regex PEM_Key_Regex_Private(
    "-----BEGIN (?:RSA )?PRIVATE KEY-----[\r\n]+([^-]*)[\r\n]+-----END (?:RSA )?PRIVATE KEY-----");

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

std::string IntegerAsString(const Integer i, const RSA::PrivateKey &private_key)
{
    const Integer &n = private_key.getModulus();

    std::string s = std::IntToString<Integer>(i, 16);

    //Should we pad these to constant lenght based on the modulus of the private key? 
    // - This would reveal the private key modulus, but that's the same as the public key modulus, right?
    // - What actualy advantage would it have?
    
    return s;
}

bool LoadKeyBodyFrom(std::string file_name, std::regex r, ByteQueue &buff)
{
    std::ifstream f(file_name.c_str());
    if(f.fail()){
        std::cerr << "Failed to open file '" << filename << "'.";
        return false;
    }
    std::string contents(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());

    std::cmatch key_search;
    if(std::regex_match(contents, key_search, r)){
        std::string key_body = key_search.str(1);

        #if DEBUG
            fprintf(std::cout, "Found key body in file '%s': %d characters.", filename, key_body.length());
        #endif

        Base64Decoder decoder;            
        decoder.Attach(new Redirector(buff));
        decoder.Put((const byte*)key_body.data(), key_body.length());
        decoder.MessageEnd();

        return true;
    }
    else
    {
        std::cerr << "Couldn't find a PEM key in file '" << filename << "'.";
        return false;
    }
}

RSA::PublicKey ReadPEMPublicKey(std::string file_name)
{
    ByteQueue buff;
    if(LoadKeyBodyFrom(file_name, PEM_Key_Regex_Public, &buff)){
        RSA::PublicKey public_key;
        public_key.BERDDecodePublicKey(buff, false, bQueue.MaxRetrievable());

        if(bQueue.IsEmpty()){
            return public_key;
        }
        else
        {
            throw std::runtime_error("Something went wrong reading the Public Key: The ByteQueue was not exhausted.")
        }
    }
    else
    {
        throw std::runtime_error("Failed to read the Public Key.");
    }
}

RSA::PrivateKey ReadPEMPrivateKey(std::string file_name)
{
    ByteQueue buff;
    if(LoadKeyBodyFrom(file_name, PEM_Key_Regex_Private, &buff)){
        RSA::PrivateKey private_key;
        private_key.BERDDecodePrivateKey(buff, false, bQueue.MaxRetrievable());

        if(bQueue.IsEmpty()){
            return private_key;
        }
        else
        {
            throw std::runtime_error("Something went wrong reading the Private Key: The ByteQueue was not exhausted.")
        }
    }
    else
    {
        throw std::runtime_error("Failed to read the Private Key.");
    }
}
#endif

