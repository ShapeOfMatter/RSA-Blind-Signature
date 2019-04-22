#include "blsig_includes.h"

using namespace CryptoPP;

int main(int argc, char *argv[])
{
    if(5 != argc){
        fprintf(std::cerr, "Incorrect useage of %s. Expected %i arguments; given %i.", argv[0], 5, argc);
        return EXIT FAILURE;
    }

    try{
        Integer blinded_signature = Integer(argv[1]);
        Integer blinded_hash = Integer(argv[2]);
        Integer client_secret = Integer(argv[3]);
        RSA::PublicKey public_key = ReadPEMPublicKey(argv[4]);
    }
    catch(std::runtime_error& e)
    {
        std::cerr << e.what();
        return EXIT_FAILURE;
    }

    if(PreverifySignature(blinded_signature, blinded_hash, public_key))
    {
        Integer unblinded_signature = SignatureUnblinding(blinded_signature, public_key, client_secret);

        std::cout << std::hex << unblinded_signature;
        return EXIT_SUCCESS;
    }
    else
    {
        std::cerr << "There is a problem with the provided signature: it does not match the blinded hash." << std::endl;
        return EXIT_FAILURE;
    }
}



