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

#ifndef DEBUG
    #define DEBUG 0
#endif

Integer GenerateClientSecret(const RSA::PublicKey &public_key, const AutoSeededRandomPool &rng_source)
{
    const Integer &n = public_key.GetModulus();

    Integer client_secret;
    do
    {
        client_secret.Randomize(rng_source, Integer::One(), n - Integer::One());
    } while (!RelativelyPrime(client_secret, n));

    #if DEBUG
        cout << "Random Client Secret: " << std::hex << client_secret << endl;
    #endif

    return client_secret;
}

Integer MessageBlinding(const Integer &hashed_message, const RSA::PublicKey &public_key, const Integer &client_secret)
{
    const Integer &n = public_key.GetModulus();
    const Integer &e = public_key.GetPublicExponent();

    Integer b = a_exp_b_mod_c(client_secret, e, n);
    Integer hidden_message = a_times_b_mod_c(hashed_message, b, n);

    #if DEBUG
        cout << "Blinding factor: " << std::hex << b << endl;
        cout << "Blinded hashed message: " << std::hex << hidden_message << endl;
    #endif

    return hidden_message;
}

Integer SignatureUnblinding(const Integer &blinded_signature, const RSA::PublicKey &public_key, const Integer &client_secret)
{
    const Integer &n = public_key.GetModulus();
    const Integer &inverse_secret = client_secret.InverseMod(n);

    Integer signed_unblinded = a_times_b_mod_c(blinded_signature, inverse_secret, n);

    #if DEBUG
        cout << "Signed Unblinded: " << std::hex << signed_unblinded << endl;
    #endif

    return signed_unblinded;
}

Integer SignBlindedMessage(const Integer &blinded_hash, const RSA::PrivateKey &private_key, const AutoSeededRandomPool &rng_source)
{
    #if DEBUG
        cout << "Generating signature..." << endl;
        cout << "Blinded Payload: " << std::hex << blinded_hash << endl;
    #endif

    Integer signed_message = private_key.CalculateInverse(rng_source, blinded_hash);

    #if DEBUG
        cout << "Signed Message: " << std::hex << signed_message << endl;
    #endif

    return signed_message;
}

bool PreverifySignature(const Integer &signed_blined_hash, const Integer &blinded_hash, const RSA::PublicKey &public_key)
{
    bool valid = public_key.ApplyFunction(signed_blinded_hash) == blinded_hash;

    #if DEBUG
        cout << "The blind message was" << (valid ? " " : " NOT ") << "properly signed." << endl;
    #endif

    return valid;
}

bool VerifySignature(const Integer &unblinded_signature, const Integer &hashed_message, const RSA::PublicKey &public_key)
{
}

//add sig verificaiton.

    // Eve verification stage
//    Integer message_hash = GenerateHash(message);
//    Integer received_hash = public_key.ApplyFunction(signed_unblinded);
//    cout << "Signature payload: " << received_hash << endl;
//    if (message_hash != received_hash)
//    {
//        cout << "Verification failed" << endl;
//        exit(EXIT_FAILURE);
//    }

//    cout << "Signature Verified" << endl;
    // return success
//    return 0;

