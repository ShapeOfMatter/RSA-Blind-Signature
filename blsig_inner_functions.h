#ifndef BLSIG_INNER_H_INCLUDED
# define BLSIG_INNER_H_INCLUDED
# include "blsig_includes.h"

using namespace CryptoPP;

Integer GenerateClientSecret(const RSA::PublicKey &public_key, const AutoSeededRandomPool &rng_source)
{
    const Integer &n = public_key.GetModulus();

    Integer client_secret;
    do
    {
        client_secret.Randomize(rng_source, Integer::One(), n - Integer::One());
    } while (!RelativelyPrime(client_secret, n));

    #if DEBUG
        std::cout << "Random Client Secret: " << std::hex << client_secret << std::endl;
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
        std::cout << "Blinding factor: " << std::hex << b << std::endl;
        std::cout << "Blinded hashed message: " << std::hex << hidden_message << std::endl;
    #endif

    return hidden_message;
}

Integer SignatureUnblinding(const Integer &blinded_signature, const RSA::PublicKey &public_key, const Integer &client_secret)
{
    const Integer &n = public_key.GetModulus();
    const Integer &inverse_secret = client_secret.InverseMod(n);

    Integer signed_unblinded = a_times_b_mod_c(blinded_signature, inverse_secret, n);

    #if DEBUG
        std::cout << "Signed Unblinded: " << std::hex << signed_unblinded << std::endl;
    #endif

    return signed_unblinded;
}

Integer SignBlindedMessage(const Integer &blinded_hash, const RSA::PrivateKey &private_key, const AutoSeededRandomPool &rng_source)
{
    #if DEBUG
        std::cout << "Generating signature..." << std::endl;
        std::cout << "Blinded Payload: " << std::hex << blinded_hash << std::endl;
    #endif

    Integer signed_message = private_key.CalculateInverse(rng_source, blinded_hash);

    #if DEBUG
        std::cout << "Signed Message: " << std::hex << signed_message << std::endl;
    #endif

    return signed_message;
}

bool PreverifySignature(const Integer &signed_blined_hash, const Integer &blinded_hash, const RSA::PublicKey &public_key)
{
    bool valid = public_key.ApplyFunction(signed_blinded_hash) == blinded_hash;

    #if DEBUG
        std::cout << "The blind message was" << (valid ? " " : " NOT ") << "properly signed." << std::endl;
    #endif

    return valid;
}

bool VerifySignature(const Integer &unblinded_signature, const Integer &hashed_message, const RSA::PublicKey &public_key)
{
    Integer signature_payload = public_key.ApplyFunction(unblinded_signature);
    bool valid = hashed_message == signature_payload;

    #if DEBUG
        std::cout << "The signature contained message hash: " << std::hex << signature_payload << std::endl;
        std::cout << "The signature is " << (valid ? "valid" : "INVALID") << "." << std::endl;
    #endif

    return valid;
}

#endif


