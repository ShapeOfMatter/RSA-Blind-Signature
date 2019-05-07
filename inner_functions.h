#ifndef BLSIG_INNER_H_INCLUDED
# define BLSIG_INNER_H_INCLUDED
# include "includes.h"

using namespace CryptoPP;

/* Generates a single-use secret value for blinding a message before it is sent
 * to the signer.
 * The public key is needed as a parameter because the space of valid secrets
 * depends on the details of the key.
 */
Integer GenerateClientSecret(const RSA::PublicKey &public_key, AutoSeededRandomPool &rng_source)
{
    const Integer &n = public_key.GetModulus();

    Integer client_secret;
    do
    {
        client_secret.Randomize(rng_source, Integer::One(), n - Integer::One());
    } while (!RelativelyPrime(client_secret, n));

    #if DEBUG
        std::cout << "Random Client Secret: " << std::hex << client_secret << std::dec << std::endl;
    #endif

    return client_secret;
}

/* Generates a blinded version of the message value, to be sent to the signer.
 */
Integer MessageBlinding(const Integer &hashed_message, const RSA::PublicKey &public_key, const Integer &client_secret)
{
    const Integer &n = public_key.GetModulus();
    const Integer &e = public_key.GetPublicExponent();

    Integer b = a_exp_b_mod_c(client_secret, e, n);
    Integer hidden_message = a_times_b_mod_c(hashed_message, b, n);

    #if DEBUG
        std::cout << "Blinding factor: " << std::hex << b << std::dec << std::endl;
        std::cout << "Blinded hashed message: " << std::hex << hidden_message << std::dec << std::endl;
    #endif

    return hidden_message;
}

/* Retrieves the completed signature from a blinded signature.
 */
Integer SignatureUnblinding(const Integer &blinded_signature, const RSA::PublicKey &public_key, const Integer &client_secret)
{
    const Integer &n = public_key.GetModulus();
    const Integer &inverse_secret = client_secret.InverseMod(n);

    Integer signed_unblinded = a_times_b_mod_c(blinded_signature, inverse_secret, n);

    #if DEBUG
        std::cout << "Signed Unblinded: " << std::hex << signed_unblinded << std::dec << std::endl;
    #endif

    return signed_unblinded;
}

/* Blindly signs the provided hash.
 * The returned value is not quite a complete signature; it must be unblinded
 * by the original requestor using the one-time client secret.
 */
Integer SignBlindedMessage(const Integer &blinded_hash, const RSA::PrivateKey &private_key, AutoSeededRandomPool &rng_source)
{
    Integer signed_message = private_key.CalculateInverse(rng_source, blinded_hash);

    #if DEBUG
        std::cout << "Signed Message: " << std::hex << signed_message << std::dec << std::endl;
    #endif

    return signed_message;
}

/* Prior to unblinding a signature, checks if the signature will be valid.
 * **It's unclear if this contributes anything of value to the algorithm or
 * this library. We include it for now for completeness.**
 */
bool PreverifySignature(const Integer &signed_blinded_hash, const Integer &blinded_hash, const RSA::PublicKey &public_key)
{
    bool valid = public_key.ApplyFunction(signed_blinded_hash) == blinded_hash;

    #if DEBUG
        std::cout << "The blind message was" << (valid ? " " : " NOT ") << "properly signed." << std::endl;
    #endif

    return valid;
}

/* Checks that a completed signature is a valid signature of the message hash. 
 */
bool VerifySignature(const Integer &unblinded_signature, const Integer &hashed_message, const RSA::PublicKey &public_key)
{
    Integer signature_payload = public_key.ApplyFunction(unblinded_signature);
    bool valid = hashed_message == signature_payload;

    #if DEBUG
        std::cout << "The signature contained message hash: " << std::hex << signature_payload << std::dec << std::endl;
        std::cout << "The signature is " << (valid ? "valid" : "INVALID") << "." << std::endl;
    #endif

    return valid;
}

#endif


