# RSA-Blind-Signature
A RSA Blind Signature implementation using Crypto++, based on Chaum's paper.

At its core, this library is based on the [example on the Crypto++ wiki](https://www.cryptopp.com/wiki/Raw_RSA#RSA_Blind_Signature).  
[Here is the documentation for the Crypto++ library](https://www.cryptopp.com/docs/ref/).  
[Here are instructions for installing and building the underlying Crypto++ library on Linux](https://www.cryptopp.com/wiki/Linux#Build_and_Install_the_Library).  
The parts of the code that read the pem-formatted keys are taken from [cryptopp-pem](https://github.com/noloader/cryptopp-pem), but for better or worse this library does not have a dependency on that library.  

### Warning:
This library has not yet been reviewed by any particular community. Until further notice, don't use it for anything.  
Additionally, one should _never_ use the keys used for RSA Blind Signatures for any other purpose.

### Scope:
This library is intended as a _minimal_, _portable_ usable implementation of a commonly-cited, trusted blind-signature algorithm. At present it only supports un-encrypted keys in PEM format, and extension to other cryptographic paradigms besides RSA would likely constitute a separate project.  
"Nice to have" feature requests will probably be treated as notes for an eventual overhaul.  
We want to keep this simple to use, maintain, _and review and verify_. For this reason even pull-requests may be declined if they don't address security concerns or important usability concerns.

### TODO:
- ✓ Link to instructions for installing the underlying library and getting this code running.
- ✓ Upgrade the hash to a FDH or SHA512.
- ✓ Upgrade the keys to 2048 bits or more.
- ✓ Separate into functions that can be called individually from surrounding code.
- ✓ Provide instructions for building (installing?) this code.
- Test function should clean up after itself.
- Figure out what the advertised restrictions on the character set of the messages should be.
- Make sure the on-failure behavior is consistent, and document it.

### Installation:
- Download the files to your chosen directory.
- You'll need the Crypto++ library accessible at `./cryptopp810/`.
- Running `make` will build the six executables in `./bin/`, including `test`, which is intended to confirm that the library has build and will run.
- `test` will use the additional directory `./scratch/`.

### Useage:
There are six separate executables (to simplify system calls from other languages).  
"Key" arguments are the path/filename of the respective key. "Message" is the bare messages as a string. Other arguments are the strings returned by earlier steps in the process. 
The executables, on success, will print their responses as text to standard-out, and will return the system's "success" value. A newline is included in the responses, but should not be included in arguments.
- blsig_get_client_secret: Generates a single-use secret for blinding a message.  
  `blsig_get_client_secret public_key.pem`
- blsig_get_blinded_hash: Hashes the message and then blinds the hash so it can be sent to the signer.  
  `blsig_get_blinded_hash message client_secret public_key.pem`
- blsig_get_blind_signature: Generates a "pre-signature" (or hashed signature or whatever you want to call it) without any knowledge of the message, the message-hash, or the client secret.  
  `blsig_get_blind_signature blinded_hash private_key.pem`
- blsig_get_unblinded_signature: Un-blinds the pre-signature using the same client_secret used to generate the blinded-hash. Also verifies the signature. The client secret should not be stored once it has served its purpose once.  
  `blsig_get_unblinded_signature blind_signature blinded_hash client_secret public_key.pem`
- blsig_verify_unblinded_signature: Confirms that a provided signature is a valid signature, by the corresponding private-key, of the provided message. Prints `true` for success.  
  `blsig_verify_unlinded_signature unblinded_signature message public_key.pem`
- test: The most rudimentary of tests for the most rudimentary of libraries! It's probably not useful in a production setting, but it's a good place to start into the code.  
  `test`
