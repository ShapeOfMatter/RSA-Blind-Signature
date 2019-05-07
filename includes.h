#ifndef BLSIG_INCLUDES_INCLUDED
# define BLSIG_INCLUDES_INCLUDED

# ifndef DEBUG
#  define DEBUG 0
# endif

# include <iostream>
# include <fstream>
# include <regex>
# include <stdexcept>

// Use "" based includes for the cryptopp library because it's perfectly
// legitimate to install it to the local directory. 
# include "cryptopp810/base64.h"
# include "cryptopp810/cryptlib.h"
# include "cryptopp810/files.h"
# include "cryptopp810/integer.h"
# include "cryptopp810/nbtheory.h"
# include "cryptopp810/osrng.h"
# include "cryptopp810/rsa.h"
# include "cryptopp810/sha.h"

# include "pem-rd.h"
# include "common_functions.h"
# include "inner_functions.h"

#endif
