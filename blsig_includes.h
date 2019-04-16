#ifndef BLSIG_INCLUDES_INCLUDED
# define BLSIG_INCLUDES_INCLUDED

# ifndef DEBUG
#  define DEBUG 0
# endif

# include <iostream>
# include <stdexcept>

# include "cryptopp810/rsa.h"
# include "cryptopp810/sha.h"
# include "cryptopp810/osrng.h"
# include "cryptopp810/integer.h"
# include "cryptopp810/cryptlib.h"
# include "cryptopp810/nbtheory.h"

# include "blsig_common_functions.h"
# include "blsig_inner_functions.h"

#endif
