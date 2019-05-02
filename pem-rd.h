#ifndef BLSIG_PEM_H_INCLUDED
# define BLSIG_PEM_H_INCLUDED
# include "includes.h"

// pem-rd.cpp - PEM read routines. Written and placed in the public domain by Jeffrey Walton
//              Copyright assigned to the Crypto++ project.
//
// Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2) licensed
// under the Boost Software License 1.0, while the individual files in the compilation
// are all public domain.

///////////////////////////////////////////////////////////////////////////
// For documentation on the PEM read and write routines, see
//   http://www.cryptopp.com/wiki/PEM_Pack
///////////////////////////////////////////////////////////////////////////

#include <string>
#include <algorithm>

#include <cctype>

#include "cryptopp810/secblock.h"
#include "cryptopp810/gfpcrypt.h"
#include "cryptopp810/camellia.h"
#include "cryptopp810/smartptr.h"
#include "cryptopp810/filters.h"
#include "cryptopp810/queue.h"
#include "cryptopp810/modes.h"
#include "cryptopp810/asn.h"
#include "cryptopp810/aes.h"
#include "cryptopp810/idea.h"
#include "cryptopp810/des.h"
#include "cryptopp810/hex.h"

NAMESPACE_BEGIN(CryptoPP)

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//I want this to be just one file, so I'm pulling some stuff in from the original headers.
enum PEM_Type { PEM_PUBLIC_KEY = 1, PEM_PRIVATE_KEY,
    PEM_RSA_PUBLIC_KEY, PEM_RSA_PRIVATE_KEY, PEM_RSA_ENC_PRIVATE_KEY,
    PEM_DSA_PUBLIC_KEY, PEM_DSA_PRIVATE_KEY, PEM_DSA_ENC_PRIVATE_KEY,
    PEM_EC_PUBLIC_KEY, PEM_ECDSA_PUBLIC_KEY, PEM_EC_PRIVATE_KEY, PEM_EC_ENC_PRIVATE_KEY,
    PEM_EC_PARAMETERS, PEM_DH_PARAMETERS, PEM_DSA_PARAMETERS,
    PEM_X509_CERTIFICATE, PEM_REQ_CERTIFICATE, PEM_CERTIFICATE,
    PEM_UNSUPPORTED = 0xFFFFFFFF };

static inline SecByteBlock StringToSecByteBlock(const std::string& str)
{
    return SecByteBlock(reinterpret_cast<const byte*>(str.data()), str.size());
}
static inline SecByteBlock StringToSecByteBlock(const char* str)
{
    return SecByteBlock(reinterpret_cast<const byte*>(str), strlen(str));
}
static inline const byte* BYTE_PTR(const char* cstr)
{
    return reinterpret_cast<const byte*>(cstr);
}
static inline byte* BYTE_PTR(char* cstr)
{
    return reinterpret_cast<byte*>(cstr);
}

static const SecByteBlock CR(BYTE_PTR("\r"), 1);
static const SecByteBlock LF(BYTE_PTR("\n"), 1);
static const SecByteBlock CRLF(BYTE_PTR("\r\n"), 2);

static const unsigned int RFC1421_LINE_BREAK = 64;
static const std::string RFC1421_EOL = "\r\n";

static const SecByteBlock SBB_PEM_BEGIN(BYTE_PTR("-----BEGIN"), 10);
static const SecByteBlock SBB_PEM_TAIL(BYTE_PTR("-----"), 5);
static const SecByteBlock SBB_PEM_END(BYTE_PTR("-----END"), 8);

static const size_t PEM_INVALID = static_cast<size_t>(-1);

static const std::string LBL_PUBLIC_BEGIN("-----BEGIN PUBLIC KEY-----");
static const std::string LBL_PUBLIC_END("-----END PUBLIC KEY-----");
static const std::string LBL_PRIVATE_BEGIN("-----BEGIN PRIVATE KEY-----");
static const std::string LBL_PRIVATE_END("-----END PRIVATE KEY-----");
static const std::string LBL_RSA_PUBLIC_BEGIN("-----BEGIN RSA PUBLIC KEY-----");
static const std::string LBL_RSA_PUBLIC_END("-----END RSA PUBLIC KEY-----");
static const std::string LBL_RSA_PRIVATE_BEGIN("-----BEGIN RSA PRIVATE KEY-----");
static const std::string LBL_RSA_PRIVATE_END("-----END RSA PRIVATE KEY-----");
static const std::string LBL_PROC_TYPE_ENC("Proc-Type: 4,ENCRYPTED");
static const SecByteBlock SBB_PUBLIC_BEGIN(StringToSecByteBlock(LBL_PUBLIC_BEGIN));
static const SecByteBlock SBB_PUBLIC_END(StringToSecByteBlock(LBL_PUBLIC_END));
static const SecByteBlock SBB_PRIVATE_BEGIN(StringToSecByteBlock(LBL_PRIVATE_BEGIN));
static const SecByteBlock SBB_PRIVATE_END(StringToSecByteBlock(LBL_PRIVATE_END));
static const SecByteBlock SBB_RSA_PUBLIC_BEGIN(StringToSecByteBlock(LBL_RSA_PUBLIC_BEGIN));
static const SecByteBlock SBB_RSA_PUBLIC_END(StringToSecByteBlock(LBL_RSA_PUBLIC_END));
static const SecByteBlock SBB_RSA_PRIVATE_BEGIN(StringToSecByteBlock(LBL_RSA_PRIVATE_BEGIN));
static const SecByteBlock SBB_RSA_PRIVATE_END(StringToSecByteBlock(LBL_RSA_PRIVATE_END));
static const SecByteBlock SBB_PROC_TYPE_ENC(StringToSecByteBlock(LBL_PROC_TYPE_ENC));

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

static size_t PEM_ReadLine(BufferedTransformation& source, SecByteBlock& line, SecByteBlock& ending);
static PEM_Type PEM_GetType(const BufferedTransformation& bt);
static PEM_Type PEM_GetType(const SecByteBlock& sb);

static void PEM_StripEncapsulatedBoundary(BufferedTransformation& bt, const SecByteBlock& pre, const SecByteBlock& post);
static void PEM_StripEncapsulatedBoundary(SecByteBlock& sb, const SecByteBlock& pre, const SecByteBlock& post);

static inline SecByteBlock::const_iterator Search(const SecByteBlock& source, const SecByteBlock& target);

static void PEM_LoadPublicKey(BufferedTransformation& bt, X509PublicKey& key, bool subjectInfo = false);
static void PEM_LoadPrivateKey(BufferedTransformation& src, PKCS8PrivateKey& key, bool subjectInfo);

static void PEM_NextObject(BufferedTransformation& src, BufferedTransformation& dest);

static void PEM_Base64Decode(BufferedTransformation& source, BufferedTransformation& dest);

static void PEM_WriteLine(BufferedTransformation& bt, const std::string& line);
static void PEM_WriteLine(BufferedTransformation& bt, const SecByteBlock& line);

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

void PEM_Load(BufferedTransformation& bt, RSA::PublicKey& rsa)
{
    ByteQueue obj;
    PEM_NextObject(bt, obj);

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, SBB_PUBLIC_BEGIN, SBB_PUBLIC_END);
    else if(type == PEM_RSA_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, SBB_RSA_PUBLIC_BEGIN, SBB_RSA_PUBLIC_END);
    else
        throw InvalidDataFormat("PEM_Load: not a RSA public key");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    PEM_LoadPublicKey(temp, rsa, type == PEM_PUBLIC_KEY);
}

void PEM_Load(BufferedTransformation& bt, RSA::PrivateKey& rsa)
{
    ByteQueue obj;
    PEM_NextObject(bt, obj);

    PEM_Type type = PEM_GetType(obj);
    if(type == PEM_PRIVATE_KEY)
        PEM_StripEncapsulatedBoundary(obj, SBB_PRIVATE_BEGIN, SBB_PRIVATE_END);
    else if(type == PEM_RSA_PRIVATE_KEY)
        PEM_StripEncapsulatedBoundary(obj, SBB_RSA_PRIVATE_BEGIN, SBB_RSA_PRIVATE_END);
    else if(type == PEM_RSA_ENC_PRIVATE_KEY)
        throw InvalidArgument("PEM_Load: RSA private key is encrypted");
    else
        throw InvalidDataFormat("PEM_Load: not a RSA private key");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    PEM_LoadPrivateKey(temp, rsa, type == PEM_PRIVATE_KEY);
}

void PEM_LoadPublicKey(BufferedTransformation& src, X509PublicKey& key, bool subjectInfo)
{
    X509PublicKey& pk = dynamic_cast<X509PublicKey&>(key);

    if (subjectInfo)
        pk.Load(src);
    else
        pk.BERDecode(src);

    #if !defined(NO_OS_DEPENDENCE)
    AutoSeededRandomPool prng;
    if(!pk.Validate(prng, 2))
        throw Exception(Exception::OTHER_ERROR, "PEM_LoadPublicKey: key validation failed");
    #endif
}

void PEM_LoadPrivateKey(BufferedTransformation& src, PKCS8PrivateKey& key, bool subjectInfo)
{
    if (subjectInfo)
        key.Load(src);
    else
        key.BERDecodePrivateKey(src, 0, src.MaxRetrievable());

    #if !defined(NO_OS_DEPENDENCE)
    AutoSeededRandomPool prng;
    if(!key.Validate(prng, 2))
        throw Exception(Exception::OTHER_ERROR, "PEM_LoadPrivateKey: key validation failed");
    #endif
}

PEM_Type PEM_GetType(const BufferedTransformation& bt)
{
    const size_t size = bt.MaxRetrievable();
    SecByteBlock sb(size);

    bt.Peek(sb.data(), sb.size());
    return PEM_GetType(sb);
}

PEM_Type PEM_GetType(const SecByteBlock& sb)
{
    SecByteBlock::const_iterator it;

    // Uses an OID to identify the public key type
    it = Search(sb, SBB_PUBLIC_BEGIN);
    if (it != sb.end())
        return PEM_PUBLIC_KEY;

    // Uses an OID to identify the private key type
    it = Search(sb, SBB_PRIVATE_BEGIN);
    if (it != sb.end())
        return PEM_PRIVATE_KEY;

    // RSA key types
    it = Search(sb, SBB_RSA_PUBLIC_BEGIN);
    if(it != sb.end())
        return PEM_RSA_PUBLIC_KEY;

    it = Search(sb, SBB_RSA_PRIVATE_BEGIN);
    if(it != sb.end())
    {
        it = Search(sb, SBB_PROC_TYPE_ENC);
        if(it != sb.end())
            return PEM_RSA_ENC_PRIVATE_KEY;

        return PEM_RSA_PRIVATE_KEY;
    }

    return PEM_UNSUPPORTED;
}

void PEM_StripEncapsulatedBoundary(BufferedTransformation& bt, const SecByteBlock& pre, const SecByteBlock& post)
{
    ByteQueue temp;
    SecByteBlock::const_iterator it;
    int n = 1, prePos = -1, postPos = -1;

    while(bt.AnyRetrievable() && n++)
    {
        SecByteBlock line, unused;
        PEM_ReadLine(bt, line, unused);

        // The write associated with an empty line must to occur. Otherwise, we loose the CR or LF
        //    in an ecrypted private key between the control fields and the encapsulated text.
        //if(line.empty())
        //    continue;

        it = Search(line, pre);
        if(it != line.end())
        {
            prePos = n;
            continue;
        }
        it = Search(line, post);
        if(it != line.end())
        {
            postPos = n;
            continue;
        }

        PEM_WriteLine(temp, line);
    }

    if(prePos == -1)
    {
        std::string msg = "PEM_StripEncapsulatedBoundary: '";
        msg += std::string((char*)pre.data(), pre.size()) + "' not found";
        throw InvalidDataFormat(msg);
    }

    if(postPos == -1)
    {
        std::string msg = "PEM_StripEncapsulatedBoundary: '";
        msg += std::string((char*)post.data(), post.size()) + "' not found";
        throw InvalidDataFormat(msg);
    }

    if(prePos > postPos)
        throw InvalidDataFormat("PEM_StripEncapsulatedBoundary: header boundary follows footer boundary");

    temp.TransferTo(bt);
}

void PEM_NextObject(BufferedTransformation& src, BufferedTransformation& dest)
{
    if(!src.AnyRetrievable())
        return;

    // We have four things to find:
    //   1. -----BEGIN (the leading begin)
    //   2. ----- (the trailing dashes)
    //   3. -----END (the leading end)
    //   4. ----- (the trailing dashes)

    // Once we parse something that purports to be PEM encoded, another routine
    //  will have to look for something particular, like a RSA key. We *will*
    //  inadvertently parse garbage, like -----BEGIN FOO BAR-----. It will
    //  be caught later when a PEM_Load routine is called.

    static const size_t BAD_IDX = PEM_INVALID;

    // We use iterators for the search. However, an interator is invalidated
    //  after each insert that grows the container. So we save indexes
    //  from begin() to speed up searching. On each iteration, we simply
    //  reinitialize them.
    SecByteBlock::const_iterator it;
    size_t idx1 = BAD_IDX, idx2 = BAD_IDX, idx3 = BAD_IDX, idx4 = BAD_IDX;

    // The idea is to read chunks in case there are multiple keys or
    //  paramters in a BufferedTransformation. So we use CopyTo to
    //  extract what we are interested in. We don't take anything
    //  out of the BufferedTransformation (yet).

    // We also use indexes because the iterator will be invalidated
    //   when we append to the ByteQueue. Even though the iterator
    //   is invalid, `accum.begin() + index` will be valid.

    // Reading 8 or 10 lines at a time is an optimization from testing
    //   against cacerts.pem. The file has 153 certs, so its a good test.
    // +2 to allow for CR + LF line endings. There's no guarantee a line
    //   will be present, or it will be RFC1421_LINE_BREAK in size.
    static const size_t READ_SIZE = (RFC1421_LINE_BREAK + 1) * 10;
    static const size_t REWIND = std::max(SBB_PEM_BEGIN.size(), SBB_PEM_END.size()) + 2;

    SecByteBlock accum;
    size_t idx = 0, next = 0;

    size_t available = src.MaxRetrievable();
    while(available)
    {
        // How much can we read?
        const size_t size = (std::min)(available, READ_SIZE);

        // Ideally, we would only scan the line we are reading. However,
        //   we need to rewind a bit in case a token spans the previous
        //   block and the block we are reading. But we can't rewind
        //   into a previous index. Once we find an index, the variable
        //   next is set to it. Hence the reason for the max()
        if(idx > REWIND)
        {
            const size_t x = idx - REWIND;
            next = std::max(next, x);
        }

        // We need a temp queue to use CopyRangeTo. We have to use it
        //   because there's no Peek that allows us to peek a range.
        ByteQueue tq;
        src.CopyRangeTo(tq, static_cast<lword>(idx), static_cast<lword>(size));

        const size_t offset = accum.size();
        accum.Grow(offset + size);
        tq.Get(accum.data() + offset, size);

        // Adjust sizes
        idx += size;
        available -= size;

        // Locate '-----BEGIN'
        if(idx1 == BAD_IDX)
        {
            it = std::search(accum.begin() + next, accum.end(), SBB_PEM_BEGIN.begin(), SBB_PEM_BEGIN.end());
            if(it == accum.end())
                continue;

            idx1 = it - accum.begin();
            next = idx1 + SBB_PEM_BEGIN.size();
        }

        // Locate '-----'
        if(idx2 == BAD_IDX && idx1 != BAD_IDX)
        {
            it = std::search(accum.begin() + next, accum.end(), SBB_PEM_TAIL.begin(), SBB_PEM_TAIL.end());
            if(it == accum.end())
                continue;

            idx2 = it - accum.begin();
            next = idx2 + SBB_PEM_TAIL.size();
        }

        // Locate '-----END'
        if(idx3 == BAD_IDX && idx2 != BAD_IDX)
        {
            it = std::search(accum.begin() + next, accum.end(), SBB_PEM_END.begin(), SBB_PEM_END.end());
            if(it == accum.end())
                continue;

            idx3 = it - accum.begin();
            next = idx3 + SBB_PEM_END.size();
        }

        // Locate '-----'
        if(idx4 == BAD_IDX && idx3 != BAD_IDX)
        {
            it = std::search(accum.begin() + next, accum.end(), SBB_PEM_TAIL.begin(), SBB_PEM_TAIL.end());
            if(it == accum.end())
                continue;

            idx4 = it - accum.begin();
            next = idx4 + SBB_PEM_TAIL.size();
        }
    }

    // Did we find `-----BEGIN XXX-----` (RFC 1421 calls this pre-encapsulated boundary)?
    if(idx1 == BAD_IDX || idx2 == BAD_IDX)
        throw InvalidDataFormat("PEM_NextObject: could not locate boundary header");

    // Did we find `-----END XXX-----` (RFC 1421 calls this post-encapsulated boundary)?
    if(idx3 == BAD_IDX || idx4 == BAD_IDX)
        throw InvalidDataFormat("PEM_NextObject: could not locate boundary footer");

    // *IF* the trailing '-----' occurred in the last 5 bytes in accum, then we might miss the
    // End of Line. We need to peek 2 more bytes if available and append them to accum.
    if(available >= 2)
    {
        ByteQueue tq;
        src.CopyRangeTo(tq, static_cast<lword>(idx), static_cast<lword>(2));

        const size_t offset = accum.size();
        accum.Grow(offset + 2);
        tq.Get(accum.data() + offset, 2);
    }
    else if(available == 1)
    {
        ByteQueue tq;
        src.CopyRangeTo(tq, static_cast<lword>(idx), static_cast<lword>(1));

        const size_t offset = accum.size();
        accum.Grow(offset + 1);
        tq.Get(accum.data() + offset, 1);
    }

    // Final book keeping
    const byte* ptr = accum.begin() + idx1;
    const size_t used = idx4 + SBB_PEM_TAIL.size();
    const size_t len = used - idx1;

    // Include one CR/LF if its available in the accumulator
    next = idx1 + len;
    size_t adjust = 0;
    if(next < accum.size())
    {
        byte c1 = accum[next];
        byte c2 = 0;

        if(next + 1 < accum.size())
            c2 = accum[next + 1];

        // Longest match first
        if(c1 == '\r' && c2 == '\n')
            adjust = 2;
        else if(c1 == '\r' || c1 == '\n')
            adjust = 1;
    }

    dest.Put(ptr, len + adjust);
    dest.MessageEnd();

    src.Skip(used + adjust);
}

size_t PEM_ReadLine(BufferedTransformation& source, SecByteBlock& line, SecByteBlock& ending)
{
    if(!source.AnyRetrievable())
    {
        line.New(0);
        ending.New(0);

        return 0;
    }

    ByteQueue temp;

    while(source.AnyRetrievable())
    {
        byte b;
        if(!source.Get(b))
            throw Exception(Exception::OTHER_ERROR, "PEM_ReadLine: failed to read byte");

        // LF ?
        if(b == '\n')
        {
            ending = LF;
            break;
        }

        // CR ?
        if(b == '\r')
        {
            // CRLF ?
            if(source.AnyRetrievable() && source.Peek(b))
            {
                if(b == '\n')
                {
                    source.Skip(1);

                    ending = CRLF;
                    break;
                }
            }

            ending = CR;
            break;
        }

        // Not End-of-Line, accumulate it.
        temp.Put(b);
    }

    if(temp.AnyRetrievable())
    {
        line.Grow(temp.MaxRetrievable());
        temp.Get(line.data(), line.size());
    }
    else
    {
        line.New(0);
        ending.New(0);
    }

    // We return a line stripped of CRs and LFs. However, we return the actual number of
    //   of bytes processed, including the CR and LF. A return of 0 means nothing was read.
    //   A return of 1 means an empty line was read (CR or LF). A return of 2 could
    //   mean an empty line was read (CRLF), or could mean 1 character was read. In
    //   any case, line will hold whatever was parsed.
    return line.size() + ending.size();
}

SecByteBlock::const_iterator Search(const SecByteBlock& source, const SecByteBlock& target)
{
    return std::search(source.begin(), source.end(), target.begin(), target.end());
}

void PEM_Base64Decode(BufferedTransformation& source, BufferedTransformation& dest)
{
    Base64Decoder decoder(new Redirector(dest));
    source.TransferTo(decoder);
    decoder.MessageEnd();
}

void PEM_WriteLine(BufferedTransformation& bt, const SecByteBlock& line)
{
    bt.Put(line.data(), line.size());
    bt.Put(reinterpret_cast<const byte*>(RFC1421_EOL.data()), RFC1421_EOL.size());
}

void PEM_WriteLine(BufferedTransformation& bt, const std::string& line)
{
    bt.Put(reinterpret_cast<const byte*>(line.data()), line.size());
    bt.Put(reinterpret_cast<const byte*>(RFC1421_EOL.data()), RFC1421_EOL.size());
}

NAMESPACE_END

#endif

