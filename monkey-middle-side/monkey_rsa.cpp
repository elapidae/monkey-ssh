#include "monkey_rsa.h"

//#include <openssl/rsaerr.h>
#include <openssl/pem.h>
#include <openssl/pemerr.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <filesystem>
#include "vcat.h"
#include "vlog.h"
#include "vbyte_buffer.h"
#include "vbyte_buffer_view.h"

using namespace std;
namespace fs = std::filesystem;

static constexpr auto rsa_pubname  = "rsa_public.pem";
static constexpr auto rsa_privname = "rsa_private.pem";

//=======================================================================================
const unsigned char *str_to_uchar( const std::string& data )
{
    auto v = static_cast<const void*>(data.c_str());
    return static_cast<const unsigned char*>(v);
}
//=======================================================================================
unsigned char *str_to_uchar( std::string* data )
{
    auto v = static_cast<void*>(data->data());
    return static_cast<unsigned char*>(v);
}
//=======================================================================================
static int max_rsa_encrypt_len(const RSA *rsa)
{
    //https://www.openssl.org/docs/manmaster/man3/RSA_public_encrypt.html
    //RSA_PKCS1_OAEP_PADDING
    return RSA_size(rsa) - 42;
}
//=======================================================================================
static int rsa_decrypt_len(const RSA *rsa)
{
    //https://www.openssl.org/docs/manmaster/man3/RSA_public_encrypt.html
    //RSA_PKCS1_OAEP_PADDING
    return RSA_size(rsa);
}
//=======================================================================================
using crypt_fn = decltype( &RSA_public_encrypt );
static string crypt( RSA *rsa, crypt_fn fn, const std::string& msg )
{
    auto from = str_to_uchar( msg );

    string res;
    res.resize( RSA_size(rsa) );
    auto to = str_to_uchar( &res );

    auto size = (*fn)( msg.size(), from, to, rsa, RSA_PKCS1_OAEP_PADDING );
    if ( size == -1 )
        throw Monkey_RSA::crypt_error("crypt");

    res.resize(size);
    return res;
}
//=======================================================================================
static BIGNUM *from_hex(std::string data)
{
    BIGNUM *res = nullptr;
    auto size = BN_hex2bn( &res, data.c_str() );
    if (size != data.size())
        throw verror << "auto size = BN_hex2bn( &res, data.c_str() );";

    return res;
}
//=======================================================================================
static string to_hex(const BIGNUM * num)
{
    auto ch = BN_bn2hex(num);
    string res = ch;
    OPENSSL_free(ch);
    return res;
}
//=======================================================================================
using read_fn = decltype(&PEM_read_RSAPrivateKey);
static RSA * read_from_pem(std::string fname, read_fn fn)
{
    auto f = fopen(fname.c_str(), "r");
    if (!f) throw verror << "Cannot open " << fname;

    RSA *res = nullptr;
    auto ptr = (*fn)(f, &res, nullptr, nullptr);
    fclose(f);
    if ( !ptr || ptr != res )
        throw verror << "read from pem" << fname;

    auto ff = fopen((fname + ".txt").c_str(), "w");
    RSA_print_fp(ff, res, 0);
    fclose(ff);

    return res;
}
//=======================================================================================


//=======================================================================================
Monkey_RSA Monkey_RSA::generate_or_read_private(std::string path)
{
    auto e1 = fs::exists(path + "/" + rsa_privname);
    auto e2 = fs::exists(path + "/" + rsa_pubname);
    if ( !e1 || !e2 )
        generate_new(path);

    Monkey_RSA res;
    res.rsa = read_from_pem( path + "/" + rsa_privname, PEM_read_RSAPrivateKey );
    return res;
}
//=======================================================================================
//Monkey_RSA Monkey_RSA::read_public(std::string path)
//{
//    auto pubname = path + "/" + rsa_pubname;
//    if ( !fs::exists(pubname) )
//        throw verror << "public does not exists";

//    Monkey_RSA res;
//    res.rsa = read_from_pem(pubname, PEM_read_RSAPublicKey);
//    return res;
//}
//=======================================================================================
Monkey_RSA Monkey_RSA::from_public_hex_e_n( std::string hex_e, std::string hex_n )
{
    auto e = from_hex( hex_e );
    auto n = from_hex( hex_n );

    //int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
    Monkey_RSA res;
    res.rsa = RSA_new();
    auto rcode = RSA_set0_key(res.rsa, n, e, nullptr);
    return res;
}
//=======================================================================================
string Monkey_RSA::sha_n() const
{
    auto n = this->hex_n();
    auto ptr = str_to_uchar(n);
    string res;
    res.resize(20);
    auto optr = str_to_uchar( &res );
    SHA1( ptr, n.size(), optr );
    return vbyte_buffer(res).tohex();
}
//=======================================================================================
string Monkey_RSA::hex_e() const
{
    auto big_e = RSA_get0_e(rsa);
    return to_hex(big_e);
}
//=======================================================================================
string Monkey_RSA::hex_n() const
{
    auto big_n = RSA_get0_n(rsa);
    return to_hex(big_n);
}
//=======================================================================================
string Monkey_RSA::encrypt( const std::string& enc ) const
{
    auto dec_len = rsa_decrypt_len(rsa);
    auto max_sz = max_rsa_encrypt_len(rsa);
    vbyte_buffer bb(enc);
    auto view = bb.view();

    vbyte_buffer res;
    while ( !view.finished() )
    {
        auto size = max_sz <= view.remained() ? max_sz : view.remained();
        auto piece = view.string( size );

        auto cur = crypt( rsa, RSA_public_encrypt, piece );

        if ( cur.size() != dec_len )
            throw verror << "RSA encrypted len is strabge:" << cur.size();

        res.append( cur );
    }
    return res;
}
//=======================================================================================
string Monkey_RSA::decrypt( const std::string& dec ) const
{
    auto dec_len = rsa_decrypt_len(rsa);

    vbyte_buffer bb(dec);
    auto view = bb.view();

    string res;
    while ( !view.finished() )
    {
        auto piece = view.string( dec_len );
        res += crypt( rsa, RSA_private_decrypt, piece );
    }
    return res;
}
//=======================================================================================
Monkey_RSA::~Monkey_RSA()
{
    RSA_free(rsa);
}
//=======================================================================================
void Monkey_RSA::generate_new(std::string path)
{
    if (!fs::exists(path))
        throw verror << "Path '" << path << "' not exists";

    vcat priv("openssl genrsa -out ", path, "/rsa_private.pem 4096");
    auto ret = system(priv.str().c_str());
    if (ret)
        throw verror("Cannot generate priv RSA key in path ", path, ", err: ", ret);

    vcat pub("openssl rsa -in ", path, "/rsa_private.pem -outform PEM -pubout -out ",
              path, "/rsa_public.pem");

    auto ret2 = system(pub.str().c_str());
    if (ret2)
        throw verror("Cannot generate pub RSA key in path ", path, "err: ", ret);
}
//=======================================================================================


//=======================================================================================
void Monkey_RSA::test()
{
    auto pri = Monkey_RSA::generate_or_read_private(".");
    auto pub = Monkey_RSA::from_public_hex_e_n(pri.hex_e(), pri.hex_n());
    string msg = "ABC";
    msg += msg + msg + msg;
    msg += msg + msg + msg;
    msg += msg + msg + msg;
    msg += msg + msg + msg;
    msg += msg + msg + msg;
    vdeb << "msg.si" << msg.size();

    auto crip = pub.encrypt(msg);
    vdeb << crip.size();
    auto chk = pri.decrypt(crip);
    vdeb << (chk == msg);
}
//=======================================================================================
