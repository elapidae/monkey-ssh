#include "monkey_aes.h"

#include <openssl/rand.h>
#include "vtime_point.h"
#include "vbyte_buffer.h"
#include "vbyte_buffer_view.h"
#include "vlog.h"
#include "vcat.h"

//=======================================================================================
// from RSA
const unsigned char *str_to_uchar( const std::string& data );
unsigned char *str_to_uchar( std::string* data );
//=======================================================================================


//=======================================================================================
void Monkey_AES::test()
{
    Monkey_AES aes;
    aes.generate_randoms();
    auto msg = some_rand(1234);
    auto enc = aes.encrypt(msg);
    auto dec = aes.decrypt(enc);

    if (dec != msg) throw verror;
}
//=======================================================================================


//=======================================================================================
void Monkey_AES::generate_randoms()
{
    int rc = RAND_bytes(key, KEY_SIZE);
    if (rc != 1)
        throw verror("RAND_bytes key failed");

    rc = RAND_bytes(iv, BLOCK_SIZE);
    if (rc != 1)
        throw verror("RAND_bytes for iv failed");
}
//=======================================================================================
void Monkey_AES::set_keys( std::string hex_keys )
{
    auto bb = vbyte_buffer::from_hex( hex_keys );
    auto view = bb.view();
    for (int i = 0; i < sizeof(key); ++i)
    {
        using T = std::remove_reference_t< decltype(key[0]) >;
        key[i] = view.LE<T>();
    }
    for (int i = 0; i < sizeof(iv); ++i)
    {
        using T = std::remove_reference_t< decltype(iv[0]) >;
        iv[i] = view.LE<T>();
    }
}
//=======================================================================================
std::string Monkey_AES::hex_keys() const
{
    vbyte_buffer bb;
    for (int i = 0; i < sizeof(key); ++i)
    {
        bb.append_LE( key[i] );
    }
    for (int i = 0; i < sizeof(iv); ++i)
    {
        bb.append_LE( iv[i] );
    }
    return bb.toHex();
}
//=======================================================================================
std::string Monkey_AES::some_rand_hex( int size, int diff )
{
    std::string str;
    str.resize(size + diff);
    RAND_bytes(str_to_uchar(&str), str.size());
    auto app = diff ? unsigned(*str.rbegin()) % diff : 0;
    auto res = vbyte_buffer(str).toHex();
    res.resize( size + app );
    return res;
}
//=======================================================================================
std::string Monkey_AES::some_rand(int size)
{
    std::string res;
    res.resize(size);
    RAND_bytes(str_to_uchar(&res), res.size());
    return res;
}
//=======================================================================================
Monkey_AES::Monkey_AES()
{
    static auto rcode = EVP_add_cipher(EVP_aes_256_cbc());

    ctx.reset( EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free );
    if ( !ctx ) throw verror;
}
//=======================================================================================

//=======================================================================================
std::string Monkey_AES::encrypt( const std::string & data )
{
    int rc;
    rc = EVP_EncryptInit(ctx.get(), EVP_aes_256_cbc(), key, iv);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    std::string res;
    res.resize( data.size() + BLOCK_SIZE );
    int out_len1 = res.size();

    auto out_ptr = str_to_uchar( &res );
    auto in_ptr  = str_to_uchar( data );
    rc = EVP_EncryptUpdate(ctx.get(), out_ptr, &out_len1, in_ptr, data.size());
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");

    int out_len2 = res.size() - out_len1;
    rc = EVP_EncryptFinal(ctx.get(), out_ptr+out_len1, &out_len2);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");

    res.resize(out_len1 + out_len2);
    return res;
}
//=======================================================================================
// 16 -- sizes
// heap
vbyte_buffer Monkey_AES::heap_encrypt( cstr heap, uint32_t body_size )
{
    auto salt = Monkey_AES::some_rand_hex(5, 15);
    vcat msg(salt, "\n", heap);
    auto emsg = encrypt(msg);
    uint32_t emsg_size = emsg.size();

    vbyte_buffer bb;
    bb.append( Monkey_AES::some_rand(7) );
    bb.append_LE(emsg_size);
    bb.append_LE(body_size);

    auto ebb = encrypt(bb);
    if (ebb.size() != 16) throw verror;

    ebb.append( emsg );

    test_heap( heap, ebb, heap, body_size );

    return ebb;
}
//=======================================================================================
void Monkey_AES::test_heap( cstr hh, vbyte_buffer enc, cstr heap, uint32_t body_size )
{
    uint32_t h, b;
    decrypt_sizes( &enc, &h, &b );
    if ( b != body_size ) throw verror;
    if ( h != enc.size() ) throw verror;
    auto dec = decrypt(enc);
    if ( dec.find(hh) == std::string::npos ) throw verror;
}
//=======================================================================================


//=======================================================================================
std::string Monkey_AES::decrypt( const std::string& data )
{
    int rc;
    rc = EVP_DecryptInit( ctx.get(), EVP_aes_256_cbc(), key, iv );
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    std::string res;
    res.resize( data.size() );
    int out_len1 = res.size();

    auto in_ptr  = str_to_uchar( data );
    auto out_ptr = str_to_uchar( &res );
    rc = EVP_DecryptUpdate( ctx.get(), out_ptr, &out_len1, in_ptr, data.size() );
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");

    int out_len2 = res.size() - out_len1;
    rc = EVP_DecryptFinal( ctx.get(), out_ptr+out_len1, &out_len2 );
    //vdeb << out_len1 << out_len2;
    if (rc != 1)
    {
        vdeb << vbyte_buffer(data).toHex();
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
        //if ( res.size() != out_len1 )

    }

    // Set recovered text size now that we know it
    res.resize(out_len1 + out_len2);
    return res;
}
//=======================================================================================
void Monkey_AES::decrypt_sizes( vbyte_buffer *data, uint32_t *h, uint32_t *b )
{
    if ( data->size() < 16 ) throw verror;
    auto esizes = data->left(16);

    auto sz1 = data->size();

    data->chop_front(16);
    if ( sz1 != data->size() + 16 )
        throw verror;

    vbyte_buffer sizes = decrypt(esizes);
    auto view = sizes.view();
    view.string(7);
    *h = view.u32_LE();
    *b = view.u32_LE();
}
//=======================================================================================
