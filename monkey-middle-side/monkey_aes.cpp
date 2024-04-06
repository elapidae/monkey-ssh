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
    ctx = EVP_CIPHER_CTX_new();
    if ( !ctx ) throw verror;
}
//=======================================================================================
Monkey_AES::~Monkey_AES()
{
    EVP_CIPHER_CTX_free(ctx);
}
//=======================================================================================

//=======================================================================================
AES_Encryptor::AES_Encryptor()
{
    base.generate_randoms();
    int rc; (void)rc;
}
//=======================================================================================
std::string AES_Encryptor::encrypt( const std::string & data )
{
    int rc;
    rc = EVP_EncryptInit(base.ctx, EVP_aes_256_cbc(), base.key, base.iv);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    std::string res;
    res.resize( data.size() + base.BLOCK_SIZE );
    int out_len1 = res.size();

    auto out_ptr = str_to_uchar( &res );
    auto in_ptr  = str_to_uchar( data );
    rc = EVP_EncryptUpdate(base.ctx, out_ptr, &out_len1, in_ptr, data.size());
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");

    int out_len2 = res.size() - out_len1;
    rc = EVP_EncryptFinal(base.ctx, out_ptr+out_len1, &out_len2);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");

    res.resize(out_len1 + out_len2);
    return res;
}
//=======================================================================================
// 16 -- sizes
// heap
AES_Encryptor::str AES_Encryptor::heap_encrypt(cstr heap, uint32_t body_size)
{
    auto salt = Monkey_AES::some_rand_hex(5, 15);
    vcat msg(salt, "\n", heap);
    auto emsg = encrypt(msg);
    uint32_t emsg_size = emsg.size();

    vbyte_buffer bb;
    bb.append( Monkey_AES::some_rand(8) );
    bb.append_LE(emsg_size);
    bb.append_LE(body_size);

    auto ebb = encrypt(bb);
    if (ebb.size() != 16) throw verror;

    ebb.append( emsg );
    return ebb;
}
//=======================================================================================


//=======================================================================================
AES_Decryptor::AES_Decryptor()
{}
//=======================================================================================
void AES_Decryptor::set_keys(std::string keys)
{
    base.set_keys(keys);
    int rc; (void)rc;
}
//=======================================================================================
std::string AES_Decryptor::decrypt( const std::string& data )
{
    int rc;
    rc = EVP_DecryptInit(base.ctx, EVP_aes_256_cbc(), base.key, base.iv);
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    std::string res;
    res.resize( data.size() );
    int out_len1 = res.size();

    auto in_ptr  = str_to_uchar( data );
    auto out_ptr = str_to_uchar( &res );
    rc = EVP_DecryptUpdate( base.ctx, out_ptr, &out_len1, in_ptr, data.size() );
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");

    int out_len2 = res.size() - out_len1;
    rc = EVP_DecryptFinal( base.ctx, out_ptr+out_len1, &out_len2 );
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed");

    // Set recovered text size now that we know it
    res.resize(out_len1 + out_len2);
    return res;
}
//=======================================================================================
AES_Decryptor::u32_u32 AES_Decryptor::decrypt_sizes(vbyte_buffer *data)
{
    if ( data->size() < 16 ) throw verror;
    auto view = data->view();
    view.u64_LE();
    auto heap = view.u32_LE();
    auto body = view.u32_LE();
    data->chop_front(16);

    return {heap, body};
}
//=======================================================================================
