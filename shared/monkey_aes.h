#pragma once

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string>
#include "vbyte_buffer.h"
#include <memory>

//=======================================================================================
class Monkey_AES final
{
public:
    static void test();

    using str = std::string;
    using cstr = const str&;
    using str_str = std::tuple<str,str>;
    using str_u32 = std::tuple<str,uint32_t>;
    using u32_u32 = std::tuple<uint32_t,uint32_t>;

    static std::string some_rand_hex(int size, int diff);
    static std::string some_rand(int size);

    Monkey_AES();
    void generate_randoms();
    void set_keys( std::string hex_keys );
    std::string hex_keys() const;

    std::string encrypt( const std::string& data );
    str heap_encrypt(cstr heap, uint32_t body_size = 0);

    std::string decrypt( const std::string& data );
    u32_u32 decrypt_sizes(vbyte_buffer* data);

private:
    static const unsigned int KEY_SIZE = 32;
    static const unsigned int BLOCK_SIZE = 16;

    typedef unsigned char byte;
    byte key[KEY_SIZE], iv[BLOCK_SIZE];

    std::shared_ptr<EVP_CIPHER_CTX> ctx;
};
//=======================================================================================
