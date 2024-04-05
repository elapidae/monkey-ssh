#pragma once

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string>

//=======================================================================================
class Monkey_AES final
{
public:
    static std::string some_rand(int size, int diff);


    Monkey_AES();
    ~Monkey_AES();

    void generate_randoms();
    void set_keys( std::string hex_keys );
    std::string hex_keys() const;

    static const unsigned int KEY_SIZE = 32;
    static const unsigned int BLOCK_SIZE = 16;

    typedef unsigned char byte;
    byte key[KEY_SIZE], iv[BLOCK_SIZE];

    EVP_CIPHER_CTX *ctx = nullptr;
};
//=======================================================================================
class AES_Encryptor final
{
public:
    AES_Encryptor();
    std::string encrypt( const std::string& data );
    std::string hex_keys() const { return base.hex_keys(); }

private:
    Monkey_AES base;
};
//=======================================================================================
class AES_Decryptor final
{
public:
    AES_Decryptor();
    void set_keys( std::string keys );

    std::string decrypt( const std::string& data );

private:
    Monkey_AES base;
};
//=======================================================================================
