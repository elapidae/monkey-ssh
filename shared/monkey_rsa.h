#pragma once

#include <openssl/rsa.h>
#include <string>
#include <stdexcept>
#include <memory>

//struct Monkey_BIGNUM final
//{
//    Monkey_BIGNUM
//    BIGNUM *item = nullptr;
//}
//=======================================================================================
class Monkey_RSA final
{
public:
    static void test();

    class crypt_error : public std::runtime_error
    {
        using runtime_error::runtime_error;
    };

    static void generate_new(std::string path);

    static Monkey_RSA generate_or_read_private(std::string path);
    //static Monkey_RSA read_public(std::string path);
    static Monkey_RSA from_public_hex_e_n(std::string hex_e, std::string hex_n);

    std::string sha_n() const;

    std::string hex_e() const;
    std::string hex_n() const;

    std::string encrypt( const std::string& enc ) const;
    std::string decrypt( const std::string& enc ) const;

    uint bits() const;
    uint block_size() const;

    //std::string sign( const std::string& enc ) const;
    //bool verify( const std::string& enc ) const;

private:
    std::shared_ptr<RSA> rsa;
};
//=======================================================================================
