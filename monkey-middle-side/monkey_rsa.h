#pragma once

#include <openssl/rsa.h>
#include <string>
#include <stdexcept>

//struct Monkey_BIGNUM final
//{
//    Monkey_BIGNUM
//    BIGNUM *item = nullptr;
//}
//=======================================================================================
class Monkey_RSA final
{
public:
    class crypt_error : public std::runtime_error
    {
        using runtime_error::runtime_error;
    };

    static void generate_new(std::string path);

    static Monkey_RSA generate_or_read_private(std::string path);
    static Monkey_RSA read_public(std::string path);
    static Monkey_RSA public_key(std::string hex_e, std::string hex_n);

    std::string sha_n() const;

    std::string e() const;
    std::string n() const;

    std::string encrypt( const std::string& enc ) const;
    std::string decrypt( const std::string& enc ) const;

    std::string sign( const std::string& enc ) const;
    bool verify( const std::string& enc ) const;

    Monkey_RSA() {}
    ~Monkey_RSA();

    Monkey_RSA(Monkey_RSA && rhs) : rsa(rhs.rsa) { rhs.rsa = nullptr; }

private:
    RSA *rsa = nullptr;
};
//=======================================================================================
