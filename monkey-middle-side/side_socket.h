#pragma once

#include "monkey_aes.h"
#include "monkey_rsa.h"
#include "vtcp_socket.h"
#include "vtimer.h"
#include "vbyte_buffer.h"
#include "settings.h"

//=======================================================================================
class Side_Socket
{
public:
    Side_Socket();

    void set_settings(Settings s);
    void set_rsa(Monkey_RSA rsa);

    void connect();

    vsignal<std::string> error_happened;

private:
    void connected();
    void received( const std::string& data );

    void wait_aes();
    void wait_aes1();

    using waiter_fn = decltype(&Side_Socket::wait_aes);
    waiter_fn waiter = nullptr;

    vtcp_socket socket;
    Settings settings;
    Monkey_RSA rsa;
    AES_Encryptor aes_enc;
    AES_Decryptor aes_dec;
    vbyte_buffer buffer;
};
//=======================================================================================
