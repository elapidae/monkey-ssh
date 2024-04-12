#pragma once

#include "monkey_aes.h"
#include "monkey_rsa.h"
#include "vtcp_socket.h"
#include "vtimer.h"
#include "vbyte_buffer.h"
#include "settings.h"
#include "keyval.h"

//=======================================================================================
class Side_Socket
{
public:
    Side_Socket();

    void set_settings(Settings s);
    void set_rsa(Monkey_RSA rsa);

    void connect();

    vsignal<std::string> error_happened;
    vsignal<> logined;

    void send_clients_list_request();
    vsignal<KeyVal::Map> clients_list;

private:
    void connected();
    void received( const std::string& data );

    void wait_aes();
    void wait_logined();
    void wait_any();
    void wait_clients();

    using waiter_fn = decltype(&Side_Socket::wait_aes);
    waiter_fn waiter = nullptr;

    vtcp_socket socket;
    Settings settings;
    Monkey_RSA rsa;
    Monkey_AES aes;
    vbyte_buffer buffer;

    bool read_heap_body_sizes();
    bool read_heap_body();
    uint32_t cur_heap_size = 0, cur_body_size = 0;
    vbyte_buffer cur_heap, cur_body;
};
//=======================================================================================
