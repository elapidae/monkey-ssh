#pragma once

#include "monkey_aes.h"
#include "monkey_rsa.h"
#include "vtcp_socket.h"
#include "vtimer.h"
#include "vbyte_buffer.h"
#include "settings.h"
#include "keyval.h"
#include "vtcp_server.h"

//=======================================================================================
class Side_Socket;
class Slot_Proxy
{
public:
    Side_Socket *owner {nullptr};
    int counter = 0;
    bool initial = false;

    vtcp_socket socket;
    std::string peer_sha;
    uint16_t peer_port;

    vtcp_server server;
    vtcp_socket::shared_ptr server_socket;

    Slot_Proxy();
private:
};
//=======================================================================================
class Side_Socket
{
public:
    Side_Socket();

    void set_settings(Settings s);
    void set_rsa(Monkey_RSA rsa);

    std::string sha() const;

    void connect();

    vsignal<std::string> error_happened;
    vsignal<> logined;

    void send_clients_list_request();
    vsignal<KeyVal::Map> clients_list;

    void bind_port_proxy( int slot,
                          std::string target_sha,
                          uint16_t src_port,
                          uint16_t peer_port );

    void make_port_proxy( int slot,
                          std::string target_sha,
                          uint16_t peer_port );

    void send_slot_connected(Slot_Proxy* slot);
    void send_slot_disconnected(Slot_Proxy* slot);
    void send_slot_received( Slot_Proxy* slot, const std::string &body );

private:
    void connected();
    void received( const std::string& data );

    void wait_aes();
    void wait_logined();
    void wait_any();
    void wait_clients();

    //void wait_proxy();

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

    Slot_Proxy slot1, slot2;
};
//=======================================================================================
