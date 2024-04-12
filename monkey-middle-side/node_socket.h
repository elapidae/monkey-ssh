#pragma once

#include "monkey_aes.h"
#include "monkey_rsa.h"
#include "vtcp_socket.h"
#include "vtimer.h"
#include "vbyte_buffer.h"

//=======================================================================================
class Node_Server;
class Node_Socket
{
public:
    // As server
    Node_Socket( Node_Server * owner, vtcp_socket::accepted_peer peer );

//    vsignal<void*> disconnected;
//    vsignal<std::string, std::string> send;

//private:
    void disconnected();
    void received( const std::string& data );

    void waiting_rsa_keys();
    void waiting_login();
    void waiting_op();



    using receive_ptr = decltype( &Node_Socket::waiting_rsa_keys );

    Node_Server * owner;
    vbyte_buffer buffer;
    receive_ptr cur_receiver = nullptr;
    vtcp_socket::shared_ptr socket;
    Monkey_RSA rsa;
    Monkey_AES aes;
    std::string client;

    bool read_heap_body_sizes();
    bool read_heap_body();
    uint32_t cur_heap_size = 0, cur_body_size = 0;
    vbyte_buffer cur_heap, cur_body;
};
//=======================================================================================
