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

    // As client
    Node_Socket();

//    vsignal<void*> disconnected;
//    vsignal<std::string, std::string> send;

//private:
    void disconnected();
    void received( const std::string& data );

    void server_waiting_rsa_keys( const std::string& data );
    void on_aes( const std::string& data );

    using receive_ptr = decltype( &Node_Socket::server_waiting_rsa_keys );

    Node_Server * owner;
    vbyte_buffer buffer;
    receive_ptr cur_receiver = nullptr;
    vtcp_socket::shared_ptr socket;
    Monkey_RSA rsa;
    AES_Encryptor aes_enc;
    AES_Decryptor aes_dec;
};
//=======================================================================================
