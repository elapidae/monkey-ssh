#include "node_socket.h"

#include "vlog.h"
#include "monkey_rsa.h"
#include "node_server.h"
#include "vcat.h"
#include "keyval.h"

using namespace std;

//=======================================================================================
Node_Socket::Node_Socket( Node_Server *_owner, vtcp_socket::accepted_peer peer )
    : owner( _owner )
{
    socket = peer.as_shared();
    socket->disconnected.link( this, &Node_Socket::disconnected );
    socket->received.link( this, &Node_Socket::received );

    cur_receiver = &Node_Socket::server_waiting_rsa_keys;
}
//=======================================================================================
Node_Socket::Node_Socket()
{
    socket.reset( new vtcp_socket );
    socket->disconnected.link( this, &Node_Socket::disconnected );
    socket->received.link( this, &Node_Socket::received );

    cur_receiver = &Node_Socket::server_waiting_rsa_keys;
}
//=======================================================================================
void Node_Socket::disconnected()
{

}
//=======================================================================================
void Node_Socket::received( const std::string& data )
{

}
//=======================================================================================
void Node_Socket::server_waiting_rsa_keys( const std::string& data )
{
    buffer += data;
    auto nn_pos = buffer.str().find("\n\n");
    if ( nn_pos == string::npos )
        return;

    auto _heap = buffer.left(nn_pos);
    buffer.chop_front( _heap.size() + 2 ); // 2 -- size of \n\n

    auto heap = KeyVal::split_heap( _heap );

    auto he = heap.at("e");
    auto hn = heap.at("n");
    rsa = Monkey_RSA::from_public_hex_e_n(he, hn);

    if ( owner->has_rsa_sha(rsa.sha_n()) )
    {
        socket->send("error:already in server\n\n");
        owner->deferred_delete_socket( this );
        return;
    }
    vcat answer;
    answer("aes:", aes_enc.hex_keys(), "\n\n");
    auto crypted = rsa.encrypt(answer);
    socket->send(crypted);
}
//=======================================================================================
