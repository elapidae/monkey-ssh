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

    cur_receiver = &Node_Socket::waiting_rsa_keys;
}
//=======================================================================================
void Node_Socket::send_transit( vbyte_buffer tran_heap, const vbyte_buffer& body )
{
    auto heap = aes.heap_encrypt( tran_heap, body.size() );
    socket->send( heap );
    socket->send( body );
}
//=======================================================================================
bool Node_Socket::is_connected() const
{
    return socket->is_connected();
}
//=======================================================================================
void Node_Socket::disconnected()
{
    owner->deferred_delete_socket( this );
}
//=======================================================================================
void Node_Socket::received( const std::string& data )
{
    buffer += data;
    //vdeb << "node socket received" << buffer.size();
    (this->*cur_receiver)();
}
//=======================================================================================
void Node_Socket::waiting_rsa_keys()
{
    vdeb << "node socket waiting rsa keys";

    auto [ok, heap] = Heap::parse( &buffer );
    if (!ok) return;

    auto he = heap.at("e");
    auto hn = heap.at("n");
    rsa = Monkey_RSA::from_public_hex_e_n(he, hn);
    if ( rsa.bits() < 2048 )
    {
        vwarning << "defer del: rsa < 2048";
        socket->send("error:rsa < 2048\n\n");
        socket->close();
        owner->deferred_delete_socket( this );
        return;
    }

    if ( owner->check_has_rsa_sha(rsa.sha_n()) )
    {
        vwarning << "defer del: sha already";
        socket->send("error:already in server\n\n");
        socket->close();
        owner->deferred_delete_socket( this );
        return;
    }
    aes.generate_randoms();

    vcat answer;
    answer("aes:", aes.hex_keys(), "\n\n");
    auto crypted = rsa.encrypt(answer);
    socket->send(crypted);

    cur_receiver = &Node_Socket::waiting_login;
    vdeb << "node socket finished rsa keys";
}
//=======================================================================================
void Node_Socket::waiting_login()
{
    vdeb << "node waiting login";
    if ( !read_heap_body() ) return;

    vbyte_buffer heap = aes.decrypt(cur_heap);
    auto map = Heap::parse_with_salt( &heap );
    auto login = map.at("login");
    auto pass = map.at("password");
    auto logined = owner->is_correct_login(login, pass);
    if ( !logined )
    {
        socket->send( aes.heap_encrypt("error:Bad login/password\n\n") );
        socket->close();
        owner->deferred_delete_socket(this);
        return;
    }
    client = map.at("client");

    owner->logined( this, rsa.sha_n() );
    socket->send( aes.heap_encrypt("logined:OK\n\n") );
    cur_receiver = &Node_Socket::waiting_op;

    vdeb << "node finished login";
}
//=======================================================================================
void Node_Socket::waiting_op()
{
    //vdeb << "node waiting op";
    if ( !read_heap_body() ) return;

    cur_heap = aes.decrypt(cur_heap);
    auto map = Heap::parse_with_salt( &cur_heap );
    auto op = map.at("op");

    if ( op == "clients-list")
    {
        auto res = owner->clients_list() + "\n";
        auto crypted = aes.heap_encrypt(res);
        socket->send( crypted );
        return;
    }

    if ( op == "transit" )
    {
        auto target_sha = map["target"];
        vdeb << "transit, target:" << target_sha << ", body size:" << cur_body.size();
        auto target = owner->get_by_sha( target_sha );
        if ( !target ) {
            vdeb << "Has no target" << target_sha;
            vcat msg("op:error\ndesc:no target\ntarget:", target_sha, "\n\n");
            auto crypted = aes.heap_encrypt( msg );
            socket->send( crypted );
            return;
        }

        target->send_transit( cur_heap, cur_body );
        return;
    }

    vdeb << "UNKNOWN OP:" << op;
}
//=======================================================================================
bool Node_Socket::read_heap_body_sizes()
{
    if ( cur_heap_size != 0 ) return true;

    if ( buffer.size() < 16 ) return false;

    auto [h, b] = aes.decrypt_sizes( &buffer );
    cur_heap_size = h;
    cur_body_size = b;

    if ( cur_heap_size == 0 ) throw verror;
    return true;
}
//=======================================================================================
bool Node_Socket::read_heap_body()
{
    if ( !read_heap_body_sizes() )
        return false;

    if ( buffer.size() < cur_heap_size + cur_body_size )
        return false;

    cur_heap = buffer.left( cur_heap_size );
    buffer.chop_front( cur_heap_size );

    cur_body = buffer.left( cur_body_size );
    buffer.chop_front( cur_body_size );

    cur_heap_size = 0;
    cur_body_size = 0;

    return true;
}
//=======================================================================================
