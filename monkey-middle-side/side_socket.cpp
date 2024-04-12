#include "side_socket.h"

#include "vcat.h"
#include "keyval.h"
#include "vbyte_buffer_view.h"

using namespace std;

//=======================================================================================
Side_Socket::Side_Socket()
{
    socket.connected.link(this, &Side_Socket::connected);
    socket.received.link(this, &Side_Socket::received);
}
//=======================================================================================
void Side_Socket::set_settings(Settings s)
{
    settings = s;
}
//=======================================================================================
void Side_Socket::set_rsa(Monkey_RSA rsa_)
{
    rsa = rsa_;
}
//=======================================================================================
void Side_Socket::connect()
{
    vsocket_address addr{settings.client.server, settings.client.port};
    vdeb << "About to connect" << addr;
    socket.connect( addr );
}
//=======================================================================================
void Side_Socket::send_clients_list_request()
{
    auto heap = aes.heap_encrypt("op:clients-list\n\n");
    socket.send(heap);
    waiter = &Side_Socket::wait_clients;
}
//=======================================================================================
void Side_Socket::connected()
{
    vdeb << "connected to server" << socket.peer_address();

    auto e = rsa.hex_e();
    auto n = rsa.hex_n();

    vcat msg("e:", e, "\n", "n:", n, "\n\n");
    socket.send(msg);

    waiter = &Side_Socket::wait_aes;
}
//=======================================================================================
void Side_Socket::received( const std::string& data )
{
    buffer = data;
    vdeb << "side socket received" << buffer.size() << "bytes";

    (this->*waiter)();
}
//=======================================================================================
void Side_Socket::wait_aes()
{
    vdeb << "side socket waiting aes";
    auto block_size = rsa.block_size();
    if ( buffer.size() < block_size )
        return;

    auto block = buffer.view().string(block_size);
    buffer.chop_front(block_size);

    vbyte_buffer heap_ = rsa.decrypt(block);

    auto [ok, heap] = Heap::parse( &heap_ );
    if (!ok) throw verror;

    auto err = heap.find("error");
    if (err != heap.end()) {
        error_happened(err->second);
        socket.close();
        return;
    }
    aes.set_keys( heap.at("aes") );

    vcat msg("login:", settings.server.login, "\n");
    msg("password:", settings.server.password, "\n");
    msg("client:", settings.client.login, "\n\n");

    auto crypted = aes.heap_encrypt(msg);
    socket.send(crypted);

    waiter = &Side_Socket::wait_logined;
    vdeb << "side socket finished aes";
}
//=======================================================================================
void Side_Socket::wait_logined()
{
    vdeb << "side: wait logined";
    if ( !read_heap_body() ) return;

    vbyte_buffer heap = aes.decrypt(cur_heap);
    auto map = Heap::parse_with_salt(&heap);

    if (map.count("error"))
    {
        vdeb << "Side error:" << map["error"];
        socket.close();
        return;
    }
    vdeb << "Side logined:" << map["logined"];

    waiter = &Side_Socket::wait_any;
    logined();

    vdeb << "side: finished logined";
}
//=======================================================================================
void Side_Socket::wait_any()
{
    if ( !read_heap_body() ) return;
    cur_heap = aes.decrypt(cur_heap);
    auto map = Heap::parse_with_salt(&cur_heap);

    if (map.at("op") == "clients-updated")
    {
        auto [ok,clients] = Heap::parse(&cur_heap);
        if (!ok) throw verror;
        clients_list(clients);
        return;
    }
    vdeb << "side: any received... bad..." << map;
}
//=======================================================================================
void Side_Socket::wait_clients()
{
    if ( !read_heap_body() ) return;
    cur_heap = aes.decrypt(cur_heap);
    auto map = Heap::parse_with_salt(&cur_heap);
    clients_list(map);
    waiter = &Side_Socket::wait_any;
}
//=======================================================================================
bool Side_Socket::read_heap_body_sizes()
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
bool Side_Socket::read_heap_body()
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
