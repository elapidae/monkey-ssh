#include "side_socket.h"

#include "vcat.h"
#include "keyval.h"
#include "vbyte_buffer_view.h"

using namespace std;

//=======================================================================================
Side_Socket::Side_Socket()
{
    slot1.owner = this;
    slot1.counter = 1;

    slot2.owner = this;
    slot2.counter = 2;

    socket.connected.link(this, &Side_Socket::connected);
    socket.received.link(this, &Side_Socket::received);
    socket.disconnected += [this]{
        disconnected();
    };
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
string Side_Socket::sha() const
{
    return rsa.sha_n();
}
//=======================================================================================
void Side_Socket::connect()
{
    vsocket_address addr{settings.server.address, settings.server.port};
    vdeb << "About to connect" << addr;
    socket.connect( addr );
}
//=======================================================================================
void Side_Socket::send_clients_list_request()
{
    auto heap = aes.heap_encrypt("op:clients-list\n\n");
    socket.send(heap);
    waiter = &Side_Socket::wait_any;
}
//=======================================================================================
void Side_Socket::bind_port_proxy( int slot,
                                   std::string target_sha,
                                   uint16_t src_port,
                                   uint16_t peer_port )
{
    if ( slot != 1 && slot != 2 ) throw verror;

    auto &sl = slot == 1 ? slot1 : slot2;
    sl.initial   = true;
    sl.peer_sha  = target_sha;
    sl.peer_port = peer_port;

    sl.server.listen( vsocket_address::loopback_ip4(src_port) );
    vdeb << "Local proxy addr:" << sl.server.address();

    waiter = &Side_Socket::wait_any;
}
//=======================================================================================
void Side_Socket::make_port_proxy( int slot,
                                   string target_sha,
                                   uint16_t peer_port )
{
    if ( slot != 1 && slot != 2 ) throw verror;

    vcat cmd;
    cmd( "op:transit\n" );
    cmd( "target:", target_sha, "\n\n" );
    // next part
    cmd( "source:", sha(), "\n" );
    cmd( "op:connect\n" );
    cmd( "slot:", slot, "\n" );
    cmd( "port:", peer_port, "\n\n" );

    auto heap = aes.heap_encrypt( cmd );
    socket.send(heap);
    waiter = &Side_Socket::wait_any;
    vdeb << "master-slot sent connect cmd";
}
//=======================================================================================
void Side_Socket::send_slot_connected( Slot_Proxy * slot )
{
    vcat cmd;
    cmd( "op:transit\n" );
    cmd( "target:", slot->peer_sha, "\n\n" );
    // next part
    cmd( "op:connected\n" );
    cmd( "slot:", slot->counter, "\n\n" );

    auto heap = aes.heap_encrypt( cmd );
    socket.send(heap);
    vdeb << "slave-slot connected, sent this";
}
//=======================================================================================
void Side_Socket::send_slot_disconnected( Slot_Proxy * slot )
{
    vcat cmd;
    cmd( "op:transit\n" );
    cmd( "target:", slot->peer_sha, "\n\n" );
    // next part
    cmd( "op:disconnected\n" );
    cmd( "slot:", slot->counter, "\n\n" );

    auto heap = aes.heap_encrypt( cmd );
    socket.send(heap);
}
//=======================================================================================
void Side_Socket::send_slot_received( Slot_Proxy * slot, const std::string & body )
{
    vcat cmd;
    cmd( "op:transit\n" );
    cmd( "target:", slot->peer_sha, "\n\n" );
    // next part
    cmd( "op:received\n" );
    cmd( "slot:", slot->counter, "\n\n" );

    auto heap = aes.heap_encrypt( cmd, body.size() );

    socket.send( heap );
    socket.send( body );

    vdeb << "slot proxied " << body.size() << "bytes";
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
    buffer += data;
    (this->*waiter)();
}
//=======================================================================================
void Side_Socket::wait_aes()
{
    vdeb << "side socket waiting aes";

    if ( buffer.starts_with("error:") )
    {
        vdeb << "Error found:" << buffer;
        socket.close();
        exit(0);
    }

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
        //exit(0);
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
    if ( !read_heap_body() )
        return;

    cur_heap = aes.decrypt( cur_heap );
    auto map = Heap::parse_with_salt( &cur_heap );
    auto op = map.at( "op" );

    if ( op == "clients-updated" )
    {
        auto [ok, clients] = Heap::parse( &cur_heap );
        if ( !ok ) {
            throw verror;
        }

        clients_list(clients);
        return;
    }

    if ( op == "connect" )
    {        
        auto * slot = map.at("slot") == "1" ? &slot1 : &slot2;
        auto port = vcat::from_text<uint16_t>( map.at("port") );
        slot->peer_sha = map.at("source");
        slot->initial = false;
        slot->socket.connect( vsocket_address::loopback_ip4(port) );
        vdeb << "About to connect to:" << port << "src:" << slot->peer_sha;
        return;
    }

    if ( op == "clients-list")
    {
        map.erase("op");
        clients_list(map);
        return;
    }

    if ( op == "connected" )
    {
        vdeb << "Peer connected, slot" << map.at("slot");
        return;
    }

    if ( op == "disconnected" )
    {
        vdeb << "Peer disconnected, " << map;
        auto * slot = map.at("slot") == "1" ? &slot1 : &slot2;
        slot->server_socket->close();
        return;
    }

    if ( op == "received" )
    {
        //vdeb << "received";

        auto * slot = map.at("slot") == "1" ? &slot1 : &slot2;

        if ( slot->initial )
        {
            if ( !slot->server_socket ) {
                vdeb << "Peer sent data to empty server socket";
                return;
            }
            slot->server_socket->send( cur_body );
            return;
        }

        slot->socket.send( cur_body );
        return;
    }

    if ( op == "error" )
    {
        if ( map["desc"] == "no target" )
        {
            auto target = map["target"];
            vdeb << "no target: " << target;
            if ( slot1.peer_sha == target )
            {
                slot1.socket.close();
                slot1.server_socket.reset();
            }
            if ( slot2.peer_sha == target )
            {
                slot2.socket.close();
                slot2.server_socket.reset();
            }
            return;
        }
    }

    vdeb << sha() << op << "side: any received... bad..." << map;
    throw verror;
}
//=======================================================================================
bool Side_Socket::read_heap_body_sizes()
{
    if ( cur_heap_size != 0 ) return true;

    if ( buffer.size() < 16 ) return false;

    aes.decrypt_sizes( &buffer, &cur_heap_size, &cur_body_size );

    //vdeb << "DECRYPTED SIZES:" << cur_heap_size << cur_body_size;

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

    //vdeb << "heap" << cur_heap.toHex() << ", body: " << cur_body << "buf left:" << buffer.size();

    return true;
}
//=======================================================================================
Slot_Proxy::Slot_Proxy()
{
    socket.connected += [this]
    {
        assert(owner);
        owner->send_slot_connected( this );
    };
    socket.disconnected += [this]
    {
        assert(owner);
        owner->send_slot_disconnected( this );
    };

    socket.received += [this]( auto && data )
    {
        assert(owner);
        owner->send_slot_received( this, data );
    };


    server.accepted += [this]( vtcp_socket::accepted_peer peer )
    {
        vdeb << "master-server accepted connection";
        server_socket = peer.as_shared();
        server_socket->received += [this]( auto & data )
        {
            owner->send_slot_received( this, data );
        };

        owner->make_port_proxy( counter, peer_sha, peer_port );
    };
}
//=======================================================================================
