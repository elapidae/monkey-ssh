#include "vtcp_server.h"
#include "vtcp_socket.h"
#include "vcmdline_parser.h"
#include "vcat.h"
#include "vlog.h"
#include "vapplication.h"

#include <openssl/rsa.h>
#include "monkey_rsa.h"
#include "monkey_aes.h"
#include "vbyte_buffer.h"
#include "settings.h"
#include "vcmdline_parser.h"
#include "node_socket.h"
#include "node_server.h"
#include "side_socket.h"

using namespace std;

//=======================================================================================
void tune_phony_sha_server(int port)
{
    static vtcp_server server;
    server.listen_any_ip4(port);
    server.accepted += [](vtcp_socket::accepted_peer peer)
    {
        static auto socket = peer.as_shared();
        auto timer = new vtimer;
        timer->start(1s);
        timer->timeout += [&]
        {
            static auto cnt = 0;
            socket->send( vcat("any many ", ++cnt) );
        };
        socket->received += [](auto data)
        {
            vdeb << "Phony ssh server got:" << data;
        };
    };
}
//=======================================================================================
int main( int argc, char** argv )
{
    Monkey_AES::test();

    vcmdline_parser args(argc, argv);
    //auto path = args.safe_starts_with("path=", "/tmp/monkey-ssh/");
    auto path = args.safe_starts_with("path=", "./");

    Settings sett;
    sett.load(path + "/monkey_settings.ini");

    auto rsa = Monkey_RSA::generate_or_read_private(".");
    system("mkdir rsa2");
    auto rsa2 = Monkey_RSA::generate_or_read_private("rsa2");

    Node_Server server;
    server.set_settings(sett);
    server.listen();

    Side_Socket peer_socket;
    peer_socket.set_settings(sett);
    peer_socket.set_rsa( rsa2 );
    peer_socket.connect();

    Side_Socket my_side;
    my_side.set_settings(sett);
    my_side.set_rsa(rsa);
    my_side.connect();

    my_side.logined += [&] {
        my_side.send_clients_list_request();
    };

    auto peer_ssh_port = 2222;
    tune_phony_sha_server(peer_ssh_port);

    vtcp_socket use_ssh_socket;
    auto use_ssh_port = 1111;
    //use_ssh_socket.connect( vsocket_address::loopback_ip4(use_ssh_port) );
    use_ssh_socket.received += [&](auto data)
    {
        vdeb << "Use socket received:" << data;
        static auto a = 0;
        if (!a) use_ssh_socket.send( vcat("answer ", ++a) );
    };

    my_side.clients_list += [&](auto map) {
        vdeb << "clients_list";
        for (auto && kv: map) {
            vdeb << kv.first << kv.second;
        }
        auto src_sha = my_side.sha();
        auto dst_sha = peer_socket.sha();
        if ( !map.count(dst_sha) )
        {
            vdeb << "has not test sha" << dst_sha;
            return;
        }
        vdeb << "===================================================\n"
             << "SOURCE:" << src_sha << "\nDEST:" << dst_sha;
        my_side.make_port_proxy( 1, src_sha, dst_sha, use_ssh_port, peer_ssh_port );
        use_ssh_socket.connect( vsocket_address::loopback_ip4(use_ssh_port) );
    };

    vapplication::poll();
}
//=======================================================================================


//=======================================================================================
vtcp_socket::unique_ptr socket1;
vtcp_socket::unique_ptr socket2;
void s1_received( const string& data )
{
    if ( !socket2 ) return;
    if ( !socket2->is_connected() ) return;
    socket2->send( data );
}
void s2_received( const string& data )
{
    if ( !socket1 ) return;
    if ( !socket1->is_connected() ) return;
    socket1->send( data );
}
//------------------------------------------
void s1_accepted( vtcp_socket::accepted_peer peer )
{
    socket1 = peer.as_unique();
    socket1->received += s1_received;
    static int cnt = 0;
    vdeb << ++cnt << "server1 accepted from" << socket1->address();
}
void s2_accepted( vtcp_socket::accepted_peer peer )
{
    socket2 = peer.as_unique();
    socket2->received += s2_received;
    static int cnt = 0;
    vdeb << ++cnt << "server2 accepted from" << socket2->address();
}
//=======================================================================================
