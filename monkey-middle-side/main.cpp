#include "vtcp_server.h"
#include "vtcp_socket.h"
#include "vcmdline_parser.h"
#include "vcat.h"
#include "vlog.h"
#include "vapplication.h"

#include "crypto_box.h"
#include <libssh/libsshpp.hpp>
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
int main( int argc, char** argv )
{
    vtcp_server ss;
    ss.listen_loopback_ip6(2983);
    vtcp_socket::shared_ptr sock;
    ss.accepted += [&](auto acc)
    {
        sock = acc.as_shared();
        vdeb << sock->peer_address();
        sock->received += [](auto data)
        {
            vdeb << data;
        };
    };
    vapplication::poll();
    return 0;


    Monkey_AES::test();

    vcmdline_parser args(argc, argv);
    //auto path = args.safe_starts_with("path=", "/tmp/monkey-ssh/");
    auto path = args.safe_starts_with("path=", "./");

    Settings sett;
    sett.load(path + "/monkey_settings.ini");

    auto rsa = Monkey_RSA::generate_or_read_private(".");

    Node_Server server, s2;
    server.set_settings(sett);
    server.listen();
    s2.set_settings(sett);
    //s2.listen();

    Side_Socket side;
    side.set_settings(sett);
    side.set_rsa(rsa);
    side.connect();

    side.logined += [&] {
        side.send_clients_list_request();
    };
    side.clients_list += [&](auto map) {
        vdeb << "clients_list";
        for (auto && kv: map) {
            vdeb << kv.first << kv.second;
        }
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
int __main( int argc, char** argv )
{
    Monkey_RSA::test();
    auto priv = Monkey_RSA::generate_or_read_private(".");
    auto pub  = Monkey_RSA::from_public_hex_e_n( priv.hex_e(), priv.hex_n() );
    return 0;

    for( int i = 0; i < 1000; ++i )
    {
        Monkey_RSA::generate_new(".");
        auto rsa = Monkey_RSA::generate_or_read_private(".");
        vdeb << rsa.sha_n();
    }
    return 0;
    vdeb << __DATE__ << __TIME__;
    vcmdline_parser args( argc, argv );

    auto s1_port = vcat::from_text<uint16_t>(args.safe_starts_with("s1-port=","2883"));
    auto s2_port = vcat::from_text<uint16_t>(args.safe_starts_with("s2-port=","2983"));

    vdeb << "s1 port =" << s1_port << ", s2 post =" << s2_port;

    vtcp_server server1, server2;

    server1.listen_any_ip4( s1_port );
    server2.listen_any_ip4( s2_port );

    server1.accepted += s1_accepted;
    server2.accepted += s2_accepted;

    vapplication::poll();
    return 0;
}
//=======================================================================================
