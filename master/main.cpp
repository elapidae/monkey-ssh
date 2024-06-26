#include "side_socket.h"

#include "vapplication.h"
#include "vcmdline_parser.h"
#include "side_socket.h"

//=======================================================================================
void test_tcp( int port )
{
    static vtcp_socket peer;
    peer.connect( vsocket_address::loopback_ip4(port) );

    static vtcp_socket ssh;
    ssh.connected += []{ vdeb << "inside socket connected to master-slot"; };
    ssh.disconnected+= []{ vdeb << "disconnected"; };

    peer.connected += []{ vdeb << "inside socket connected to master-slot"; };
    peer.disconnected+= []{ vdeb << "disconnected"; };
    peer.received += [](auto data){
        vdeb << "received >> " << data;
    };
}
//=======================================================================================
int main( int argc, char **argv )
{
    Monkey_AES::test();

    vcmdline_parser args( argc, argv );
    auto path = args.safe_starts_with( "path=", "/home/el/monkey-ssh/master" );
    system( vcat("mkdir -p ", path, " 2>/dev/null").str().c_str() );

    Settings sett;
    auto sett_fname = path + "/master-settings.ini";
    system( vcat("touch ", sett_fname).str().c_str() );
    sett.load( sett_fname );

    auto rsa = Monkey_RSA::generate_or_read_private( path );

    Side_Socket socket;

    socket.set_rsa( rsa );
    socket.set_settings( sett );
    socket.connect();

    socket.logined += [&]
    {
        socket.send_clients_list_request();
    };

    //auto peer_sha = "2b45c3b6208cf87ebf6e4f46917940163ffd4eed";
    auto peer_sha = "85b2548706829f29d269d5aa38400c3097567ccc";
    auto my_port = 2222;
    socket.clients_list += [&](auto list)
    {
        for ( auto l: list ) {
            vdeb << l;
        }
        vdeb << "my sha:" << socket.sha();
        socket.bind_port_proxy( 1, peer_sha, my_port, 22 );
        //test_tcp(my_port);
    };

    vapplication::poll();
}
//=======================================================================================
