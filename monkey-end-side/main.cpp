#include "vtcp_server.h"
#include "vtcp_socket.h"
#include "vcmdline_parser.h"
#include "vcat.h"
#include "vlog.h"
#include "vapplication.h"
#include "vtimer.h"
#include <thread>

using namespace std;
using namespace chrono_literals;

//=======================================================================================
string peer_server, ssh_server;
uint16_t peer_port, ssh_port;
//=======================================================================================
class Peer
{
public:
    Peer( string server, uint16_t port )
        : server( server )
        , port( port )
    {
        peer.connected += [this] { vdeb << "peer connected to" << peer.peer_address(); };

        peer.disconnected     += [this] { disconnected(); };
        peer.err_broken_pipe  += [this] { disconnected(); };
        peer.err_conn_refused += [this] { disconnected(); };
    }

    void connect()
    {
        if ( peer.is_connected() ) return;
        static int cnt = 0;
        vdeb << ++cnt << "About peer connect to" << server << ":" << port;
        peer.connect( {server, port} );
    }

private:
    string server;
    uint16_t port;

    friend class SSH;
    vsignal<> disconnected;
    vtcp_socket peer;
};
//=======================================================================================
class SSH
{
public:
    SSH( Peer * peer, string server, uint16_t port )
        : server( server )
        , port( port )
    {
        ssh.connected.link( this, &SSH::ssh_connected );
        ssh.disconnected.link( &peer->peer, &vtcp_socket::close );
        ssh.received.link( &peer->peer, &vtcp_socket::send );

        peer->peer.received.link( this, &SSH::peer_received );
        peer->disconnected.link ( this, &SSH::clear );
    }

private:
    void connect()
    {
        if ( ssh.is_connected() ) return;
        static int cnt = 0;
        vdeb << ++cnt << "About ssh connect to" << server << ":" << port;
        ssh.connect( {server, port} );
    }

    void clear()
    {
        buffer.clear();
        ssh.close();
    }

    void ssh_connected()
    {
        if ( buffer.empty() ) return;
        ssh.send( buffer );
        buffer.clear();
    }

    void peer_received( const string& data )
    {
        if ( ssh.is_connected() )
        {
            ssh.send( data );
            return;
        }
        connect();
        buffer += data;
    }
    string server;
    uint16_t port;

    string buffer;
    vtcp_socket ssh;
};
//=======================================================================================
int main( int argc, char** argv )
{
    vcmdline_parser args( argc, argv );

    peer_server = args.safe_starts_with( "peer-server=", "v25735.hosted-by-vdsina.com" );
    peer_port   = vcat::from_text<uint16_t>( args.safe_starts_with("peer-port=","2883"));

    ssh_server = args.safe_starts_with( "ssh-server=", "localhost" );
    ssh_port   = vcat::from_text<uint16_t>( args.safe_starts_with("ssh-port=","22"));

    Peer peer( peer_server, peer_port );
    SSH ssh( &peer, ssh_server, ssh_port );


    vtimer timer;
    timer.start( 1s );

    timer.timeout += [&]{ peer.connect(); };
    vapplication::poll();
    return 0;
}
//=======================================================================================
