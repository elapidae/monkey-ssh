#include "vtcp_server.h"
#include "vtcp_socket.h"
#include "vcmdline_parser.h"
#include "vcat.h"
#include "vlog.h"
#include "vapplication.h"

#include <openssl/rsa.h>
#include "vbyte_buffer.h"
#include "settings.h"
#include "vcmdline_parser.h"
#include "node_socket.h"
#include "node_server.h"
#include "vtimer.h"

using namespace std;

//=======================================================================================
int main( int argc, char** argv )
{
    Monkey_AES::test();

    vcmdline_parser args( argc, argv );
    auto path = args.safe_starts_with( "path=", "/root/monkey-ssh/node" );

    Settings sett;
    auto sett_fname = path + "/node-settings.ini";
    system( vcat("touch ", sett_fname).str().c_str() );
    sett.load( sett_fname );

    //auto rsa = Monkey_RSA::generate_or_read_private( path );

    Node_Server server;
    server.set_settings( sett );
    server.listen();

    vtimer timer;
    timer.start(10s);
    timer.timeout.link( &server, &Node_Server::print_status );

    vapplication::poll();
}
//=======================================================================================
