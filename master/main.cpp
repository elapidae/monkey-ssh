#include "side_socket.h"

#include "vapplication.h"
#include "vcmdline_parser.h"
#include "side_socket.h"

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
    auto my_port = 2222;

    socket.set_rsa( rsa );
    socket.set_settings( sett );
    socket.connect();

    socket.logined += [&]
    {
        socket.send_clients_list_request();
    };

    socket.clients_list += [&](auto list)
    {
        for ( auto l: list ) {
            vdeb << l;
        }
        vdeb << "my sha:" << socket.sha();
    };

    vapplication::poll();
}
//=======================================================================================
