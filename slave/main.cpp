#include "side_socket.h"

#include "vapplication.h"
#include "vcmdline_parser.h"
#include "side_socket.h"

//=======================================================================================
int main( int argc, char **argv )
{
    Monkey_AES::test();

    vcmdline_parser args( argc, argv );
    auto path = args.safe_starts_with( "path=", "/home/pushik/monkey-ssh/slave" );
    system( vcat("mkdir -p ", path, " 2>/dev/null").str().c_str() );

    Settings sett;
    auto sett_fname = path + "/slave-settings.ini";
    system( vcat("touch ", sett_fname, " 2>/dev/null").str().c_str() );
    sett.load( sett_fname );

    auto rsa = Monkey_RSA::generate_or_read_private( path );

    Side_Socket socket;
    socket.set_rsa( rsa );
    socket.set_settings( sett );
    socket.connect();

    vapplication::poll();
}
//=======================================================================================
