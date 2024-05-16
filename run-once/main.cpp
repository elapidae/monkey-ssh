#include <iostream>
#include <fstream>
#include <sstream>
#include "vcmdline_parser.h"
#include "vbyte_buffer.h"

using namespace std;

int main( int argc, char ** argv )
{
    string tmpfile = "/tmp/ps-once.log";

    vcmdline_parser args(argc, argv);
    //auto pidfile = args.take_starts_with( "pidfile=" );
    auto cmd = args.take_starts_with( "cmd=" );

    string ps = R"(ps -e --format="cmd"|grep ")" + cmd + '"';
    ps += " >" + tmpfile;
    cout << "ps cmd >>> " << ps << endl;
    system( ps.c_str() );

    ifstream ifile;
    ifile.open( tmpfile, ios_base::in );
    if ( ifile.bad() )
    {
        cout << "Cannot read file " << tmpfile << ", exit..." << endl;
        return 1;
    }
    string data;
    data.resize(1000000);
    auto sz = ifile.readsome( data.data(), data.size() );
    data.resize(sz);
    auto list = vbyte_buffer::split(data, '\n');
    for ( auto line: list )
    {
        cout << "ps >>> " << line << endl;
        if ( line != cmd ) continue;

        cout << "Found exactly identical command, exiting..." << endl;
        return 0;
    }

    cout << "Cmd not found by ps, let's start it..." << endl;
    auto rcode = system( cmd.c_str() );
    cout << "system exec returned " << rcode << endl;

    return 0;
}
//=======================================================================================
