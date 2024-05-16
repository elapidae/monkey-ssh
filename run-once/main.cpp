#include <iostream>
#include <fstream>
#include <sstream>
#include "vcmdline_parser.h"
#include "vbyte_buffer.h"
#include "vlog.h"
#include "vcat.h"
#include <stdlib.h>

using std::string;

int main( int argc, char ** argv )
{
    vcmdline_parser args(argc, argv);
    auto cmd = args.take_starts_with( "cmd=" );
    auto id = args.safe_starts_with( "id=", "ID" );

    vlog::set_shared_log( "/tmp/run-once-" + id + ".log", 16*1024, 3 );

    std::string tmp_name = "/tmp/run-once-XXXXXX";
    tmp_name = mktemp( tmp_name.data() );
    vdeb << "tmp filename:" << tmp_name;

    string ps = R"(ps -e --format="cmd"|grep ")" + cmd + '"';
    ps += " >" + tmp_name;
    vtrace << "ps cmd >>> " << ps;
    system( ps.c_str() );

    auto lines = [tmp_name]
    {
        std::ifstream ifile;
        ifile.open( tmp_name, std::ios_base::in );
        if ( ifile.bad() )
        {
            throw verror << "Cannot read file " << tmpfile;
        }
        string data;
        data.resize(1000000);
        auto sz = ifile.readsome( data.data(), data.size() );
        data.resize(sz);
        auto res = vbyte_buffer::split(data, '\n');
        system( ("rm " + tmp_name).c_str() );
        return res;
    }();
    for ( auto line: lines )
    {
        vtrace << "ps >>> " << line;
        if ( line != cmd ) continue;

        vdeb << "Found exactly identical command, exiting...";
        return 0;
    }

    vdeb << "Cmd not found by ps, let's start it...";
    auto rcode = system( cmd.c_str() );
    vdeb << "system exec returned " << rcode;

    return 0;
}
//=======================================================================================
