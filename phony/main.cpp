#include "side_socket.h"

#include "vapplication.h"
#include "vcmdline_parser.h"
#include "side_socket.h"

#include "vtcp_server.h"

using namespace std::chrono_literals;

//=======================================================================================
int main( int argc, char **argv )
{
    vtcp_server phony;
    phony.listen_loopback_ip4(1111);

    vtcp_socket::unique_ptr socket;
    phony.accepted += [&](vtcp_socket::accepted_peer peer)
    {
        socket = peer.as_unique();
        socket->received += [](auto data)
        {
            vdeb << "received:" << data;
        };
    };

    vtimer t;
    t.timeout += [&]
    {
        static auto c = 0;
        vdeb << ++c;
        if (!socket) return;
        socket->send( vcat("phony ", c++) );
    };
    t.start(1s);

    vapplication::poll();
}
//=======================================================================================
