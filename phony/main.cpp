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
        socket->received += [&](auto data)
        {
            vdeb << "received:" << data;
            socket->send("\r\n\r\n<h1>HW!</h1>");
        };
    };

    vtimer t;
    t.timeout += [&]
    {
        static auto c = 0;
        static std::string msg;
        msg += vcat(++c);
        vdeb << msg;
        if (!socket || !socket->is_connected() ) return;
        socket->send( msg );
    };
    //
//    t.start(2s);
//    t.start(400ms);
//    t.start(100ms);
    //t.start(10ms);

    vapplication::poll();
}
//=======================================================================================
