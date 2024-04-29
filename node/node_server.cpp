#include "node_server.h"

#include "vapplication.h"
#include "vlog.h"
#include "node_socket.h"

//=======================================================================================
Node_Server::Node_Server()
{
    server.accepted.link( this, &Node_Server::server_accepted );
}
//=======================================================================================
void Node_Server::set_settings(Settings s)
{
    settings = s;
}
//=======================================================================================
void Node_Server::listen()
{
    try
    {
        server.listen_any_ip4( settings.server.port );
    }
    catch (const std::exception &e)
    {
        vwarning << "listen server err:" << e.what();
        exit(0);
    }
}
//=======================================================================================
void Node_Server::server_accepted(vtcp_socket::accepted_peer peer)
{
    vdeb << "accepted connection from" << peer.peer_address();
    Node_Socket_Ptr ptr( new Node_Socket(this, peer) );
    waiters.emplace( ptr.get(), ptr );
}
//=======================================================================================
bool Node_Server::has_rsa_sha(string sha) const
{
    return connections.count(sha);
}
//=======================================================================================
bool Node_Server::is_correct_login( string login, string pass ) const
{
    return login == settings.server.login &&
           pass == settings.server.password;
}
//=======================================================================================
void Node_Server::logined( Node_Socket *socket, std::string sha )
{
    auto ptr = waiters[socket];
    connections.emplace( sha, ptr );

    waiters.erase(socket);
}
//=======================================================================================
void Node_Server::deferred_delete_socket( Node_Socket * socket )
{
    auto del = [this,socket]
    {
        if ( waiters.erase(socket) )
        {
            vdeb << "socket erased from waiters" << socket;
            return;
        }

        for ( auto & s: connections )
        {
            if ( s.second.get() == socket )
            {
                connections.erase( s.first );
                vdeb << "socket erased from connections" << socket;
                return;
            }
        }
        vwarning << "Cannot delete socket" << socket;
    };

    vapplication().invoke( del );
}
//=======================================================================================
std::string Node_Server::clients_list() const
{
    vcat res;
    for ( auto && kv: connections )
    {
        res(kv.first, ":", kv.second->client, "\n");
    }
    return res;
}
//=======================================================================================
Node_Server::Node_Socket_Ptr Node_Server::get_by_sha( string sha ) const
{
    auto it = connections.find( sha );
    return it == connections.end() ? nullptr : connections.at(sha);
}
//=======================================================================================
