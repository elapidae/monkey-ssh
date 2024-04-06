#include "node_server.h"

#include "vapplication.h"

//=======================================================================================
Node_Server::Node_Server()
{}
//=======================================================================================
Node_Server::reg_or_err
Node_Server::register_new_peer( Node_Socket* socket, const Monkey_RSA& rsa )
{
    auto sha = rsa.sha_n();
    if ( connections.count(sha) )
    {
        return {false, "SHA already in pool"};
    }
    return { true, {} };
}
//=======================================================================================
bool Node_Server::has_rsa_sha(string sha) const
{
    return connections.count(sha);
}
//=======================================================================================
void Node_Server::deferred_delete_socket( Node_Socket * socket )
{
    auto del = [this,socket] {
        waiters.erase(socket);
    };
    vapplication().invoke( del );
}
//=======================================================================================
