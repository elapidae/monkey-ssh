#pragma once

#include <map>
#include <memory>
#include "settings.h"
#include "monkey_rsa.h"
#include "vtcp_server.h"

//=======================================================================================
class Node_Socket;
class Node_Server
{
public:
    using string = std::string;
    Node_Server();

    void set_settings( Settings settings );

    void listen();

    void print_status();

private:
    Settings settings;
    vtcp_server server;
    void server_accepted(vtcp_socket::accepted_peer peer);

    friend class Node_Socket;
    bool has_rsa_sha(string sha) const;

    using Node_Socket_Ptr = std::shared_ptr<Node_Socket>;
    std::map<Node_Socket*,Node_Socket_Ptr> waiters;
    std::map<std::string,Node_Socket_Ptr> connections;

    bool is_correct_login(string login, string pass) const;
    void logined( Node_Socket * socket, std::string sha );
    void deferred_delete_socket( Node_Socket * socket );
    std::string clients_list() const;
    Node_Socket_Ptr get_by_sha(string sha) const;
};
//=======================================================================================
