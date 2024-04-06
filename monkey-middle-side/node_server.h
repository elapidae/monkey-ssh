#pragma once

#include "monkey_rsa.h"
#include <map>
#include <memory>

//=======================================================================================
class Node_Socket;
class Node_Server
{
public:
    using string = std::string;
    Node_Server();

private:
    friend class Node_Socket;
    using reg_or_err = std::tuple<bool, string>;
    reg_or_err register_new_peer( Node_Socket * socket, const Monkey_RSA& rsa );

    bool has_rsa_sha(string sha) const;

    using Node_Socket_Ptr = std::shared_ptr<Node_Socket>;
    std::map<Node_Socket*,Node_Socket_Ptr> waiters;
    std::map<std::string,Node_Socket_Ptr> connections;

    void deferred_delete_socket( Node_Socket * socket );
};
//=======================================================================================
