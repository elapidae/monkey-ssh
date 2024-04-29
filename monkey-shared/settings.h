#pragma once

#include <vsettings.h>

//=======================================================================================
class Settings
{
public:
    using string = std::string;

    void load( std::string fname );

    struct Server {
        string   login      = "node";
        string   password   = "apes";
        uint16_t port       = 2883;
    } server;

    struct Client {
        string   server     = "v25735.hosted-by-vdsina.com";
        uint16_t port       = 2883;

        string   login      = "client";
        string   password   = "apes";
    } client;
};
//=======================================================================================
