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

        string   address    = "v37503.hosted-by-vdsina.com";
        uint16_t port       = 2883;
    } server;

    struct Client {
        string   login      = "client";
        string   password   = "apes";
    } client;
};
//=======================================================================================
