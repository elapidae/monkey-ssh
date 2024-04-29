#include "settings.h"

#include "vsettings.h"
#include "vlog.h"

//=======================================================================================
void Settings::load( std::string fname )
{
    vsettings sett;
    if ( !sett.from_ini_file(fname) )
    {
        vwarning.nospace() << "Cannot open settings file '" << fname << "'";
        system("pwd");
        return;
    }
    auto serv = sett.subgroup("server");
    server.login    = serv.safe_get("login",    server.login);
    server.password = serv.safe_get("password", server.password);
    server.port     = serv.safe_get("port",     server.port);
    server.address  = serv.safe_get("address",  server.address);

    auto cli = sett.subgroup("client");
    client.login    = cli.safe_get("login",     client.login);
    client.password = cli.safe_get("password",  client.password);
}
//=======================================================================================
