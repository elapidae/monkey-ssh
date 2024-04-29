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

    auto cli = sett.subgroup("client");
    client.server   = cli.safe_get("server",    client.server);
    client.port     = cli.safe_get("port",      client.port);
    client.login    = cli.safe_get("login",     client.login);
    client.password = cli.safe_get("password",  client.password);
}
//=======================================================================================
