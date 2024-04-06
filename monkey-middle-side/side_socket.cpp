#include "side_socket.h"

#include "vcat.h"
#include "keyval.h"

using namespace std;

//=======================================================================================
Side_Socket::Side_Socket()
{
    socket.connected.link(this, &Side_Socket::connected);
}
//=======================================================================================
void Side_Socket::set_settings(Settings s)
{
    settings = s;
}
//=======================================================================================
void Side_Socket::set_rsa(Monkey_RSA rsa_)
{
    rsa = rsa_;
}
//=======================================================================================
void Side_Socket::connect()
{
    socket.connect( {settings.client.server, settings.client.port} );
}
//=======================================================================================
void Side_Socket::connected()
{
    auto e = rsa.hex_e();
    auto n = rsa.hex_n();

    vcat msg("e:", e, "\n", "n:", n, "\n\n");
    socket.send(msg);

    waiter = &Side_Socket::wait_aes;
}
//=======================================================================================
void Side_Socket::received( const std::string& data )
{
    buffer = data;
    (this->*waiter)();
}
//=======================================================================================
void Side_Socket::wait_aes()
{
    auto [ok, heap] = Heap::parse( &buffer );
    if (!ok) return;

    auto err = heap.find("error");
    if (err != heap.end()) {
        error_happened(err->second);
        socket.close();
        return;
    }
    aes_dec.set_keys( heap.at("aes") );

    vcat msg("login:", settings.server.login, "\n");
    msg("password:", settings.server.password, "\n\n");

    //git saes_enc

    socket.send(msg);

}
//=======================================================================================
