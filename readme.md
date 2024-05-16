
In raspberry:
===

add to `/etc/rc.local`
`autossh -f -N -R 2222:localhost:2222 root@v37503.hosted-by-vdsina.com`

Port 2221 -- local port (for Pi: 22)
Port 2222 -- new binded port in server 
`autossh -f -N -R 2222:localhost:2221 root@v37503.hosted-by-vdsina.com`

So, finished command:
autossh -f -N -R 2222:localhost:22 root@v37503.hosted-by-vdsina.com


In server:
===
`ssh -N -f -g -L 2223:localhost:2222 root@localhost`
