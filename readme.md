
In raspberry:
add to `/etc/rc.local`
`autossh -f -N -R 2222:localhost:2222 root@v37503.hosted-by-vdsina.com`

in server:
`ssh -N -f -g -L 2223:localhost:2222 root@localhost`
