# DNS-server cache poisoning tool

This program tries to put the set data to the
target server cache. It sends a DNS-request to
the server and after that it sends a DNS-reply
to this server, so the program imitates a
forwarder of server. It sends a forwarder reply
on all of ports because it isn't known from
which port server waits a response. If this
program sends a forwarder response to server
in time (earlier than a real forwarder) then
a fake information writes in the server cache.

The program requires three arguments: IP-address of
a target server, the requested domain name and the
IP-address for this domain name for writing to
server cache.

To show a help message use --help or -h argument.
