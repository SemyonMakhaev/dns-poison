# DNS-poison

DNS-server cache poisoning tool

#### Description

<p>
This program is trying to put a fake data to a target DNS-server
cache. It sends a DNS-request to server and then it sends
a DNS-reply to all of server ports, so the program imitates
a forwarder of this server.
</p>

<p>
Program sends a forwarder reply to all of ports because it can't
predict which port is server waiting for response. If the program
sends a forwarder response to server earlier than a real forwarder
then a fake information will be written in the server cache.
</p>

<p>
A DNS-server interrraction protocol and packages formats
are described in <a target="_blank" href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
</p>

#### Usage

```sh
python3 poison.py [-h] server name address
```

#### Arguments

**Args** | **Description**
-------- | ----------------
`server` | IP-address of a target server
`name` | Requested domain name
`address` | IP-address of domain this name for writing to server cache
`-h` or `--help` | Show a help message
