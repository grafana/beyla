#pragma once

// Taken from linux/socket.h
#define AF_UNIX 1   /* Unix sockets             */
#define AF_INET 2   /* Internet IP Protocol     */
#define AF_INET6 10 /* IP version 6	            */

#define IP_V6_ADDR_LEN 16
#define IP_V6_ADDR_LEN_WORDS 4

// Most Linux distros use 32768 to 61000 for the ephemeral ports, so we look up from 32768
// IANA suggests that the range should be 49152-65535, which is what Windows uses
#define EPHEMERAL_PORT_MIN 32768

// Taken from errno.h
#define EINPROGRESS 115 /* Operation now in progress */

// Taken from uapi/linux/if_ether.h
#define ETH_HLEN 14       /* Total octets in header.       */
#define ETH_P_IP 0x0800   /* Internet Protocol packet      */
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook            */

// Taken from uapi/linux/in.h
#define IPPROTO_TCP 6 /* Transmission Control Protocol */

// Taken from linux/include/net/tcp.h
#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80

#define TCP_SEND 1
#define TCP_RECV 0

#define NO_SSL 0
#define WITH_SSL 1
