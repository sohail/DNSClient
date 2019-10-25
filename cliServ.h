/*
cliServ.h
Written by, Sohail Qayum Malik
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DNS_SERV_PORT        53
#define SA struct sockaddr *

#define NUMBER_OF_QUESTIONS               0x0100    /* big endian, 1 */ 
#define RECURSIVE_QUERY                   0x0100
#define INVERSE_QUERY                     0x0800
#define DOMAIN_NAME_END                   0x00

#define RR_TYPE_ADDRESS                   0x0100    /* A */
#define RR_TYPE_NAME_SERVER               0x0200    /* NS */
#define RR_TYPE_CANONICAL_NAME            0x0500    /* CNAME */
#define RR_TYPE_HOST_INFO                 0x0D00    /* HINFO */
#define RR_TYPE_MAIL_EXCHANGE             0x0F00    /* MX */
#define RR_TYPE_REQUEST_FOR_ZONE_TRANSFER 0xFC00    /* AXFR */
#define RR_TYPE_ANY                       0xFF00    /* * or ANY */
#define RR_TYPE_PTR                       0x0C00    /* PTR */
#define RR_TYPE_SOA                       0x0600    /* SOA */
#define RR_TYPE_TXT                       0x1000    /* TXT */

#define CLASS_TYPE                        0x0100    /* internet class type */

