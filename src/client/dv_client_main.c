#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>

#include "dv_types.h"
#include "dv_errno.h"
#include "dv_lib.h"
#include "dv_client_net.h"
#include "dv_proto.h"

static const char *
dv_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
dv_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"tun", 0, 0, 't'},
	{"daemonize", 0, 0, 'd'},
	{"address", 0, 0, 'a'},
	{"port", 0, 0, 'p'},
	{"certificate", 0, 0, 'c'},
	{"root-ca", 0, 0, 'r'},
	{"key", 0, 0, 'k'},
	{"mode", 0, 0, 'm'},
	{0, 0, 0, 0}
};

static const char *
dv_options[] = {
	"--address      -a	IP address for TLS tunnel\n",	
	"--port         -p	Port for TLS tunnel\n",	
	"--certificate  -c	certificate file\n",	
	"--key          -k	private key file\n",	
	"--root-ca      -r	ca certificate file\n",	
	"--tun          -t	tun device name\n",	
	"--daemonize    -d	daemonize process\n",	
	"--mode         -m	mode(plaintext, tls, satl)\n",	
	"--help         -H	Print help information\n",	
};

static void 
dv_help(void)
{
	int     index;

	fprintf(stdout, "Version: %s\n", dv_program_version);

	fprintf(stdout, "\nOptions:\n");
	for(index = 0; index < DV_ARRAY_SIZE(dv_options); index++) {
		fprintf(stdout, "  %s", dv_options[index]);
	}
}

static const char *
dv_optstring = "Hdta:p:c:k:r:m:";

int
main(int argc, char **argv)  
{
    char                    *ip = NULL;
    char                    *port = NULL;
    char                    *ca = NULL;
    char                    *cf = NULL;
    char                    *key = NULL;
    char                    *dev = NULL;
    char                    *mode = NULL;
    struct sockaddr_in      addr = {
        .sin_family = AF_INET,
    };
    struct sockaddr_in6     addr6 = {
        .sin6_family = AF_INET6,
    };
    dv_u8                   proto = DV_PROTO_NONE;
    int                     c = 0;
    int                     d = 0;

    while((c = getopt_long(argc, argv, 
                    dv_optstring,  dv_long_opts, NULL)) != -1) {
        switch(c) {
            case 'H':
                dv_help();
                return DV_OK;

            case 'd':
                d = 1;
                break;

            case 't':
                dev = optarg;
                break;

            case 'a':
                ip = optarg;
                break;

            case 'p':
                port = optarg;
                break;

            case 'c':
                cf = optarg;
                break;

            case 'r':
                ca = optarg;
                break;

            case 'k':
                key = optarg;
                break;

            case 'm':
                mode = optarg;
                break;

            default:
                dv_help();
                return -DV_ERROR;
        }
    }

    if (cf == NULL) {
        fprintf(stderr, "Please input cf by -c!\n");
        return -DV_ERROR;
    }

    if (key == NULL) {
        fprintf(stderr, "Please input key by -k!\n");
        return -DV_ERROR;
    }

    if (d) {
        if (dv_process_daemonize() != DV_OK) {
            fprintf(stderr, "Daemonize failed!\n");
            return -DV_ERROR;
        }
    }

    if (mode != NULL) {
    }

    if (dv_ip_version4(ip)) {
        addr.sin_port = DV_HTONS(atoi(port));
        addr.sin_addr.s_addr = inet_addr(ip);
        return dv_v4_client(&addr, cf, key, ca, dev, proto);
    }

    addr6.sin6_port = DV_HTONS(atoi(port));
    return dv_v6_client(&addr6, cf, key, ca, dev, proto);
}
