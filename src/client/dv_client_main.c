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

static const char *
dv_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
dv_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"client", 0, 0, 'C'},
	{"server", 0, 0, 'S'},
	{"address", 0, 0, 'a'},
	{"port", 0, 0, 'p'},
	{"certificate", 0, 0, 'c'},
	{"key", 0, 0, 'k'},
	{0, 0, 0, 0}
};

static const char *
dv_options[] = {
	"--address      -a	IP address for SSL communication\n",	
	"--port         -p	Port for SSL communication\n",	
	"--certificate  -c	certificate file\n",	
	"--key          -k	private key file\n",	
	"--client       -C	Client use openssl lib\n",	
	"--server       -S	Server use openssl lib\n",	
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
dv_optstring = "HCSa:p:c:k:";

int
main(int argc, char **argv)  
{
    int                     c = 0;

    while((c = getopt_long(argc, argv, 
                    dv_optstring,  dv_long_opts, NULL)) != -1) {
        switch(c) {
            case 'H':
                dv_help();
                return DV_OK;

            default:
                dv_help();
                return -DV_ERROR;
        }
    }

    return 0;
}
