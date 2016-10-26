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
#include "dv_proto.h"
#include "dv_client_conf.h"
#include "dv_client_process.h"

static const char *
dv_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
dv_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"config", 0, 0, 'c'},
	{0, 0, 0, 0}
};

static const char *
dv_options[] = {
	"--config       -c	configure file\n",	
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
dv_optstring = "Hc:";

int
main(int argc, char **argv)  
{
    char                    *cf = NULL;
    dv_client_conf_t        conf = {};
    int                     c = 0;
    int                     ret = 0;

    while((c = getopt_long(argc, argv, 
                    dv_optstring,  dv_long_opts, NULL)) != -1) {
        switch(c) {
            case 'H':
                dv_help();
                return DV_OK;

            case 'c':
                cf = optarg;
                break;

            default:
                dv_help();
                return -DV_ERROR;
        }
    }

    if (cf == NULL) {
        fprintf(stderr, "Please input configure file by -c!\n");
        return -DV_ERROR;
    }

    ret = dv_cli_conf_parse(&conf, cf);
    if (ret != DV_OK) {
        fprintf(stderr, "Parse %s failed!\n", cf);
        return -DV_ERROR;
    }

    if (conf.cc_daemon) {
        if (dv_process_daemonize() != DV_OK) {
            fprintf(stderr, "Daemonize failed!\n");
            return -DV_ERROR;
        }
    }

    return -dv_client_process(&conf);
}
