bin_PROGRAMS = dove_vpn_client
dove_vpn_client_SOURCES = dv_client_main.c dv_client_conf.c dv_client_vpn.c \
						  dv_client_process.c ../dv_log.c ../dv_process.c \
						  ../dv_conf.c ../dv_socket.c ../dv_tun.c ../dv_if.c \
						  ../dv_openssl.c ../dv_proto.c dv_client_ssl.c \
						  ../dv_mem.c ../dv_trans.c

AM_CFLAGS = -Wall -Werror -DDV_CLIENT -I$(srcdir)/../include -I$(srcdir)/../ -lm
AUTOMAKE_OPTIONS = foreign subdir-objects
