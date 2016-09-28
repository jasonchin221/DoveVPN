bin_PROGRAMS = dove_vpn_client
dove_vpn_client_SOURCES = dv_client_main.c dv_client_conf.c dv_client_process.c \
						  ../dv_log.c  ../dv_process.c ../dv_conf.c \
						  ../dv_tun.c
dove_vpn_client_LDADD = $(srcdir)/../lib/libdove_vpn.la

AM_CPPFLAGS = -I$(srcdir)/../include -I$(srcdir)/../ -lm
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
