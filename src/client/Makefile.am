bin_PROGRAMS = dove_vpn_client
dove_vpn_client_SOURCES = dv_client_main.c dv_client_conf.c dv_client_vpn.c \
						  dv_client_process.c dv_client_ssl.c

dove_vpn_client_LDADD = $(srcdir)/../lib/libdove_vpn.la

AM_CFLAGS = -Wall -Werror -DDV_CLIENT -I$(srcdir)/../include -I$(srcdir)/../lib -lm
AUTOMAKE_OPTIONS = foreign subdir-objects
