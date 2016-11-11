bin_PROGRAMS = dove_vpn_server
dove_vpn_server_SOURCES = dv_server_main.c dv_server_conf.c dv_server_cycle.c \
						  dv_server_core.c dv_ip_pool.c dv_server_socket.c \
						  dv_server_tun.c dv_server_signal.c

dove_vpn_server_LDADD = $(srcdir)/../lib/libdove_vpn.la

AM_CFLAGS = -Wall -Werror -I$(srcdir)/../include -I$(srcdir)/../lib -lm
