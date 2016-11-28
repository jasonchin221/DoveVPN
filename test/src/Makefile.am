bin_PROGRAMS = dove_test_client
dove_test_client_SOURCES = dv_test_cycle.c dv_test_main.c dv_test_conf.c \
						   ../../src/server/dv_ip_pool.c ../../src/server/dv_server_conn.c \
						   ../../src/server/dv_server_cycle.c  ../../src/server/dv_server_signal.c \
						   ../../src/server/dv_server_tun.c ../../src/server/dv_server_conf.c \
						   ../../src/server/dv_server_core.c ../../src/server/dv_server_socket.c \
						   ../../src/client/dv_client_ssl.c

dove_test_client_LDADD = $(srcdir)/../../src/lib/libdove_vpn.la

AM_CFLAGS = -Wall -Werror -I$(srcdir)/../../src/include -I$(srcdir)/../../src/lib \
			-I$(srcdir)/../../src/server -I$(srcdir)/../../src/client -lm
