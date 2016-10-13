bin_PROGRAMS = dove_vpn_server
dove_vpn_server_SOURCES = dv_server_main.c dv_server_conf.c dv_server_cycle.c \
						  ../dv_process.c dv_event.c ../dv_mem.c ../dv_conf.c \
						  dv_server_core.c dv_ip_pool.c ../dv_lib.c \
						  ../dv_tun.c

AM_CFLAGS = -Wall -Werror -I$(srcdir)/../include -I$(srcdir)/../ -lm
