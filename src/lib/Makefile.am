lib_LTLIBRARIES = libdove_vpn.la
libdove_vpn_la_SOURCES = dv_buffer.c dv_conf.c dv_event.c dv_if.c dv_lib.c \
						 dv_log.c dv_mem.c dv_msg.c dv_openssl.c dv_tun.c \
						 dv_process.c dv_proto.c dv_socket.c dv_trans.c \
						 dv_signal.c dv_channel.c

libdove_vpn_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include -fPIC
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
