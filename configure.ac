AC_INIT([DoveVPN], [1.0], [jasonchin221@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_ARG_WITH(libevent_includes,
			[  --with-libevent-includes=DIR    libevent include directory],
			[with_libevent_includes="$withval"],
			[with_libevent_includes=no])

AC_ARG_WITH(libevent_libraries,
			[  --with-libevent-libraries=DIR   libevent library directory],
			[with_libevent_libraries="$withval"],
			[with_libevent_libraries=no])

AC_ARG_WITH(libcrypto_includes,
			[  --with-libcrypto-includes=DIR    libcrypto include directory],
			[with_libcrypto_includes="$withval"],
			[with_libcrypto_includes=no])

AC_ARG_WITH(libcrypto_libraries,
			[  --with-libcrypto-libraries=DIR   libcrypto library directory],
			[with_libcrypto_libraries="$withval"],
			[with_libcrypto_libraries=no])

AC_ARG_WITH(libssl_libraries,
			[  --with-libssl-libraries=DIR   libssl library directory],
			[with_libssl_libraries="$withval"],
			[with_libssl_libraries=no])

AC_ARG_WITH(libjson_includes,
			[  --with-libjson-includes=DIR    libjson include directory],
			[with_libjson_includes="$withval"],
			[with_libjson_includes=no])

AC_ARG_WITH(libjson_libraries,
			[  --with-libjson-libraries=DIR   libjson library directory],
			[with_libjson_libraries="$withval"],
			[with_libjson_libraries=no])


CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
LIBS="${LIBS} -L/usr/local/lib"

if test "$with_libevent_includes" != "no"; then
	CPPFLAGS="${CPPFLAGS} -I${with_libevent_includes}"
fi

if test "$with_libevent_libraries" != "no"; then
	LIBS="${LIBS} -L${with_libevent_libraries}"
fi

LPTHREAD=""
AC_CHECK_LIB([pthread], [pthread_create], , LPTHREAD="no")

if test "$LPTHREAD" = "no"; then
    echo
    echo "   ERROR!  pthread library not found, go get it from"
    echo "   or use the --with-pthread-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LIBEVENTH=""
AC_CHECK_HEADERS([event2/event.h], , OPENVCH="no")

if test "$LIBEVENTH" = "no"; then
    echo
    echo "   ERROR!  libevent headers not found, go get it from"
    echo "   http://www.xmlsoft.org/downloads.html"
    echo "   or use the --with-libevent-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LLIBEVENT=""
AC_CHECK_LIB([event], [event_base_dispatch], , LLIBEVENT="no")

if test "$LLIBEVENT" = "no"; then
    echo
    echo "   ERROR!  libevent library not found, go get it from"
    echo "   or use the --with-libevent-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LIBCRYPTO=""
AC_CHECK_HEADERS([openssl/ssl.h], , LIBCRYPTO="no")

if test "$LIBCRYPTO" = "no"; then
    echo
    echo "   ERROR!  libcrypto headers not found, go get it from"
    echo "   http://www.xmlsoft.org/downloads.html"
    echo "   or use the --with-libcrypto-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LLIBCRYPTO=""
AC_CHECK_LIB([crypto], [OPENSSL_config], , LLIBCRYPTO="no")

if test "$LLIBCRYPTO" = "no"; then
    echo
    echo "   ERROR!  libcrypto library not found, go get it from"
    echo "   or use the --with-libcrypto-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LLIBSSL=""
AC_CHECK_LIB([ssl], [SSL_get_verify_result], , LLIBSSL="no")

if test "$LLIBSSL" = "no"; then
    echo
    echo "   ERROR!  libssl library not found, go get it from"
    echo "   or use the --with-libssl-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi


LIBJSON=""
AC_CHECK_HEADERS([json-c/json.h], , LIBJSON="no")

if test "$LIBJSON" = "no"; then
    echo
    echo "   ERROR!  libjson headers not found, go get it from"
    echo "   http://www.xmlsoft.org/downloads.html"
    echo "   or use the --with-libjson-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LLIBJSON=""
AC_CHECK_LIB([json-c], [json_object_from_file], , LLIBJSON="no")

if test "$LLIBJSON" = "no"; then
    echo
    echo "   ERROR!  libjson library not found, go get it from"
    echo "   or use the --with-libjson-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

AC_CONFIG_FILES([
				 Makefile
				 src/Makefile
				 src/lib/Makefile
				 src/client/Makefile
				 src/server/Makefile
				 src/tools/Makefile
				 ])

AC_OUTPUT
