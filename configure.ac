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

AC_CONFIG_FILES([
				 Makefile
				 src/Makefile
				 src/client/Makefile
				 src/server/Makefile
				 src/tools/Makefile
				 ])

AC_OUTPUT
