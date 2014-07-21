#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([webauth-via-ssh], [0.1], [])
dnl AC_CONFIG_SRCDIR([test-app/fcgi/b64dec.c])
dnl AC_CONFIG_HEADERS([config.h])
# not sure if we need above.

AC_PROG_CC
AC_PROG_CXX

if test -z "$LD" ; then
	LD=$CC
fi
AC_SUBST([LD])

dnl Checks for libraries.
AC_CHECK_LIB([crypto], [HMAC],[],[NO_SYSTEM_SSL=1])
AC_CHECK_LIB([fcgi], [FCGI_printf],[],[NO_SYSTEM_FCGI=1])
AC_CHECK_LIB([rt], [time])
AC_CHECK_LIB([ssl], [HMAC],[],[NO_SYSTEM_SSL=1])
AC_CHECK_LIB([websockets], [libwebsocket_service],[],[NO_SYSTEM_LIBWS=1])

dnl Checks for header files.
AC_USE_SYSTEM_EXTENSIONS
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

dnl Checks for library functions.
AC_FUNC_MALLOC
dnl AC_FUNC_STRNLEN some crazy how invokes a sequence that will require all
dnl the standard files like "install.sh", so we leave that out.
AC_CHECK_FUNCS([bzero memset socket strchr])

PATCHEDSSHD=""
AC_ARG_WITH([patched-sshd],
	[  --with-patched-sshd=xxx Location of sshd patched with authorized_keys_script],
	[
		if test -n "$withval" ; then
			PATCHEDSSHD="$withval"
		fi
	]
)
AC_SUBST([PATCHEDSSHD])

SSH_USER=`whoami`
AC_ARG_WITH([ssh-user],
	[  --with-ssh-user=xxx local user account used to multiplex accounts for
	 the web application (like the 'git' user at github.)],
	[
		if test -n "$withval" ; then
			SSH_USER="$withval"
		fi
	]
)
AC_SUBST([SSH_USER])

PATCHED_SSHD_PORT=31337
AC_ARG_WITH([sshd-port],
	[  --with-sshd-port=xxx run patched sshd on this port (default: 31337).],
	[
		if test -n "$withval" ; then
			PATCHED_SSHD_PORT="$withval"
		fi
	]
)
AC_SUBST([PATCHED_SSHD_PORT])

LOCAL_LIBWS=""
LWSLDFLAGS=""
LWSCPPFLAGS=""
AC_ARG_WITH([libwebsockets],
	[  --with-libwebsockets=xxx path to local source tree],
	[
		if test -n "$withval" ; then
			LOCAL_LIBWS="$withval"
			LWSLDFLAGS="-L${LOCAL_LIBWS}/build/lib/ -Wl,-O1,-rpath ${LOCAL_LIBWS}/build/lib/"
			LWSCPPFLAGS="-I${LOCAL_LIBWS}/lib/"
		fi
		if ! test -f $LOCAL_LIBWS/build/lib/libwebsockets.so ; then
			AC_MSG_WARN([Could not find shared object lib in $LOCAL_LIBWS/build/lib/
						 Please symlink "build" to the build dir for libwebsockets.])
		fi
	]
)
AC_SUBST([LOCAL_LIBWS])
AC_SUBST([LWSLDFLAGS])
AC_SUBST([LWSCPPFLAGS])

NGINX_TMP_DIR="/tmp/nginx"
AC_ARG_WITH([nginx-tmp-dir],
	[  --with-nginx-tmp-dir=xxx path for nginx tempfiles and logs (defaults to
				 /tmp/nginx/)],
	[
		if test -n "$withval" ; then
			NGINX_TMP_DIR="$withval"
		fi
	]
)
AC_SUBST([NGINX_TMP_DIR])

dnl stole the next few from openSSH.  Thanks guys! :D
AC_ARG_WITH([cflags],
	[  --with-cflags           Specify additional flags to pass to compiler],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			CFLAGS="$CFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([cppflags],
	[  --with-cppflags         Specify additional flags to pass to preprocessor] ,
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			CPPFLAGS="$CPPFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([ldflags],
	[  --with-ldflags          Specify additional flags to pass to linker],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			LDFLAGS="$LDFLAGS $withval"
		fi
	]
)
dnl AC_ARG_WITH([libs],
dnl 	[  --with-libs             Specify additional libraries to link with],
dnl 	[
dnl 		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
dnl 		    test "x${withval}" != "xyes"; then
dnl 			LIBS="$LIBS $withval"
dnl 		fi
dnl 	]
dnl )

# assuming configure invoked as ./configure, we save a few useful dirs:
PROJECT_ROOT=`pwd`
SSH_CONF_DIR=$PROJECT_ROOT/ssh-conf
NGINX_CONF_DIR=$PROJECT_ROOT/test-app/nginx
AUTH_MODULES_DIR=$PROJECT_ROOT/auth-modules
TEST_APP_DIR=$PROJECT_ROOT/test-app
AC_SUBST([PROJECT_ROOT])
AC_SUBST([SSH_CONF_DIR])
AC_SUBST([NGINX_CONF_DIR])
AC_SUBST([AUTH_MODULES_DIR])
AC_SUBST([TEST_APP_DIR])

dnl AC_OUTPUT would create all of the following using variable
dnl substitution: each @VAR@ occurence in "blah.in" would be replaced
dnl by the contents of some shell variable VAR in file "blah".
dnl So be careful with that.
AC_CONFIG_FILES([auth-modules/Makefile
                 ssh-conf/start-sshd.sh
				 ssh-conf/Makefile
                 test-app/fcgi/Makefile
				 test-app/html/login.html
				 test-app/startnginx.sh
				 test-app/nginx/nginx.conf
				 Makefile])
AC_OUTPUT

dnl make scripts executable:
chmod +x ssh-conf/start-sshd.sh test-app/startnginx.sh

if test -z "$PATCHEDSSHD" ; then
	AC_MSG_WARN([server depends on a patched version sshd, available here:
				  https://github.com/norbauer/openssh-for-git.git])
fi

if test "$NO_SYSTEM_FCGI" = "1"; then
	AC_MSG_WARN([server requires fastcgi:
				 http://www.fastcgi.com/])
fi

if test "$NO_SYSTEM_SSL" = "1"; then
	AC_MSG_WARN([client and server require openssl.])
fi

if test "$NO_SYSTEM_LIBWS" = "1" && test -z $LOCAL_LIBWS ; then
	AC_MSG_WARN([client requires libwebsockets:
                 git://git.libwebsockets.org/libwebsockets])
fi
