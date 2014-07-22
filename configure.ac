#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([webauth-via-ssh], [0.1], [])
dnl AC_CONFIG_SRCDIR([test-app/fcgi/b64dec.c])
dnl AC_CONFIG_HEADERS([config.h])

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

dnl look for spawn-fcgi and nginx
AC_ARG_VAR([SPAWN_FCGI],[path to spawn-fcgi program.])
AC_PATH_PROG([SPAWN_FCGI],[spawn-fcgi],[missing-spawn-fcgi])
if test "x$SPAWN_FCGI" = "xmissing-spawn-fcgi" ; then
	AC_MSG_WARN([could not find spawn-fcgi. some scripts will not work.])
fi
AC_ARG_VAR([NGINX_BIN],[path to nginx binary.])
AC_PATH_PROG([NGINX_BIN],[nginx],[missing-nginx])
if test "x$NGINX_BIN" = "xmissing-nginx" ; then
	AC_MSG_WARN([could not find nginx. some scripts will not work.])
fi

PATCHEDSSHD=""
AC_ARG_WITH([patched-sshd],
	[AS_HELP_STRING([--with-patched-sshd=xxx],
					[location of sshd patched with authorized_keys_script])],
	[
		if test -n "$withval" ; then
			PATCHEDSSHD="$withval"
		fi
	]
)
AC_SUBST([PATCHEDSSHD])

SSH_USER=`whoami`
AC_ARG_WITH([ssh-user],
	[AS_HELP_STRING([--with-ssh-user=xxx],
					[local account used to multiplex accounts for the web
					 application (like the "git" user at github.)])],
	[
		if test -n "$withval" ; then
			SSH_USER="$withval"
		fi
	]
)
AC_SUBST([SSH_USER])

PATCHED_SSHD_PORT=31337
AC_ARG_WITH([sshd-port],
	[AS_HELP_STRING([--with-sshd-port=xxx],
					[run patched sshd on this port (default: 31337)])],
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
	[AS_HELP_STRING([--with-libwebsockets=xxx],
					[path to local source tree])],
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
	[AS_HELP_STRING([--with-nginx-tmp-dir=xxx],
					[path for nginx tempfiles and logs (defaults to
					 /tmp/nginx/)])],
	[
		if test -n "$withval" ; then
			NGINX_TMP_DIR="$withval"
		fi
	]
)
AC_SUBST([NGINX_TMP_DIR])

dnl stole the next few from openSSH.  Thanks guys! :D
AC_ARG_WITH([cflags],
	[AS_HELP_STRING([--with-cflags],
					[Specify additional flags to pass to compiler])],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			CFLAGS="$CFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([cppflags],
	[AS_HELP_STRING([--with-cppflags],
					[Specify additional flags to pass to preprocessor])],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			CPPFLAGS="$CPPFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([ldflags],
	[AS_HELP_STRING([--with-ldflags],
					[Specify additional flags to pass to linker])],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			LDFLAGS="$LDFLAGS $withval"
		fi
	]
)

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

m4_define([conf_gen_files],[auth-modules/Makefile
							ssh-conf/Makefile
							test-app/fcgi/Makefile
							test-app/html/login.html
							test-app/nginx/nginx.conf
							Makefile])
AC_CONFIG_FILES(conf_gen_files)
m4_define([conf_gen_scripts],[ssh-conf/start-sshd.sh test-app/startnginx.sh])
m4_define([ADD_CONFIG_FILE_EXEC], [AC_CONFIG_FILES([$1], [chmod +x $1])])
m4_map_args_w(conf_gen_scripts, [ADD_CONFIG_FILE_EXEC(], [)])
dnl now save list for distclean
CONFIG_GEN_FILES="m4_normalize(conf_gen_scripts conf_gen_files)"
AC_SUBST([CONFIG_GEN_FILES])

AC_OUTPUT

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
