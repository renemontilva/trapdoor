#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(td2, 1.6, clifford@clifford.at)
AC_CONFIG_SRCDIR([gencookie.c])
AC_CONFIG_HEADER([config.h])

# Use /etc instead of $prefix/etc
test "$sysconfdir" = '${prefix}/etc' && sysconfdir=/etc

AC_ARG_WITH(openssl, [  --with-openssl          use OpenSSL])
AC_ARG_WITH(gnutls,  [  --with-gnutls           use GNU TLS])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([crypt], [crypt])

if test "$with_openssl" != "no" ; then
AC_CHECK_LIB([crypto], [BIO_new])
AC_CHECK_LIB([ssl], [SSL_new], , 
  if test "$with_gnutls" != "no" ; then
    AC_CHECK_LIB([gnutls], [gnutls_init], , AC_MSG_ERROR(no suitable SSL library found))
  fi, -lcrypto)
elif test "$with_gnutls" != "no" ; then
  AC_CHECK_LIB([gnutls], [gnutls_init], , AC_MSG_ERROR(no suitable SSL library found))
else
  AC_MSG_ERROR(you need to enable at least one SSL library)
fi

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h crypt.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([alarm getpass gettimeofday inet_ntoa memset socket strdup strerror strrchr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
