#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(bpf-tools, 0.1, marianp@mellanox.com)
AC_CONFIG_SRCDIR([sample/sample-user.c])
AM_INIT_AUTOMAKE([foreign])

# Checks for programs.
AC_PROG_CC([clang])

CFLAGS_COMMON+=" -I/usr/include/x86_64-linux-gnu"
CFLAGS_KERN+=" -target bpf"

AC_SUBST(CFLAGS_COMMON)
AC_SUBST(CFLAGS_KERN)

AC_ARG_VAR([IPROUTE2_SRC], [path to iproute2 sources])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([inet_ntoa memset socket strerror])

AC_CONFIG_FILES([Makefile
                 sample/Makefile])
AC_OUTPUT
