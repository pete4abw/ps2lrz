#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([ps2lrz], [0.12], [pete@peterhyman.com],[],[https://github.com/pete4abw/ps2lrz])
AC_CONFIG_SRCDIR([ps2lrz.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([memset setlocale strtoull])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
