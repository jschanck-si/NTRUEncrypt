AC_INIT([libNTRUEncrypt],[1.0.0])
AC_CONFIG_SRCDIR([src/ntru_crypto_drbg.c])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST

AM_INIT_AUTOMAKE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT

dnl Suggest O3 optimization & no debugging if there are no user-specified CFLAGS
if test "x$CFLAGS" = "x"; then
  CFLAGS=-O3
fi
AC_PROG_CC

AC_ARG_ENABLE(simd,
   AS_HELP_STRING([--enable-simd=yes|no], [Enable vectorized polynomial arithmetic (default=no)]),
   [], [enable_simd=no])


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
