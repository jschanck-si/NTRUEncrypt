AC_PREREQ([2.69])
AC_INIT([libNTRUEncrypt],[1.0.0])
AC_CONFIG_SRCDIR([src/ntru_crypto_drbg.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])

dnl autoscan: Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h])

dnl autoscan: Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT16_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

dnl autoscan: Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove memset])

dnl Compute the canonical host-system type variable, host, and its three individual
dnl parts host_cpu, host_vendor, and host_os.
AC_CANONICAL_HOST


AM_INIT_AUTOMAKE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT

dnl Suggest -O3 without debugging symbols if there are no user-specified CFLAGS
if test "x$CFLAGS" = "x"; then
  CFLAGS=-O3
fi
AC_PROG_CC

AC_ARG_ENABLE(simd,
   AS_HELP_STRING([--enable-simd=yes|no],
                  [Enable vectorized polynomial arithmetic (default=no)]),
                  [], [enable_simd=no])


simd_support=no
if test x$enable_simd != xno; then
  AC_CHECK_HEADERS([immintrin.h])
  AC_MSG_CHECKING(whether we have SSSE3 instructions)
  AC_LINK_IFELSE([AC_LANG_PROGRAM([ #include <immintrin.h> ],
                  [ __m128i a,b; _mm_alignr_epi8(a, b, 1); ])],
                  [simd_support=yes; AC_MSG_RESULT(yes)], [AC_MSG_RESULT(no)])
fi
AM_CONDITIONAL(SIMD_ENABLED, test x$simd_support != xno)



AC_CONFIG_FILES([Makefile])
AC_OUTPUT
