AUTOMAKE_OPTIONS = foreign 1.9 subdir-objects

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I$(top_srcdir)/include
AM_CFLAGS += -Wall -Wshadow

noinst_PROGRAMS = \
	bin/sanity \
	bin/bench \
	bin/sample_NTRUEncrypt

# Set conditionally below
TESTS =

noinst_LTLIBRARIES = libntrutests.la
lib_LTLIBRARIES = libntruencrypt.la

pkginclude_HEADERS = \
	include/ntru_crypto_error.h \
	include/ntru_crypto_platform.h \
	include/ntru_crypto_drbg.h \
	include/ntru_crypto.h

noinst_HEADERS = \
	src/ntru_crypto_hash_basics.h \
	src/ntru_crypto_hash.h \
	src/ntru_crypto_hmac.h \
	src/ntru_crypto_msbyte_uint32.h \
	src/ntru_crypto_ntru_convert.h \
	src/ntru_crypto_ntru_encrypt_key.h \
	src/ntru_crypto_ntru_encrypt_param_sets.h \
	src/ntru_crypto_ntru_mgf1.h \
	src/ntru_crypto_ntru_poly.h \
	src/ntru_crypto_sha1.h \
	src/ntru_crypto_sha256.h \
	src/ntru_crypto_sha2.h \
	src/ntru_crypto_sha.h \
	test/test_common.h

dist_pkgdata_DATA = libntruencrypt.sym

# libntruencrypt.la
libntruencrypt_la_CFLAGS = $(AM_CFLAGS) -Wno-parentheses
libntruencrypt_la_LDFLAGS = -export-symbols $(top_srcdir)/libntruencrypt.sym
libntruencrypt_la_SOURCES = \
	src/ntru_crypto_drbg.c \
	src/ntru_crypto_hash.c \
	src/ntru_crypto_hmac.c \
	src/ntru_crypto_msbyte_uint32.c \
	src/ntru_crypto_ntru_convert.c \
	src/ntru_crypto_ntru_encrypt.c \
	src/ntru_crypto_ntru_encrypt_key.c \
	src/ntru_crypto_ntru_encrypt_param_sets.c \
	src/ntru_crypto_ntru_mgf1.c \
	src/ntru_crypto_ntru_poly.c \
	src/ntru_crypto_sha256.c \
	src/ntru_crypto_sha1.c \
	src/ntru_crypto_sha2.c
if SIMD_ENABLED
libntruencrypt_la_SOURCES += \
	src/ntru_crypto_ntru_mult_indices_simd.c \
	src/ntru_crypto_ntru_mult_coeffs_simd.c
libntruencrypt_la_CFLAGS += $(SIMD_FLAGS)
else
libntruencrypt_la_SOURCES += \
	src/ntru_crypto_ntru_mult_indices.c \
	src/ntru_crypto_ntru_mult_coeffs_karat.c
endif


# If we have the CHECK package then link an extra copy of the library
# with all internal functions exposed and build unit tests
if HAVE_CHECK
TESTS += bin/check_public bin/check_internal
noinst_PROGRAMS += bin/check_public bin/check_internal

noinst_LTLIBRARIES += libntruencrypt_check.la

libntruencrypt_check_la_CFLAGS = $(libntruencrypt_la_CFLAGS)
libntruencrypt_check_la_LDFLAGS =
libntruencrypt_check_la_SOURCES = $(libntruencrypt_la_SOURCES)
else
# If we don't have CHECK fall back to the basic sanity test
TESTS += bin/sanity
endif


# Test helper library
libntrutests_la_SOURCES = \
	test/test_common.c

# Crude benchmarking program
bin_bench_SOURCES = test/bench.c
bin_bench_LDADD = \
	$(top_builddir)/libntruencrypt.la \
	$(top_builddir)/libntrutests.la

# Sample program
bin_sample_NTRUEncrypt_SOURCES = sample/sample_NTRUEncrypt.c
bin_sample_NTRUEncrypt_LDADD = libntruencrypt.la

# Sanity test for when CHECK package is not available
bin_sanity_SOURCES = test/sanity.c
bin_sanity_LDADD = \
	$(top_builddir)/libntruencrypt.la \
	$(top_builddir)/libntrutests.la

# Tests using only the public API
bin_check_public_SOURCES = test/check_public.c
bin_check_public_CFLAGS = $(AM_CFLAGS) @CHECK_CFLAGS@
bin_check_public_LDADD = \
	$(top_builddir)/libntruencrypt.la \
	$(top_builddir)/libntrutests.la \
	@CHECK_LIBS@

# Tests requiring access to internals
bin_check_internal_SOURCES = test/check_internal.c
bin_check_internal_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/src @CHECK_CFLAGS@
bin_check_internal_LDADD = \
	$(top_builddir)/libntruencrypt_check.la \
	$(top_builddir)/libntrutests.la \
	@CHECK_LIBS@
