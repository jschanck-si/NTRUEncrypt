AUTOMAKE_OPTIONS = foreign 1.9 subdir-objects

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_CFLAGS += -Wall -Wshadow

noinst_PROGRAMS = bin/sanity bin/test_poly_mul bin/sample_NTRUEncrypt
lib_LTLIBRARIES = libNTRUEncrypt.la

TESTS = bin/test_poly_mul

pkginclude_HEADERS = \
	include/ntru_crypto_error.h \
	include/ntru_crypto_platform.h \
	include/ntru_crypto_drbg.h \
	include/ntru_crypto.h

# libNTRUEncrypt.la
libNTRUEncrypt_la_SOURCES = \
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
libNTRUEncrypt_la_LDFLAGS = -export-symbols libNTRUEncrypt.sym
libNTRUEncrypt_la_CFLAGS = $(AM_CFLAGS) -Wno-parentheses


# Sanity check
bin_sanity_SOURCES = test/sanity.c
bin_sanity_LDADD = libNTRUEncrypt.la

# Check polynomial arithmetic correctness
bin_test_poly_mul_SOURCES = test/test_poly_mul.c
bin_test_poly_mul_CFLAGS = $(AM_CFLAGS) -DTEST_COMPARE_CONVOLUTIONS
bin_test_poly_mul_LDADD = libNTRUEncrypt.la

# Sample program
bin_sample_NTRUEncrypt_SOURCES = sample/sample_NTRUEncrypt.c
bin_sample_NTRUEncrypt_LDADD = libNTRUEncrypt.la

