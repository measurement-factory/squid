## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

libexec_PROGRAMS= ntlm_fake_auth

ntlm_fake_auth_SOURCES = ntlm_fake_auth.cc
ntlm_fake_auth_LDADD= \
	$(top_builddir)/lib/ntlmauth/libntlmauth.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LIBNETTLE_LIBS) \
	$(CRYPTLIB) \
	$(XTRA_LIBS)

## Demo using perl.
## ntlm_fake_auth.pl: ntlm_fake_auth.pl.in
##	$(subst_perlshell)

EXTRA_DIST= \
	ntlm_fake_auth.pl.in \
	required.m4
