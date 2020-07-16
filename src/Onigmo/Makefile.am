## Makefile.am for Oniguruma
encdir    = $(top_srcdir)/enc
sampledir = $(top_srcdir)/sample
libname = libonig.la

ACLOCAL_AMFLAGS = -I m4
#AM_CFLAGS = -DNOT_RUBY
AM_CFLAGS =
INCLUDES  = -I$(top_srcdir) -I$(includedir)

SUBDIRS = . sample

include_HEADERS = oniguruma.h oniggnu.h onigposix.h
lib_LTLIBRARIES = $(libname)

libonig_la_SOURCES = regint.h regparse.h regenc.h st.h \
	regerror.c regparse.c regext.c regcomp.c regexec.c reggnu.c \
	regenc.c regsyntax.c regtrav.c regversion.c st.c \
	regposix.c regposerr.c \
	$(encdir)/unicode.c $(encdir)/ascii.c $(encdir)/utf8.c \
	$(encdir)/utf16_be.c $(encdir)/utf16_le.c \
	$(encdir)/utf32_be.c $(encdir)/utf32_le.c \
	$(encdir)/unicode/casefold.h $(encdir)/unicode/name2ctype.h \
	$(encdir)/euc_jp.c $(encdir)/sjis.c $(encdir)/cp932.c \
	$(encdir)/iso8859_1.c \
	$(encdir)/iso8859_2.c  $(encdir)/iso8859_3.c \
	$(encdir)/iso8859_4.c  $(encdir)/iso8859_5.c \
	$(encdir)/iso8859_6.c  $(encdir)/iso8859_7.c \
	$(encdir)/iso8859_8.c  $(encdir)/iso8859_9.c \
	$(encdir)/iso8859_10.c $(encdir)/iso8859_11.c \
	$(encdir)/iso8859_13.c $(encdir)/iso8859_14.c \
	$(encdir)/iso8859_15.c $(encdir)/iso8859_16.c \
	$(encdir)/euc_tw.c $(encdir)/euc_kr.c $(encdir)/big5.c \
	$(encdir)/gb18030.c $(encdir)/koi8_r.c $(encdir)/cp1251.c

libonig_la_LDFLAGS = -version-info $(LTVERSION)

EXTRA_DIST = .gitignore oniguruma.pc.in HISTORY README.ja index.html \
	index_ja.html doc/API doc/API.ja doc/RE doc/RE.ja doc/FAQ doc/FAQ.ja \
	doc/UnicodeProps.txt \
	tool/.gitignore tool/CaseFolding.py tool/convert-name2ctype.sh \
	tool/enc-unicode.rb \
	win32/Makefile win32/config.h win32/testc.c \
	win32/makedef.py win32/onig.rc \
	$(encdir)/koi8.c $(encdir)/mktable.c \
	$(sampledir)/encode.c $(sampledir)/listcap.c $(sampledir)/names.c \
	$(sampledir)/posix.c $(sampledir)/simple.c $(sampledir)/sql.c \
	$(sampledir)/syntax.c $(sampledir)/crnl.c \
	test.rb testconv.rb testconvu.rb \
	onig.py testpy.py

bin_SCRIPTS = onig-config

onig-config: onig-config.in

do_subst = sed                                          \
      -e 's,[@]datadir[@],$(datadir),g'                 \
      -e 's,[@]datarootdir[@],$(datarootdir),g'         \
      -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
      -e 's,[@]prefix[@],$(prefix),g'                   \
      -e 's,[@]exec_prefix[@],$(exec_prefix),g'         \
      -e 's,[@]libdir[@],$(libdir),g'                   \
      -e 's,[@]includedir[@],$(includedir),g'

oniguruma.pc: $(srcdir)/oniguruma.pc.in Makefile
	$(do_subst) < $(<) > $(@)

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = oniguruma.pc

dll:
	$(CXX) -shared -Wl,--output-def,libonig.def -o libonig.dll *.o \
	$(LIBS)
	strip libonig.dll

# Ruby TEST
rtest:
	$(RUBYDIR)/ruby -w -Ke $(srcdir)/test.rb

# character-types-table source generator
mktable: $(encdir)/mktable.c $(srcdir)/regenc.h
	$(CC) -I$(top_srcdir) -o mktable $(encdir)/mktable.c


# TEST
TESTS = testc testp testcu

check_PROGRAMS = testc testp testcu

atest: testc testp testcu
	@echo "[Oniguruma API, ASCII/EUC-JP check]"
	@$(top_builddir)/testc  | grep RESULT
	@echo "[POSIX API, ASCII/EUC-JP check]"
	@$(top_builddir)/testp  | grep RESULT
	@echo "[Oniguruma API, UTF-16 check]"
	@$(top_builddir)/testcu | grep RESULT

testc_SOURCES = testc.c
testc_LDADD = libonig.la

testp_SOURCES = testc.c
testp_LDADD = libonig.la
testp_CFLAGS = -DPOSIX_TEST

testcu_SOURCES = testu.c
testcu_LDADD = libonig.la


testc.c: $(srcdir)/test.rb $(srcdir)/testconv.rb
	ruby -Ke $(srcdir)/testconv.rb < $(srcdir)/test.rb > $@

testu.c: $(srcdir)/test.rb $(srcdir)/testconvu.rb
	ruby -Ke $(srcdir)/testconvu.rb $(srcdir)/test.rb > $@

win32/testc.c: $(srcdir)/test.rb $(srcdir)/testconv.rb
	ruby -Ke $(srcdir)/testconv.rb -win < $(srcdir)/test.rb | nkf -cs > $@

## END OF FILE
