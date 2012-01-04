# Clear out all vpaths, then set just one (default vpath) for the main build
# directory.
vpath
vpath % .

# Clear the default suffixes, so that built-in rules are not used.
.SUFFIXES :

SHELL := /bin/sh

CC := gcc

# Configuration parameters.
DESTDIR =
BINDIR := $(DESTDIR)/usr/local/bin
INCLUDEDIR := $(DESTDIR)/usr/local/include
LIBDIR := $(DESTDIR)/usr/local/lib
DATADIR := $(DESTDIR)/usr/local/share
MANDIR := $(DESTDIR)/usr/local/share/man

# Build parameters.
CPPFLAGS :=  -D_GNU_SOURCE -D_REENTRANT -Iinclude -Iinclude
CFLAGS := -std=gnu99 -Wall -pipe -g3 -fvisibility=hidden -O3 -funroll-loops
ifeq (macho, elf)
CFLAGS += -dynamic
endif
LDFLAGS := 
LIBS :=  -lpthread -ldl
RPATH_EXTRA := 
ifeq (macho, elf)
SO := dylib
WL_SONAME := dylib_install_name
else
SO := so
WL_SONAME := soname
endif
REV := 1
ifeq (macho, elf)
TEST_LIBRARY_PATH := DYLD_FALLBACK_LIBRARY_PATH=lib
else
TEST_LIBRARY_PATH :=
endif

# Lists of files.
BINS := bin/pprof
CHDRS := include/jemalloc/jemalloc.h \
	include/jemalloc/jemalloc_defs.h
CSRCS := src/jemalloc.c src/arena.c src/atomic.c \
	src/base.c src/bitmap.c src/chunk.c \
	src/chunk_dss.c src/chunk_mmap.c \
	src/chunk_swap.c src/ckh.c src/ctl.c \
	src/extent.c src/hash.c src/huge.c \
	src/mb.c src/mutex.c src/prof.c \
	src/rtree.c src/stats.c src/tcache.c
ifeq (macho, elf)
CSRCS += src/zone.c
endif
STATIC_LIBS :=	lib/libjemalloc.a
DSOS := lib/libjemalloc.$(SO).$(REV) \
	lib/libjemalloc.$(SO) \
	lib/libjemalloc_pic.a
MAN3 := doc/jemalloc.3
DOCS_XML := doc/jemalloc.xml
DOCS_HTML := $(DOCS_XML:%.xml=%.html)
DOCS_MAN3 := $(DOCS_XML:%.xml=%.3)
DOCS := $(DOCS_HTML) $(DOCS_MAN3)
CTESTS := test/allocated.c test/allocm.c \
	test/bitmap.c test/mremap.c \
	test/posix_memalign.c test/rallocm.c \
	test/thread_arena.c

.PHONY: all dist doc_html doc_man doc
.PHONY: install_bin install_include install_lib
.PHONY: install_html install_man install_doc install
.PHONY: tests check clean distclean relclean

.SECONDARY : $(CTESTS:%.c=%.o)

# Default target.
all: $(DSOS) $(STATIC_LIBS)

dist: doc

doc/%.html : doc/%.xml doc/stylesheet.xsl doc/html.xsl
	 -o $@ doc/html.xsl $<

doc/%.3 : doc/%.xml doc/stylesheet.xsl doc/manpages.xsl
	 -o $@ doc/manpages.xsl $<

doc_html: $(DOCS_HTML)
doc_man: $(DOCS_MAN3)
doc: $(DOCS)

#
# Include generated dependency files.
#
-include $(CSRCS:%.c=%.d)
-include $(CSRCS:%.c=%.pic.d)
-include $(CTESTS:%.c=%.d)

src/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $(CPPFLAGS) -o $@ $<
	@$(SHELL) -ec "$(CC) -MM $(CPPFLAGS) $< | sed \"s/\($(subst /,\/,$(notdir $(basename $@)))\)\.o\([ :]*\)/$(subst /,\/,$(strip $(dir $@)))\1.o \2/g\" > $(@:%.o=%.d)"

src/%.pic.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -fPIC -DPIC -c $(CPPFLAGS) -o $@ $<
	@$(SHELL) -ec "$(CC) -MM $(CPPFLAGS) $< | sed \"s/\($(subst /,\/,$(notdir $(basename $(basename $@))))\)\.o\([ :]*\)/$(subst /,\/,$(strip $(dir $@)))\1.pic.o \2/g\" > $(@:%.o=%.d)"

%.$(SO) : %.$(SO).$(REV)
	@mkdir -p $(@D)
	ln -sf $(<F) $@

lib/libjemalloc.$(SO).$(REV) : $(CSRCS:%.c=%.pic.o)
	@mkdir -p $(@D)
	$(CC) -shared -Wl,-$(WL_SONAME),$(@F) $(RPATH_EXTRA:%=-Wl,-rpath,%) -o $@ $+ $(LDFLAGS) $(LIBS)

lib/libjemalloc_pic.a : $(CSRCS:%.c=%.pic.o)
	@mkdir -p $(@D)
	ar crus $@ $+

lib/libjemalloc.a : $(CSRCS:%.c=%.o)
	@mkdir -p $(@D)
	ar crus $@ $+

test/%.o: test/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $(CPPFLAGS) -Itest -o $@ $<
	@$(SHELL) -ec "$(CC) -MM $(CPPFLAGS) -Itest $< | sed \"s/\($(subst /,\/,$(notdir $(basename $@)))\)\.o\([ :]*\)/$(subst /,\/,$(strip $(dir $@)))\1.o \2/g\" > $(@:%.o=%.d)"

# Automatic dependency generation misses #include "*.c".
test/bitmap.o : src/bitmap.o

test/%: test/%.o \
		 lib/libjemalloc.$(SO)
	@mkdir -p $(@D)
ifneq (-Wl,-rpath,, )
	$(CC) -o $@ $< -Wl,-rpath,lib -Llib -ljemalloc
else
	$(CC) -o $@ $< -Llib -ljemalloc
endif

install_bin:
	install -d $(BINDIR)
	@for b in $(BINS); do \
	echo "install -m 755 $$b $(BINDIR)"; \
	install -m 755 $$b $(BINDIR); \
done

install_include:
	install -d $(INCLUDEDIR)/jemalloc
	@for h in $(CHDRS); do \
	echo "install -m 644 $$h $(INCLUDEDIR)/jemalloc"; \
	install -m 644 $$h $(INCLUDEDIR)/jemalloc; \
done

install_lib: $(DSOS) $(STATIC_LIBS)
	install -d $(LIBDIR)
	install -m 755 lib/libjemalloc.$(SO).$(REV) $(LIBDIR)
	ln -sf libjemalloc.$(SO).$(REV) $(LIBDIR)/libjemalloc.$(SO)
	install -m 755 lib/libjemalloc_pic.a $(LIBDIR)
	install -m 755 lib/libjemalloc.a $(LIBDIR)

install_html:
	install -d $(DATADIR)/doc/jemalloc
	@for d in $(DOCS_HTML); do \
	echo "install -m 644 $$d $(DATADIR)/doc/jemalloc"; \
	install -m 644 $$d $(DATADIR)/doc/jemalloc; \
done

install_man:
	install -d $(MANDIR)/man3
	@for d in $(DOCS_MAN3); do \
	echo "install -m 644 $$d $(MANDIR)/man3"; \
	install -m 644 $$d $(MANDIR)/man3; \
done

install_doc: install_html install_man

install: install_bin install_include install_lib install_doc

tests: $(CTESTS:%.c=%)

check: tests
	@mkdir -p test
	@$(SHELL) -c 'total=0; \
		failures=0; \
		echo "========================================="; \
		for t in $(CTESTS:%.c=%); do \
			total=`expr $$total + 1`; \
			/bin/echo -n "$${t} ... "; \
			$(TEST_LIBRARY_PATH) $${t} /tmp/dist/jemalloc/src/ /tmp/dist/jemalloc/src/ \
			  > $${t}.out 2>&1; \
			if test -e "$${t}.exp"; then \
				diff -u $${t}.exp \
				  $${t}.out >/dev/null 2>&1; \
				fail=$$?; \
				if test "$${fail}" -eq "1" ; then \
					failures=`expr $${failures} + 1`; \
					echo "*** FAIL ***"; \
				else \
					echo "pass"; \
				fi; \
			else \
				echo "*** FAIL *** (.exp file is missing)"; \
				failures=`expr $${failures} + 1`; \
			fi; \
		done; \
		echo "========================================="; \
		echo "Failures: $${failures}/$${total}"'

clean:
	rm -f $(CSRCS:%.c=%.o)
	rm -f $(CSRCS:%.c=%.pic.o)
	rm -f $(CSRCS:%.c=%.d)
	rm -f $(CSRCS:%.c=%.pic.d)
	rm -f $(CTESTS:%.c=%)
	rm -f $(CTESTS:%.c=%.o)
	rm -f $(CTESTS:%.c=%.d)
	rm -f $(CTESTS:%.c=%.out)
	rm -f $(DSOS) $(STATIC_LIBS)

distclean: clean
	rm -rf autom4te.cache
	rm -f config.log
	rm -f config.status
	rm -f config.stamp
	rm -f include/jemalloc/jemalloc_defs.h
	rm -f Makefile doc/html.xsl doc/manpages.xsl doc/jemalloc.xml include/jemalloc/jemalloc.h include/jemalloc/internal/jemalloc_internal.h test/jemalloc_test.h

relclean: distclean
	rm -f configure
	rm -f VERSION
	rm -f $(DOCS_HTML)
	rm -f $(DOCS_MAN3)

#===============================================================================
# Re-configuration rules.

ifeq (0, 1)
configure : configure.ac
	cd ./ && /usr/bin/autoconf

config.status : configure
	./config.status --recheck

config.stamp.in : configure.ac
	echo stamp > config.stamp.in

config.stamp : Makefile.in doc/html.xsl.in doc/manpages.xsl.in doc/jemalloc.xml.in include/jemalloc/jemalloc.h.in include/jemalloc/internal/jemalloc_internal.h.in test/jemalloc_test.h.in include/jemalloc/jemalloc_defs.h.in configure
	./config.status
	@touch $@

# There must be some action in order for make to re-read Makefile when it is
# out of date.
Makefile doc/html.xsl doc/manpages.xsl doc/jemalloc.xml include/jemalloc/jemalloc.h include/jemalloc/internal/jemalloc_internal.h test/jemalloc_test.h include/jemalloc/jemalloc_defs.h : config.stamp
	@true
endif
