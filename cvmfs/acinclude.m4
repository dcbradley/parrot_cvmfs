# ===========================================================================
#           http://www.nongnu.org/autoconf-archive/ax_pthread.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PTHREAD([ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])
#
# DESCRIPTION
#
#   This macro figures out how to build C programs using POSIX threads. It
#   sets the PTHREAD_LIBS output variable to the threads library and linker
#   flags, and the PTHREAD_CFLAGS output variable to any special C compiler
#   flags that are needed. (The user can also force certain compiler
#   flags/libs to be tested by setting these environment variables.)
#
#   Also sets PTHREAD_CC to any special C compiler that is needed for
#   multi-threaded programs (defaults to the value of CC otherwise). (This
#   is necessary on AIX to use the special cc_r compiler alias.)
#
#   NOTE: You are assumed to not only compile your program with these flags,
#   but also link it with them as well. e.g. you should link with
#   $PTHREAD_CC $CFLAGS $PTHREAD_CFLAGS $LDFLAGS ... $PTHREAD_LIBS $LIBS
#
#   If you are only building threads programs, you may wish to use these
#   variables in your default LIBS, CFLAGS, and CC:
#
#     LIBS="$PTHREAD_LIBS $LIBS"
#     CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
#     CC="$PTHREAD_CC"
#
#   In addition, if the PTHREAD_CREATE_JOINABLE thread-attribute constant
#   has a nonstandard name, defines PTHREAD_CREATE_JOINABLE to that name
#   (e.g. PTHREAD_CREATE_UNDETACHED on AIX).
#
#   ACTION-IF-FOUND is a list of shell commands to run if a threads library
#   is found, and ACTION-IF-NOT-FOUND is a list of commands to run it if it
#   is not found. If ACTION-IF-FOUND is not specified, the default action
#   will define HAVE_PTHREAD.
#
#   Please let the authors know if this macro fails on any platform, or if
#   you have any other suggestions or comments. This macro was based on work
#   by SGJ on autoconf scripts for FFTW (http://www.fftw.org/) (with help
#   from M. Frigo), as well as ac_pthread and hb_pthread macros posted by
#   Alejandro Forero Cuervo to the autoconf macro repository. We are also
#   grateful for the helpful feedback of numerous users.
#
# LICENSE
#
#   Copyright (c) 2008 Steven G. Johnson <stevenj@alum.mit.edu>
#
#   This program is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation, either version 3 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <http://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 5

AU_ALIAS([ACX_PTHREAD], [AX_PTHREAD])
AC_DEFUN([AX_PTHREAD], [
AC_REQUIRE([AC_CANONICAL_HOST])
AC_LANG_SAVE
AC_LANG_C
ax_pthread_ok=no

# We used to check for pthread.h first, but this fails if pthread.h
# requires special compiler flags (e.g. on True64 or Sequent).
# It gets checked for in the link test anyway.

# First of all, check if the user has set any of the PTHREAD_LIBS,
# etcetera environment variables, and if threads linking works using
# them:
if test x"$PTHREAD_LIBS$PTHREAD_CFLAGS" != x; then
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        AC_MSG_CHECKING([for pthread_join in LIBS=$PTHREAD_LIBS with CFLAGS=$PTHREAD_CFLAGS])
        AC_TRY_LINK_FUNC(pthread_join, ax_pthread_ok=yes)
        AC_MSG_RESULT($ax_pthread_ok)
        if test x"$ax_pthread_ok" = xno; then
                PTHREAD_LIBS=""
                PTHREAD_CFLAGS=""
        fi
        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"
fi

# We must check for the threads library under a number of different
# names; the ordering is very important because some systems
# (e.g. DEC) have both -lpthread and -lpthreads, where one of the
# libraries is broken (non-POSIX).

# Create a list of thread flags to try.  Items starting with a "-" are
# C compiler flags, and other items are library names, except for "none"
# which indicates that we try without any flags at all, and "pthread-config"
# which is a program returning the flags for the Pth emulation library.

ax_pthread_flags="pthreads none -Kthread -kthread lthread -pthread -pthreads -mthreads pthread --thread-safe -mt pthread-config"

# The ordering *is* (sometimes) important.  Some notes on the
# individual items follow:

# pthreads: AIX (must check this before -lpthread)
# none: in case threads are in libc; should be tried before -Kthread and
#       other compiler flags to prevent continual compiler warnings
# -Kthread: Sequent (threads in libc, but -Kthread needed for pthread.h)
# -kthread: FreeBSD kernel threads (preferred to -pthread since SMP-able)
# lthread: LinuxThreads port on FreeBSD (also preferred to -pthread)
# -pthread: Linux/gcc (kernel threads), BSD/gcc (userland threads)
# -pthreads: Solaris/gcc
# -mthreads: Mingw32/gcc, Lynx/gcc
# -mt: Sun Workshop C (may only link SunOS threads [-lthread], but it
#      doesn't hurt to check since this sometimes defines pthreads too;
#      also defines -D_REENTRANT)
#      ... -mt is also the pthreads flag for HP/aCC
# pthread: Linux, etcetera
# --thread-safe: KAI C++
# pthread-config: use pthread-config program (for GNU Pth library)

case "${host_cpu}-${host_os}" in
        *solaris*)

        # On Solaris (at least, for some versions), libc contains stubbed
        # (non-functional) versions of the pthreads routines, so link-based
        # tests will erroneously succeed.  (We need to link with -pthreads/-mt/
        # -lpthread.)  (The stubs are missing pthread_cleanup_push, or rather
        # a function called by this macro, so we could check for that, but
        # who knows whether they'll stub that too in a future libc.)  So,
        # we'll just look for -pthreads and -lpthread first:

        ax_pthread_flags="-pthreads pthread -mt -pthread $ax_pthread_flags"
        ;;
esac

if test x"$ax_pthread_ok" = xno; then
for flag in $ax_pthread_flags; do

        case $flag in
                none)
                AC_MSG_CHECKING([whether pthreads work without any flags])
                ;;

                -*)
                AC_MSG_CHECKING([whether pthreads work with $flag])
                PTHREAD_CFLAGS="$flag"
                ;;

		pthread-config)
		AC_CHECK_PROG(ax_pthread_config, pthread-config, yes, no)
		if test x"$ax_pthread_config" = xno; then continue; fi
		PTHREAD_CFLAGS="`pthread-config --cflags`"
		PTHREAD_LIBS="`pthread-config --ldflags` `pthread-config --libs`"
		;;

                *)
                AC_MSG_CHECKING([for the pthreads library -l$flag])
                PTHREAD_LIBS="-l$flag"
                ;;
        esac

        save_LIBS="$LIBS"
        save_CFLAGS="$CFLAGS"
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Check for various functions.  We must include pthread.h,
        # since some functions may be macros.  (On the Sequent, we
        # need a special flag -Kthread to make this header compile.)
        # We check for pthread_join because it is in -lpthread on IRIX
        # while pthread_create is in libc.  We check for pthread_attr_init
        # due to DEC craziness with -lpthreads.  We check for
        # pthread_cleanup_push because it is one of the few pthread
        # functions on Solaris that doesn't have a non-functional libc stub.
        # We try pthread_create on general principles.
        AC_TRY_LINK([#include <pthread.h>
	             static void routine(void* a) {a=0;}
	             static void* start_routine(void* a) {return a;}],
                    [pthread_t th; pthread_attr_t attr;
                     pthread_create(&th,0,start_routine,0);
                     pthread_join(th, 0);
                     pthread_attr_init(&attr);
                     pthread_cleanup_push(routine, 0);
                     pthread_cleanup_pop(0); ],
                    [ax_pthread_ok=yes])

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        AC_MSG_RESULT($ax_pthread_ok)
        if test "x$ax_pthread_ok" = xyes; then
                break;
        fi

        PTHREAD_LIBS=""
        PTHREAD_CFLAGS=""
done
fi

# Various other checks:
if test "x$ax_pthread_ok" = xyes; then
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Detect AIX lossage: JOINABLE attribute is called UNDETACHED.
	AC_MSG_CHECKING([for joinable pthread attribute])
	attr_name=unknown
	for attr in PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_UNDETACHED; do
	    AC_TRY_LINK([#include <pthread.h>], [int attr=$attr; return attr;],
                        [attr_name=$attr; break])
	done
        AC_MSG_RESULT($attr_name)
        if test "$attr_name" != PTHREAD_CREATE_JOINABLE; then
            AC_DEFINE_UNQUOTED(PTHREAD_CREATE_JOINABLE, $attr_name,
                               [Define to necessary symbol if this constant
                                uses a non-standard name on your system.])
        fi

        AC_MSG_CHECKING([if more special flags are required for pthreads])
        flag=no
        case "${host_cpu}-${host_os}" in
            *-aix* | *-freebsd* | *-darwin*) flag="-D_THREAD_SAFE";;
            *solaris* | *-osf* | *-hpux*) flag="-D_REENTRANT";;
        esac
        AC_MSG_RESULT(${flag})
        if test "x$flag" != xno; then
            PTHREAD_CFLAGS="$flag $PTHREAD_CFLAGS"
        fi

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        # More AIX lossage: must compile with xlc_r or cc_r
	if test x"$GCC" != xyes; then
          AC_CHECK_PROGS(PTHREAD_CC, xlc_r cc_r, ${CC})
        else
          PTHREAD_CC=$CC
	fi
else
        PTHREAD_CC="$CC"
fi

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_CC)

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test x"$ax_pthread_ok" = xyes; then
        ifelse([$1],,AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.]),[$1])
        :
else
        ax_pthread_ok=no
        $2
fi
AC_LANG_RESTORE
])dnl AX_PTHREAD


# openmp.m4 serial 3 (gettext-0.16)
dnl Copyright (C) 2006 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl Determine the compiler flags needed to support OpenMP.
dnl Define OPENMP_CFLAGS.

dnl From Bruno Haible.

AC_DEFUN([gt_OPENMP],
[
  AC_MSG_CHECKING([whether to use OpenMP])
  AC_ARG_ENABLE(openmp,
    [  --disable-openmp        do not use OpenMP],
    [OPENMP_CHOICE="$enableval"],
    [OPENMP_CHOICE=yes])
  AC_MSG_RESULT([$OPENMP_CHOICE])
  OPENMP_CFLAGS=
  if test "$OPENMP_CHOICE" = yes; then
    AC_MSG_CHECKING([for $CC option to support OpenMP])
    AC_CACHE_VAL([gt_cv_prog_cc_openmp], [
      gt_cv_prog_cc_openmp=no
      AC_COMPILE_IFELSE([
#ifndef _OPENMP
 Unlucky
#endif
        ], [gt_cv_prog_cc_openmp=none])
      if test "$gt_cv_prog_cc_openmp" = no; then
        dnl Try these flags:
        dnl   GCC >= 4.2           -fopenmp
        dnl   SunPRO C             -xopenmp
        dnl   Intel C              -openmp
        dnl   SGI C, PGI C         -mp
        dnl   Tru64 Compaq C       -omp
        dnl   AIX IBM C            -qsmp=omp
        if test "$GCC" = yes; then
          dnl --- Test for GCC.
          gt_save_CFLAGS="$CFLAGS"
          CFLAGS="$CFLAGS -fopenmp"
          AC_COMPILE_IFELSE([
#ifndef _OPENMP
 Unlucky
#endif
            ], [gt_cv_prog_cc_openmp="-fopenmp"])
          CFLAGS="$gt_save_CFLAGS"
        else
          dnl --- Test for SunPRO C.
          AC_EGREP_CPP([Brand], [
#if defined __SUNPRO_C || defined __SUNPRO_CC
 Brand
#endif
            ], result=yes, result=no)
          if test $result = yes; then
            gt_save_CFLAGS="$CFLAGS"
            CFLAGS="$CFLAGS -xopenmp"
            AC_COMPILE_IFELSE([
#ifndef _OPENMP
 Unlucky
#endif
              ], [gt_cv_prog_cc_openmp="-xopenmp"])
            CFLAGS="$gt_save_CFLAGS"
          else
            dnl --- Test for Intel C.
            AC_EGREP_CPP([Brand], [
#if defined __INTEL_COMPILER
 Brand
#endif
              ], result=yes, result=no)
            if test $result = yes; then
              gt_save_CFLAGS="$CFLAGS"
              CFLAGS="$CFLAGS -openmp"
              AC_COMPILE_IFELSE([
#ifndef _OPENMP
 Unlucky
#endif
                ], [gt_cv_prog_cc_openmp="-openmp"])
              CFLAGS="$gt_save_CFLAGS"
            else
              dnl --- Test for SGI C, PGI C.
              AC_EGREP_CPP([Brand], [
#if defined __sgi || defined __PGI || defined __PGIC__
 Brand
#endif
                ], result=yes, result=no)
              if test $result = yes; then
                gt_save_CFLAGS="$CFLAGS"
                CFLAGS="$CFLAGS -mp"
                AC_COMPILE_IFELSE([
#ifndef _OPENMP
 Unlucky
#endif
                  ], [gt_cv_prog_cc_openmp="-mp"])
                CFLAGS="$gt_save_CFLAGS"
              else
                dnl --- Test for Compaq C.
                AC_EGREP_CPP([Brand], [
#if defined __DECC || defined __DECCXX
 Brand
#endif
                  ], result=yes, result=no)
                if test $result = yes; then
                  gt_save_CFLAGS="$CFLAGS"
                  CFLAGS="$CFLAGS -omp"
                  AC_COMPILE_IFELSE([
#ifndef _OPENMP
 Unlucky
#endif
                    ], [gt_cv_prog_cc_openmp="-omp"])
                  CFLAGS="$gt_save_CFLAGS"
                else
                  dnl --- Test for AIX IBM C.
                  AC_EGREP_CPP([Brand], [
#if defined _AIX
 Brand
#endif
                    ], result=yes, result=no)
                  if test $result = yes; then
                    gt_save_CFLAGS="$CFLAGS"
                    CFLAGS="$CFLAGS -qsmp=omp"
                    AC_COMPILE_IFELSE([
#ifndef _OPENMP
 Unlucky
#endif
                      ], [gt_cv_prog_cc_openmp="-qsmp=omp"])
                    CFLAGS="$gt_save_CFLAGS"
                  else
                    :
                  fi
                fi
              fi
            fi
          fi
        fi
      fi
      ])
    case $gt_cv_prog_cc_openmp in
      none)
        AC_MSG_RESULT([none needed]) ;;
      no)
        AC_MSG_RESULT([unsupported]) ;;
      *)
        AC_MSG_RESULT([$gt_cv_prog_cc_openmp]) ;;
    esac
    case $gt_cv_prog_cc_openmp in
      none | no)
        OPENMP_CFLAGS= ;;
      *)
        OPENMP_CFLAGS=$gt_cv_prog_cc_openmp ;;
    esac
  fi
  AC_SUBST([OPENMP_CFLAGS])
])
