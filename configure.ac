# configure.ac
#
# Copyright (C) 2012 Stephan Peijnik <stephan@peijnik.at>
#
# This file is part of upolicy.
#
#  upolicy is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  upolicy is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with upolicy.  If not, see <http://www.gnu.org/licenses/>.
AC_INIT(upolicy, 0.1.0, stephan@peijnik.at)

dnl Define netlink version numbers
UPOLICY_NL_VERMAJOR=0
UPOLICY_NL_VERMINOR=0
AC_SUBST(UPOLICY_NL_VERMAJOR)
AC_SUBST(UPOLICY_NL_VERMINOR)

dnl Define library/module version numbers
UPOLICY_VERSION_MAJOR=0
UPOLICY_VERSION_MINOR=1
UPOLICY_VERSION_PATCH=0
AC_SUBST(UPOLICY_VERSION_MAJOR)
AC_SUBST(UPOLICY_VERSION_PATCH)
AC_SUBST(UPOLICY_VERSION_MINOR)

dnl Early calls
AC_CANONICAL_TARGET
AC_USE_SYSTEM_EXTENSIONS

m4_include([m4/upolicy_local.m4])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([lib/c/src/context.c])
AC_CONFIG_HEADER(config.h)

AS_IF([test "$target_os" != "linux-gnu"],
  AC_MSG_ERROR([Unsupported target OS: $target_os]))

dnl Language
AC_LANG_C

dnl Programs
AC_PROG_CC
AC_PROG_LIBTOOL

dnl Build feature selection
AC_ARG_ENABLE([kernel-module],
  AS_HELP_STRING([--disable-kernel-module],
    [disable building of the upolicy kernel module]),
  [case "${enableval}" in
    no) enable_kernel_module=no ;;
    yes) enable_kernel_module=yes ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --disable-kernel-module) ;;
   esac],
   enable_kernel_module=yes)

AC_ARG_ENABLE([library],
  AS_HELP_STRING([--disable-library],
    [disable building of the upolicy library]),
  [case "${enableval}" in
    no) enable_lib=no ;;
    yes) enable_lib=yes ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --disable-library) ;;
   esac],
   enable_lib=yes)

AC_ARG_ENABLE([debug],
  AS_HELP_STRING([--enable-debug],
    [enable debug build]),
  [case "${enableval}" in
    yes) enable_debug=yes ;;
    no)  enable_debug=no  ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
   esac],
   enable_debug=no)

AC_ARG_ENABLE([examples],
  AS_HELP_STRING([--enable-examples],
    [enable building examples]),
   [case "${enableval}" in
    yes) enable_examples=yes ;;
    no)  enable_examples=no  ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-examples) ;;
   esac],
   enable_examples=no)

AS_IF([test "x$enable_debug" == xyes],
  UPOLICY_DEBUG="-DUPOLICY_DEBUG=1",
  UPOLICY_DEBUG="-DUPOLICY_DEBUG=0")
AC_SUBST(UPOLICY_DEBUG)

AC_ARG_ENABLE([apidoc],
  AS_HELP_STRING([--disable-apidoc],
    [disable building the API documentation]),
  [case "${enableval}" in
    yes) enable_apidoc=yes ;;
    no) enable_apidoc=no ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --disable-apidoc) ;;
  esac],
  enable_apidoc=yes)

AC_ARG_ENABLE([python],
  AS_HELP_STRING([--disable-python],
    [disable building the Python bindings]),
  [case "${enableval}" in
    yes) enable_python=yes ;;
    no) enable_python=no ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --disable-python) ;;
   esac],
   enable_python=yes)

dnl Check that at building of at least one of kernel-module and library
dnl is enabled.
AS_IF([test "x$enable_lib" == xno -a "x$enable_kernel_module" == xno],
  AC_MSG_ERROR([Nothing to build selected. Please use only one of --disable-kernel-module or --disable-library]))

KDIR_DEFAULT=/lib/modules/`uname -r`/build

dnl kernel module conditional part
AS_IF([test "x$enable_kernel_module" == xyes], [
  AC_MSG_CHECKING(kernel build dir)
  AC_ARG_WITH([kernel-build-dir],
    [AS_HELP_STRING([--with-kernel-build-dir],
      [location of the kernel build dir, defaults to $KDIR])],
      [case $KDIR in
       /*) KDIR="$withval" ;;
        *) KDIR=$(pwd)/$withval ;;
       esac],
      [KDIR=$KDIR_DEFAULT])

  AS_IF([test -f $KDIR/Kbuild -a -f $KDIR/Kconfig],
    [],
    [AC_MSG_RESULT(error)
    AC_MSG_ERROR([Invalid kernel build dir $KDIR])])
  AC_MSG_RESULT([$KDIR])
  AC_SUBST(KDIR)

  dnl Kernel lsmstub support
  CPPFLAGS_OLD=$CPPFLAGS
  CPPFLAGS=-I$KDIR/include
  AC_CHECK_HEADER(linux/lsmstub.h,
    lsmstub=yes,
    lsmstub=no)
  CPPFLAGS=$CPPFLAGS_OLD

  AS_IF([test "x$lsmstub" == xno],
    AC_MSG_ERROR([linux/lsmstub.h not found]))

  dnl Configure include path for library
  UPOLICY_CFLAGS="-I\$(abs_top_srcdir)/kernel/include"
], [
  AC_MSG_WARN([Missing checks for kernel module headers...])
])

AC_SUBST(UPOLICY_CFLAGS)

dnl library conditional part
AS_IF([test "x$enable_lib" == xyes], [
  PKG_CHECK_MODULES([libnl3], [libnl-3.0 >= 3.0])
  PKG_CHECK_MODULES([libnl3_genl], [libnl-genl-3.0 >= 3.0], 
    have_libnl3_genl=yes, have_libnl3_genl=no)
  AS_IF([test "x$have_libnl3_genl" == xno], [
    dnl This could mean that we are either missing the library altogether
    dnl or that it is "included" in libnl3.
    dnl TODO: Add this check!
  ])

  AX_PTHREAD()
])

dnl Doxygen
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)

DX_INIT_DOXYGEN([$PACKAGE_NAME], [Doxyfile], [apidoc])

dnl Header files
AC_HEADER_STDC
AC_HEADER_ASSERT
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_CHECK_HEADERS([sys/time.h sys/un.h sys/epoll.h arpa/inet.h])
AC_CHECK_SIZEOF([sem_t], ,[#include <semaphore.h>])
AC_CHECK_SIZEOF([unsigned long])
AC_CHECK_LIB(rt, clock_gettime, [
  LIBS="-lrt $LIBS"
])

dnl Types
AC_TYPE_PID_T
AC_TYPE_SIZE_T

dnl Functions
AC_FUNC_MALLOC
AC_FUNC_MMAP

dnl custom tests
UPOLICY_PAGESIZE

dnl Python bindings - conditional part
AS_IF([test "x$enable_python" == xyes], [
	    AM_PATH_PYTHON(2.6)
	    PKG_CHECK_MODULES([python], [python >= 2.7])
])

dnl Conditionals
AM_CONDITIONAL(BUILD_KERNEL, test x$enable_kernel_module = xyes)
AM_CONDITIONAL(BUILD_LIB, test x$enable_lib = xyes)
AM_CONDITIONAL(BUILD_EXAMPLES, test x$enable_examples = xyes -a x$enable_lib = xyes)
AM_CONDITIONAL(BUILD_APIDOC, test x$enable_apidoc = xyes)
AM_CONDITIONAL(BUILD_PYTHON, test x$enable_lib = xyes -a x$enable_python = xyes)

AC_OUTPUT([
	Makefile
	doc/Makefile
	doc/apidoc/Doxyfile
	doc/apidoc/Makefile
	doc/kerneldoc/Makefile
	kernel/Makefile
	kernel/include/Makefile
	kernel/include/kupolicy/netlink_version.h
	examples/Makefile
	examples/c/Makefile
	lib/Makefile
	lib/c/Makefile
	lib/c/include/Makefile
	lib/c/include/upolicy/version.h
	lib/c/src/Makefile
	lib/python/Makefile
])

dnl Print configuration
AC_MSG_NOTICE([])
AC_MSG_NOTICE([+ upolicy general])
AC_MSG_NOTICE([  - version         : $UPOLICY_VERSION_MAJOR.$UPOLICY_VERSION_MINOR]) 
AC_MSG_NOTICE([  - netlink version : $UPOLICY_NL_VERMAJOR.$UPOLICY_NL_VERMINOR])
AC_MSG_NOTICE([  - debug build     : $enable_debug])
AC_MSG_NOTICE([+ upolicy kernel module])
AC_MSG_NOTICE([  - build           : $enable_kernel_module])
dnl begin kernel conditional part
AS_IF([test "x$enable_kernel_module" == xyes],
  [
AC_MSG_NOTICE([  - kernel bulddir  : $KDIR])
  ])
dnl end kernel conditional part
AC_MSG_NOTICE([+ upolicy userspace library])
AC_MSG_NOTICE([  - build           : $enable_lib])
AC_MSG_NOTICE([+ upolicy Python bindings])
AC_MSG_NOTICE([  - build           : $enable_python])
AC_MSG_NOTICE([+ upolicy examples])
AC_MSG_NOTICE([  - build           : $enable_examples])
AC_MSG_NOTICE([+ upolicy API documentation])
AC_MSG_NOTICE([  - build           : $enable_apidoc])