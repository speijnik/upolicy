# lib/c/src/Makefile.am
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

if BUILD_LIB
lib_LTLIBRARIES = libupolicy.la
endif

libupolicy_la_SOURCES = \
	context.c \
	core.c \
	lib.c \
	netlink.c 
libupolicy_la_CFLAGS = -Wall -Werror $(UPOLICY_CFLAGS) $(UPOLICY_DEBUG)  -I$(srcdir)/../include \
	$(PTHREAD_CFLAGS) $(libnl3_CFLAGS) $(libnl3_genl_CFLAGS)
libupolicy_la_LIBS = $(PTHREAD_LIBS) $(libnl3_LIBS) $(libnl3_genl_LIBS)
