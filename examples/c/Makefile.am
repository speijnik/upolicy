# examples/c/Makefile.am
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

if BUILD_EXAMPLES
noinst_PROGRAMS = \
	example_init \
	example_nosocket \
	example_socket_nolisten \
	example_localhost_only \
	example_nokill \
	example_exec
endif

EXAMPLE_LIBS = $(abs_top_srcdir)/lib/c/src/libupolicy.la \
	$(libnl3_LIBS) $(libnl3_genl_LIBS)
EXAMPLE_CFLAGS = $(UPOLICY_DEBUG) $(UPOLICY_CFLAGS) $(libnl3_CFLAGS) $(libnl3_genl_CFLAGS) \
	-I$(abs_top_srcdir)/lib/c/include -Wall -Werror

example_init_SOURCES = example_init.c
example_init_LDADD = $(EXAMPLE_LIBS)
example_init_CFLAGS = $(EXAMPLE_CFLAGS)

example_nosocket_SOURCES = example_nosocket.c
example_nosocket_LDADD = $(EXAMPLE_LIBS)
example_nosocket_CFLAGS = $(EXAMPLE_CFLAGS)

example_socket_nolisten_SOURCES = example_socket_nolisten.c
example_socket_nolisten_LDADD = $(EXAMPLE_LIBS)
example_socket_nolisten_CFLAGS = $(EXAMPLE_CFLAGS)

example_localhost_only_SOURCES = example_localhost_only.c
example_localhost_only_LDADD = $(EXAMPLE_LIBS)
example_localhost_only_CFLAGS = $(EXAMPLE_CFLAGS)

example_nokill_SOURCES = example_nokill.c
example_nokill_LDADD = $(EXAMPLE_LIBS)
example_nokill_CFLAGS = $(EXAMPLE_CFLAGS)

example_exec_SOURCES = example_exec.c
example_exec_LDADD = $(EXAMPLE_LIBS)
example_exec_CFLAGS = $(EXAMPLE_CFLAGS)
