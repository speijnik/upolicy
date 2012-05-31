# Makefile.am
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

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = doc kernel lib examples

doc: apidoc kerneldoc

if BUILD_APIDOC
apidoc:
	$(MAKE) -C $(top_srcdir)/doc/apidoc doxygen-doc
kerneldoc:
	$(MAKE) -C $(top_srcdir)/doc/kerneldoc kerneldoc
else
apidoc:
	@echo "API documentation building not enabled."
kerneldoc:
	@echo "Kernel documentation building not enabled."
endif

EXTRA_DIST = \
	kernel/context.c \
	kernel/handler_bprm.c \
	kernel/handler_cred.c \
	kernel/handler_fs.c \
	kernel/handler_ptrace.c \
	kernel/handler_socket.c \
	kernel/handler_task.c \
	kernel/Kbuild \
	kernel/lib.c \
	kernel/lsm.c \
	kernel/netlink.c \
	kernel/tracee.c \
	kernel/tracer.c