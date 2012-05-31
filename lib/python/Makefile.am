# lib/python/Makefile.am
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

AUTOMAKE_OPTIONS = 1.7

pkgpython_PYTHON = __init__.py
pkgpyexec_LTLIBRARIES = _upolicy.la
_upolicy_la_LDFLAGS = -module -avoid-version
_upolicy_la_CFLAGS = $(UPOLICY_CFLAGS) $(UPOLICY_DEBUG) $(libnl3_CFLAGS) \
	$(libnl3_genl_CFLAGS) $(python_CFLAGS) -I$(abs_top_srcdir)/lib/c/include \
	-Wall -Werror -Wno-strict-aliasing
_upolicy_la_LIBADD = ../c/src/libupolicy.la $(libnl3_LIBS) $(libnl3_genl_LIBS)
_upolicy_la_SOURCES = pyupolicy.c






