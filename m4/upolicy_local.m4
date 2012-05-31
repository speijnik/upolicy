# upolicy_local.m4 - upolicy local autoconf tests              -*- Autoconf -*-
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

m4_include([m4/ax_pthread.m4])
m4_include([m4/dx_doxygen.m4])

AC_DEFUN([UPOLICY_PAGESIZE],
[
  AC_MSG_CHECKING([for page size])
  SIZEOF_PAGE=`getconf PAGESIZE 2>/dev/null`
  AC_MSG_RESULT([$SIZEOF_PAGE bytes])
  AH_TEMPLATE([SIZEOF_PAGE], [Size of a single page])
  AC_DEFINE_UNQUOTED(SIZEOF_PAGE, [$SIZEOF_PAGE], [Define page size])
])