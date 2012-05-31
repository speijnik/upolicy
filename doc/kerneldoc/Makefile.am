# doc/kerneldoc/Makefile.am
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

EXTRA_DIST = kernel-doc
DOC_OUTPUT = kerneldoc.html

KERNEL_SRCES = `ls @top_srcdir@/kernel/*.c`
KERNEL_INCS = `ls @top_srcdir@/kernel/include/kupolicy/*.h`

doc: kerneldoc

kerneldoc:
	$(top_srcdir)/doc/kerneldoc/kernel-doc -html $(KERNEL_SRCES) \
		$(KERNEL_INCS) > $(DOC_OUTPUT)

clean-local:
	rm -f kerneldoc.html