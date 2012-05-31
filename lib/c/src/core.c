/* core.c
 *
 * Copyright (C) 2012 Stephan Peijnik <stephan@peijnik.at>
 *
 * This file is part of upolicy.
 *
 *  upolicy is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  upolicy is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with upolicy.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <upolicy/core.h>
#include <upolicy/netlink.h>
#include <upolicy/internal.h>

int upolicy_init(void) {
	int rc = 0;
	up_dprintf(CORE, "begin context_init.");
	upolicy_context_init();
	up_dprintf(CORE, "begin netlink_init.");
  rc = upolicy_netlink_init();
  up_dprintf(CORE, "initialized.");
  return rc;
}

void upolicy_cleanup(void) {
	up_dprintf(CORE, "begin context_cleanup.");
	upolicy_context_cleanup();
	up_dprintf(CORE, "begin netlink_cleanup.");
  upolicy_netlink_cleanup();
  up_dprintf(CORE, "cleanup complete.");
}

