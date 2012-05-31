/* handler_fs.c
 *
 * Copyright (C) 2012 Stephan Peijnik <stephan@peijnik.at>
 *
 * This file is part of upolicy.
 *
 *
 *  upolicy is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  upolicy is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with upolicy; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
 *  MA  02110-1301, USA.
 */

#include <linux/sched.h>
#include <kupolicy/handler.h>
#include <kupolicy/tracee.h>
#include <kupolicy/upolicy.h>

int up_fs_dentry_open(struct file *file, const struct cred *cred) {
	struct up_tracee *tracee = up_want_handle_event(UPOLICY_EVENT(OPEN));

	if (unlikely(tracee)) {
		/* TODO: fs_dentry_open is not implemented yet. */
		up_dprintk(HANDLER_FS, "dentry_open called by current=%p\n", current);
		up_tracee_put(tracee);
	}
	return 0;
}
