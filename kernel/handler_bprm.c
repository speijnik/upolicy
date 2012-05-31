/* handler_bprm.c
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

#include <linux/binfmts.h>
#include <linux/cred.h>

#include <kupolicy/handler.h>
#include <kupolicy/netlink.h>
#include <kupolicy/tracee.h>
#include <kupolicy/upolicy.h>

int up_bprm_set_creds(struct linux_binprm *bprm) {
	int rc = 0;
	const struct cred *cred = current_cred();
	struct upolicy *upol = current_upolicy();
	struct sk_buff *skb = NULL;
	struct up_tracee *tracee = NULL;

	/*
	 * NOTE: This callback is invoked upon exec, so we need to do some sanity checks here
	 * and then give the tracer a chance to allow or deny the call.
	 */

	/* Do not operate on non-traced processes. */
	if (likely(!upol))
		return 0;

	up_dprintk(HANDLER_BPRM, "Running security checks for current=%p,upol=%p\n", current, upol);

	/*
	 * SANITY CHECK:
	 *
	 * If the calling process is has neither UID set to 0
	 * do not allow executing a suid binary.
	 *
	 * This is required so tracers which are not running as root do
	 * are unable to control what a process running as root can do.
	 *
	 * Allowing to let the process run as root in untraced mode is not an option
	 * as this could be used to escape the sandbox.
	 */
	if (cred->euid != 0 && cred->uid != 0) {
		/* Not running with uid=0, check bprm credentials */
		if (bprm->cred->euid != cred->euid || bprm->cred->uid != cred->uid) {
			/* EUID/UID mismatch. Deny call. */
			return -EPERM;
		}
	}

	/*
	 * SANITY CHECK:
	 *
	 * Same as above, but for GID.
	 */
	if (cred->egid != 0 && cred->gid != 0) {
		/* Not running with gid=0, check bprm credentials */
		if (bprm->cred->egid != cred->egid || bprm->cred->gid != cred->gid) {
			/* EGID/GID mismatch. Deny call. */
			return -EPERM;
		}
	}

	/*
	 * After carrying out all sanity checks we can give the tracer a chance to
	 * check if it wants to allow this exec call.
	 */
	if (unlikely((tracee = up_want_handle_event(UPOLICY_EVENT(EXEC))))) {
		struct up_nlhdr *up_nlhdr = NULL;
		enum UP_EV_DECISION decision = UP_DECISION(KILL);
		skb = __up_nlevent_prepare(UP_NLMSG_PATHSIZE, UPOLICY_EVENT(EXEC), &up_nlhdr,
				UPOLICY_COMMAND(QUESTION), 0);

		if (likely(skb)) {
			NLA_PUT_STRING(skb, UP_NLA_PATH, bprm->filename);
			decision = up_nlevent_send(skb, tracee, UPOLICY_EVENT(EXEC), NULL);
			if (decision != UP_DECISION(ALLOW)) {
				up_dprintk(HANDLER_BPRM,
						"tracee@%p,tsk@%p: exec(%s) denied (decision=%d).\n",
						tracee, current, bprm->filename, decision);
				rc = -EPERM;
			}
		} else {
			rc = -EPERM;
		}
		up_tracee_put(tracee);
	}

	return rc;
nla_put_failure:
	up_eprintk("nla_put_failure.\n");
	kfree_skb(skb);
	up_tracee_put(tracee);
	return -ENOMEM;
}


