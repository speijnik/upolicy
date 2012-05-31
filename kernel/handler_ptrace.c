/* handler_ptrace.c
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

#include <linux/errno.h>
#include <linux/sched.h>

#include <kupolicy/handler.h>
#include <kupolicy/netlink.h>
#include <kupolicy/tracee.h>
#include <kupolicy/upolicy.h>

int up_ptrace_access_check(struct task_struct *tsk, unsigned int mode) {
	/*
	 * Same as with up_task_kill we want to do some basic checks before
	 * asking the tracer anything.
	 */
	struct up_tracee *tracee = NULL;
	struct upolicy *upol = current_upolicy();
	struct upolicy *target_upol = task_upolicy(tsk);
	struct sk_buff *skb = NULL;
	int rc = 0;
	int want_ev = 0;

	if (!upol) {
		return 0;
	}

	tracee = up_want_handle_event(UPOLICY_EVENT(PTRACE_ATTACH));

	if (unlikely(tracee)) {
		want_ev = 1;
	} else {
		tracee = up_tracee_get(upol->tracee);
	}

	if (unlikely(tracee)) {
		/* Begin sanity checks */

		/*
		 * PTRACE_ATTACH from within context to outside world: DENY
		 */
		if (!target_upol) {
			up_dprintk(HANDLER_PTRACE, "PTRACE_ATTACH from %p to %p: denied, target not traced.\n",
					current, tsk);
			rc = -EPERM;
			goto out_put_tracee;
		}

		/*
		 * PTRACE_ATTACH from one context to another: DENY
		 */
		if (!up_same_context(upol, target_upol)) {
			up_dprintk(HANDLER_PTRACE, "PTRACE_ATTACH from %p to %p: denied, context mismatch.\n",
								current, tsk);
			rc = -EPERM;
			goto out_put_tracee;
		}

		/* End of sanity checks */
		if (unlikely(want_ev)) {
			/* Event delivery is desired, let's do that now. */
			struct up_nlhdr *up_nlhdr;
			skb = up_nlevent_prepare(UPOLICY_EVENT(KILL), &up_nlhdr);

			if (likely(skb)) {
				enum UP_EV_DECISION decision = UP_DECISION(ALLOW);

				/* UP_NLA_PID is set by up_pre_send_fixup_pid. */
				/* NLA_PUT_U32(skb, UP_NLA_PID, task_pid_nr(tsk)); */

				NLA_PUT_U32(skb, UP_NLA_PTRACE_MODE, mode);

				decision = __up_nlevent_send(skb, tracee, UPOLICY_EVENT(KILL), NULL, current,
						up_pre_send_fixup_pid, task_pid(current));
				if (decision != UP_DECISION(ALLOW)) {
					up_dprintk(HANDLER_PTRACE,
							"tracee@%p,tsk@%p: ptrace_attach(%p,%d) denied (decision=%d).\n",
							tracee, current, tsk, mode, decision);
					rc = -EPERM;
				}
			} else {
				rc = -EPERM;
			}
		}
		up_tracee_put(tracee);
	}
	return rc;

nla_put_failure:
	kfree_skb(skb);
out_put_tracee:
	up_tracee_put(tracee);
	return rc;
}

