/* handler_task.c
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
#include <linux/signal.h>

#include <kupolicy/handler.h>
#include <kupolicy/netlink.h>
#include <kupolicy/tracee.h>
#include <kupolicy/upolicy.h>

int up_task_kill(struct task_struct *p, struct siginfo *info,
		      int sig, u32 secid) {
  /* 
   * We need to verify that signals are not sent from inside one
   * context to the outside, be it another context or outside any
   * context.
   */
  struct upolicy* upol = current_upolicy();
  struct upolicy* target_up = task_upolicy(p);
  struct up_tracee *tracee = NULL;
  struct sk_buff *skb = NULL;
  int want_ev = 0;
  int rc = 0;

  if (!upol)
    return 0;

  tracee = up_want_handle_event(UPOLICY_EVENT(KILL));

  if (unlikely(tracee)) {
  	want_ev = 1;
  } else {
  	tracee = up_tracee_get(upol->tracee);
  }

  if (unlikely(tracee)) {
  	/* Common sanity checks first... */
  	if (!target_up) {
  		/* Disallow, signal from tracee to outside world. */
  		up_dprintk(HANDLER_TASK, "kill by %p of %p (signo=%d) denied: target not traced.\n",
  				current, p, sig);
  		rc = -EPERM;
  		goto out_put_tracee;
  	}

  	if (!up_same_context(upol, target_up)) {
  		/* Disallow, signal from one context to another */
  		rc = -EPERM;
  		up_dprintk(HANDLER_TASK, "kill by %p of %p (signo=%d) denied: different contexts.\n",
  		  				current, p, sig);
  		goto out_put_tracee;
  	}

  	if (want_ev) {
  		/* Event delivery is desired, let's do that now. */
  		struct up_nlhdr *up_nlhdr;
  		skb = up_nlevent_prepare(UPOLICY_EVENT(KILL), &up_nlhdr);

  		if (likely(skb)) {
  			enum UP_EV_DECISION decision = UP_DECISION(ALLOW);

  			/* UP_NLA_PID is set by up_pre_send_fixup_pid. */
  			/* NLA_PUT_U32(skb, UP_NLA_PID, task_pid_nr(p)); */
  			NLA_PUT_U32(skb, UP_NLA_SIGNO, sig);

  			decision = __up_nlevent_send(skb, tracee, UPOLICY_EVENT(KILL), NULL, current,
  					up_pre_send_fixup_pid, task_pid(current));
				if (decision != UP_DECISION(ALLOW)) {
					up_dprintk(HANDLER_TASK,
							"tracee@%p,tsk@%p: task_kill(%p,%p,%d) denied (decision=%d).\n",
							tracee, current, p, info, sig, decision);
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

int up_task_create(unsigned long clone_flags) {
	struct up_tracee *tracee = up_want_handle_event(UPOLICY_EVENT(CLONE));
	struct sk_buff *skb = NULL;
	int rc = 0;

	if (unlikely(tracee)) {
		struct up_nlhdr *up_nlhdr;
		enum UP_EV_DECISION decision = UP_DECISION(KILL);

		skb = up_nlevent_prepare(UPOLICY_EVENT(CLONE), &up_nlhdr);

		if (likely(skb)) {
			NLA_PUT_U64(skb, UP_NLA_CLONE_FLAGS, clone_flags);
			decision = up_nlevent_send(skb, tracee, UPOLICY_EVENT(CLONE), NULL);
			if (decision != UP_DECISION(ALLOW)) {
				up_dprintk(HANDLER_TASK,
						"tracee@%p,tsk@%p: task_create(%ul) denied (decision=%d).\n",
						tracee, current, clone_flags, decision);
				rc = -EPERM;
			}

		} else {
			rc = -EPERM;
		}
		up_tracee_put(tracee);
	}
	return 0;
nla_put_failure:
	up_eprintk("nla_put_failure.\n");
	kfree_skb(skb);
	up_tracee_put(tracee);
	return -ENOMEM;
}
