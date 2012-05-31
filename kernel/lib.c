/* lib.c
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
#include <linux/slab.h>
#include <linux/types.h>

#include <kupolicy/context.h>
#include <kupolicy/netlink.h>
#include <kupolicy/tracee.h>
#include <kupolicy/tracer.h>
#include <kupolicy/upolicy.h>

/* function declarations */

struct upolicy*
up_alloc(gfp_t gfp) {
	return kzalloc(sizeof(struct upolicy), gfp);
}

int up_copy(struct cred *new, const struct cred *old, gfp_t gfp) {
	struct upolicy* up_old = cred_upolicy(old);
	struct upolicy* up_new = cred_upolicy(new);
	int rc = 0;

	if (unlikely(!up_old)) {
		rc = -ENOENT;
		goto out;
	}

	if (unlikely(old != current_cred() && old != current->real_cred)) {
		up_dprintk(CORE,
				"Ignoring cred@%p: does not equal current task credentials@%p,@%p\n",
				old, current_cred(), current->real_cred);
		return 0;
	}

	if (!up_new) {
		struct up_tracer *old_tracer;
		struct up_tracee *old_tracee;

		up_new = up_alloc(gfp);

		if (unlikely(!up_new)) {
			rc = -ENOMEM;
			goto out;
		}

		new->security = up_new;

		old_tracer = up_tracer_get(up_old->tracer);
		old_tracee = up_tracee_get(up_old->tracee);
		if (old_tracer) {
			/*
			 * Old process is a tracer.
			 * This means that the new process automatically becomes a tracee.
			 */
			struct up_tracee *new_tracee = up_tracee_alloc(gfp);
			if (unlikely(!new_tracee)) {
				/* Alloc failed. */
				up_tracer_put(old_tracer);

				if (old_tracee)
					up_tracee_put(old_tracee);

				rc = -ENOMEM;
				goto out_free_up;
			}

			if (old_tracee) {
				/* ... and a tracee too. Nesting detected. */
				new_tracee->parent_tracee = up_tracee_get(old_tracee);
				up_dprintk(CORE, "new tracee@%p has parent tracee@%p\n",
						new_tracee, old_tracee);
			}
			new_tracee->tracer = up_tracer_get(old_tracer);
			up_context_add(&old_tracer->null_context, new_tracee);
			up_new->tracee = new_tracee;
		}
		else if (old_tracee) {
			/*
			 * New tracee is not child of a tracer...
			 * The nesting case has been handled above already.
			 * If in nesting mode there is nothing we need to do.
			 */
			struct up_tracee *new_tracee = up_tracee_alloc(gfp);
			if (unlikely(!new_tracee)) {
			  rc = -ENOMEM;
			  goto out_put;
			}

			new_tracee->tracer = up_tracer_get(old_tracee->tracer);
			if (unlikely(!new_tracee->tracer)) {
				rc = -EINVAL;
				up_tracee_put(new_tracee);
				goto out_put;
			}

			rc = up_context_add(old_tracee->context, new_tracee);
			if (unlikely(rc)) {
				rc = -EINVAL;
				up_tracer_put(new_tracee->tracer);
				up_tracee_put(new_tracee);
				goto out_put;
			}

			if (unlikely(old_tracee->parent_tracee)) {
				up_dprintk(CORE, "Copied parent_tracee=%p from old=%p to new=%p\n",
						old_tracee->parent_tracee, old_tracee, new_tracee);
				new_tracee->parent_tracee = up_tracee_get(old_tracee->parent_tracee);
			}

			up_new->tracee = new_tracee;
		}

		if (old_tracee)
			up_tracee_put(old_tracee);
		if (old_tracer)
			up_tracer_put(old_tracer);
		goto out;

		out_put:
		if (old_tracee)
			up_tracee_put(old_tracee);
		if (old_tracer)
			up_tracer_put(old_tracer);

		out_free_up:
		new->security = NULL;
		up_free(new);
		goto out;
	}
	out:
	return rc;
}

void up_free(struct cred *cred) {
	struct upolicy* up = cred_upolicy(cred);
	struct up_tracer *tracer = NULL;
	struct up_tracee *tracee = NULL;

	if (unlikely(!up)) {
		/*
		 * No upolicy information, which means nothing do to.
		 */
		return;
	}
	/* Set the security field to NULL before doing anything... */
	cred->security = NULL;

	tracer = up_tracer_get(up->tracer);
	if (tracer) {
		/* Is a tracer. */

		up_dprintk(CORE, "up_free: Tracer@%p has exited.\n", tracer);
		/* Detach all contexts and in turn kill all tracees. */
	  up_tracer_detach_all(tracer);

		/* Give up two references:
		 * One we just got here and the initial reference.
		 */
		up_tracer_put(tracer);
		up_tracer_put(tracer);
		up->tracer = NULL;
	}

	tracee = up_tracee_get(up->tracee);
	if (tracee) {
		/* Is a tracee. */
		up_dprintk(CORE, "up_free: tracee@%p has exited.\n", tracee);
		/* Again, give up both the local and the initial reference. */
		up_tracee_put(tracee);
		up_tracee_put(tracee);
	}

	/*
	 * Free the memory reserved by the upolicy struct.
	 */
	kfree(up);
}

int up_same_context(struct upolicy* src, struct upolicy* dst) {
	struct up_tracee *tracee_src = NULL;
	struct up_tracee *tracee_dst = NULL;
	struct up_tracee *tracee_tmp = NULL;

	/* LOGIC:
	 * Two tasks are in the same context if:
	 *  - both are tracees and the context pointer matches.
	 *  - both are tracees and dst has a matching context somewhere in its parent_tracee
	 *    path.
	 */
	tracee_src = up_tracee_get(src->tracee);
	if (unlikely(!tracee_src)) {
		/* Source is untraced, which means they are "in the same context". */
		return 1;
	}

	tracee_dst = up_tracee_get(dst->tracee);
	if (unlikely(!tracee_dst)) {
		/* Destination is untraced whilst source is traced: not in same context. */
		up_tracee_put(tracee_src);
		return 0;
	}

	/* Getting this far means that both are tracees. */

	if (tracee_src->context == tracee_dst->context) {
		/* Simple case: pointer comparison. */
		up_tracee_put(tracee_src);
		up_tracee_put(tracee_dst);
		return 1;
	}

	/*
	 * Getting this far means we need to do a more expensive check by walking the
	 * destination's parent_tracee list...
	 */

	/* NOTE: we intentionally do NOT call up_tracee_get here.
	 * That's because we are holding a reference to tracee_dst, which means it cannot
	 * be free'd meanwhile. If parent_tracee is set in tracee_dst then tracee_dst is in
	 * turn holding a reference on its parent tracee, which also cannot be free'd meanwhile.
	 * This is true for the whole group of tracees linked through parent_tracee pointers.
	 */
	tracee_tmp = tracee_dst->parent_tracee;
	while(tracee_tmp) {
		/* Checking the context pointer is fine here once again. */
		if (tracee_src->context == tracee_tmp->context) {
			up_tracee_put(tracee_src);
			up_tracee_put(tracee_dst);
			return 1;
		}
		tracee_tmp = tracee_tmp->parent_tracee;
	}
	up_tracee_put(tracee_src);
	up_tracee_put(tracee_dst);
	return 0;
}

struct up_tracee *up_want_handle_event(enum UP_EVENT ev) {
	const struct cred *this_cred = current_cred();
	struct upolicy *this_up = NULL;
	struct up_tracee *tracee = NULL;
	int rc = 0;

	if (unlikely(!this_cred)) {
		up_eprintk("this_cred = NULL?\n");
		return NULL;
	}

	this_up = cred_upolicy(this_cred);

	if (likely(!this_up)) {
		return NULL;
	}

	if (unlikely((tracee = up_tracee_get(this_up->tracee)))) {
		rc = up_tracee_validate();

		if (unlikely(rc)) {
			/* tracee validation failed. */
			up_tracee_put(tracee);
			tracee = NULL;
		}

		if (!(tracee->context)) {
			up_eprintk("tracee->context is NULL?\n");
			up_tracee_put(tracee);
			return NULL;
		}

		if (!tracee->context || \
				!(tracee->context->combined_mask & upolicy_ev_flag(ev))) {
			/* event handling is not wanted. */
			up_tracee_put(tracee);
			tracee = NULL;
		}
	}

	return tracee;
}

int up_pre_send_fixup_pid(struct sk_buff *skb, struct up_tracee *tracee,
		struct up_tracer *tracer, void *data) {
	struct pid *pid = data;
	NLA_PUT_U32(skb, UP_NLA_PID, pid_nr_ns(pid, tracer->pid_ns));
	return 0;

nla_put_failure:
	return -1;
}

