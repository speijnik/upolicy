/* tracee.c
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
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>

#include <kupolicy/context.h>
#include <kupolicy/tracee.h>
#include <kupolicy/tracer.h>
#include <kupolicy/upolicy.h>

/* function declarations */
static void up_tracee_free(struct up_tracee* tracee);

struct up_tracee* up_tracee_alloc(gfp_t gfp) {
  struct up_tracee* t = NULL;
  t = kzalloc(sizeof(struct up_tracee), gfp);
  if (unlikely(!t))
    goto out;

  atomic_set(&t->usage, 1);

 out:
  return t;
}

static void up_tracee_free(struct up_tracee* tracee) {
  if (unlikely(!tracee))
    return;

  if (unlikely(atomic_read(&tracee->usage) > 0)) {
  	up_eprintk("tracee_free called, but tracee->usage > 0\n");
    return;
  }

  if (tracee->context) {
  	if (tracee->tg_pid != NULL) {
  		/* We need to retrieve another reference to the context here, because
  		 * we need to avoid the context being free'd until the worker has done
  		 * its job. The worker is responsible for dropping the reference again.
  		 */
  		struct up_context *ctx = up_context_get(tracee->context);
  		if (up_worker_add(UP_WORKER_TRACEE_EXITED, ctx, get_pid(tracee->tg_pid),
  				GFP_ATOMIC)) {
  			up_context_put(tracee->context);
  		}
  	}
  	up_context_remove(tracee->context, tracee);
  }

  if (tracee->tg_pid != NULL)
   	put_pid(tracee->tg_pid);

  if (tracee->parent_tracee)
  	up_tracee_put(tracee->parent_tracee);

  if (tracee->tracer)
  	up_tracer_put(tracee->tracer);

  kfree(tracee);
}

void __up_tracee_put(struct up_tracee* tracee) {
	BUG_ON(atomic_read(&tracee->usage) == 0);

  if (atomic_dec_and_test(&tracee->usage)) {
    up_tracee_free(tracee);
  } else {
  	up_dprintk(REFCOUNT, "tracee@%p,usage=%d\n", tracee, atomic_read(&tracee->usage));
  }
}

int __up_tracee_validate(void)
{
  struct upolicy* up = current_upolicy();
  struct up_tracee* tracee = NULL;
  struct up_tracer* tracer = NULL;
  int new_tracee = 0;

  if (!up) {
  	up_dprintk(TRACEE, "security is NULL. cred@%p,cred->security@%p\n",
  			current_cred(), current_cred() ? current_cred()->security : NULL);
    return 0;
  }

  tracee = up_tracee_get(up->tracee);

  /* Check if this is a tracee. */
  if (unlikely(!tracee)) {
  	up_dprintk(TRACEE, "Tracee is NULL.\n");
    return 0;
  }

  /*
   * First check to do is checking if the tracer has its socket open.
   * A closed socket means we need to kill the tracee.
   */
  tracer = up_tracer_get(tracee->tracer);
  if (unlikely(!tracer)) {
    /* A tracee without a tracer? Kill it! */
  	up_eprintk("Tracer is NULL.\n");
    goto out_kill_put_tracee;
  }

  if (tracer->socket.nlpid == UP_NL_PID_INVALID) {
  	up_dprintk(TRACEE, "tracer@%p has its socket closed, killing tracee@%p\n",
  			tracer, tracee);
  	goto out_kill_put_tracer;
  }

  if (unlikely(!tracee->tg_pid)) {
    tracee->tg_pid = get_pid(task_tgid(current));
    new_tracee = 1;
	}

  if (unlikely(tracee->context == &tracer->null_context)) {
	  /* Seems like a top-level tracee. Inform the tracer about it. */
  	enum UP_EV_DECISION decision = UP_DECISION(ALLOW);
  	struct up_nl_response resp;
  	struct up_nlhdr* up_nlhdr;

  	up_dprintk(TRACEE, "Tracee@%p running in NULL-context.\n");

  	decision = up_nlevent_send_single_simple(tracee, UPOLICY_EVENT(TRACEE_NEW),
  			&resp);
  	if (decision == UP_DECISION(ALLOW)) {
  		up_ctx_id ctx_id = 0;

  		up_nlhdr = resp.info.userhdr;

  		if (unlikely(!up_nlhdr)) {
  			up_eprintk("resp.info.userhdr == %p (NULL).\n", up_nlhdr);
  			up_nl_response_free(&resp);
  			goto out_kill_put_tracer;
  		}

  		ctx_id = up_nlhdr->context_id;
  		up_dprintk(TRACEE, "tracee@%p assigned to ctx ID=%d\n.", tracee, ctx_id);
  		/*
  		 * After getting the context we have received all information we need, so we
			 * can free up some memory again.
			 */
			up_nl_response_free(&resp);

  		if (ctx_id) {
  			/* Attaching to specified context requested. */
  			struct up_context *ctx = up_tracer_find_ctx(tracee->tracer, ctx_id);
  			int rc = 0;

  			if (unlikely(!ctx)) {
  				up_eprintk("received invalid context ID from tracer: %d\n",
  						ctx_id);
  				goto out_kill_put_tracer;
  			}

  			/* Remove from null-context. */
  			up_dprintk(TRACEE, "Removing tracee@%p from null-context@%p...\n", tracee, ctx);
  			up_context_remove(&tracer->null_context, tracee);
  			up_dprintk(TRACEE, "Removed tracee@%p from null-context.\n", tracee);

  			if (unlikely((rc = up_context_add(ctx, tracee)))) {
  				up_eprintk("adding tracee to context failed: %d\n", rc);
  				up_context_put(ctx);
  				goto out_kill_put_tracer;
  			}
  			up_dprintk(TRACEE, "tracee@%p added to context@%p.\n", tracee, ctx);
  			/* Release the reference we got from up_tracer_find_ctx. */
  			up_context_put(ctx);
  		} else {
  			/* context_id == 0, which means the tracer does not want to attach to the tracee. */
  			up_dprintk(TRACEE, "Removing tracee@%p from null context...\n", tracee);
  			up_context_remove(&tracer->null_context, tracee);

  			if (tracee->parent_tracee) {
  				/*
  				 * parent_tracee is present, which means we will simply attach to the context
  				 * the parent tracee is attached to.
  				 */
  				int rc = 0;
  				up_dprintk(TRACEE, "Adding tracee@%p to parent_tracee context@%p.\n", tracee,
  						tracee->parent_tracee->context);
  				if (unlikely((rc = up_context_add(tracee->parent_tracee->context, tracee)))) {
  					up_eprintk("adding tracee to (parent) context failed: %d\n", rc);
  					goto out_kill_put_tracer;
  				}
  				/* Modify the responsible tracer accordingly... */
  				tracee->tracer = up_tracer_get(tracee->parent_tracee->tracer);
  				up_tracer_put(tracer);
  			} else {
  				/*
  				 * Detach requested.
  				 */

  				if (likely(!up->tracer)) {
  					/* Not a tracer, get rid of struct upolicy for that process. */
  					up_dprintk(TRACEE, "Detaching tracee@%p from tracer@%p.\n", tracee, tracer);
  					up_free((struct cred*)current_cred());
  				} else {
  					/* Also a tracer, get rid of tracee information only. */
  					up_dprintk(TRACEE, "Detaching tracee@%p from tracer@%p. Still a tracer.\n",
  							tracee, tracer);
  					up->tracee = NULL;
  					up_tracee_put(tracee);
  				}
  			}
  		}

  		if (new_tracee && tracee->context) {
  			/* Notify tracer that a new tracee has been started. */
  			up_nlevent_send_simple(tracee, UPOLICY_EVENT(TRACEE_STARTED), NULL);
  		}

  	} else {
  		/* decision != UP_DECISION(ALLOW) */
  		up_nl_response_free(&resp);

  		/* Force KILL here... */
  		if (decision != UP_DECISION(KILL))
  			goto out_kill_put_tracee;
  	}
  }
  /* Fall-through: Give up references to tracee and tracer. */
  up_tracer_put(tracer);
  up_tracee_put(tracee);
  return 0;
out_kill_put_tracer:
  up_tracer_put(tracer);
out_kill_put_tracee:
  up_tracee_put(tracee);
  up_tracee_kill(tracee);
  return -EPERM;
}

void up_tracee_kill(struct up_tracee *tracee) {
  int rc = 0;
  struct task_struct *tsk = NULL;

  if (unlikely(!tracee)) {
    up_dprintk(TRACEE, "Called with tracee=NULL\n");
    return;
  }

  if (unlikely(!tracee->tg_pid)) {
    up_dprintk(TRACEE, "tracee@%p: tracee->tg_pid is NULL!\n", tracee);
    return;
  }

  tsk = pid_task(tracee->tg_pid, PIDTYPE_PID);

  if (unlikely(!tsk)) {
  	up_dprintk(TRACEE, "tracee@%p: unable to find task of tg_pid@%p\n",
  			tracee, tracee->tg_pid);
  	return;
  }

  if ((rc = send_sig_info(SIGKILL, SEND_SIG_PRIV, tsk))) {
    up_eprintk("tracee@%p, tsk@%p: kill_pid_info failed: %d\n", tracee, tsk, rc);
    return;
  }
}
