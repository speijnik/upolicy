/* context.c
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
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <kupolicy/context.h>
#include <kupolicy/tracee.h>
#include <kupolicy/tracer.h>
#include <kupolicy/upolicy.h>

/* function declarations */
static void up_context_free(struct up_context* ctx);

void up_context_init(struct up_context *ctx, struct up_tracer *tracer) {
	memset(ctx, 0, sizeof(struct up_context));

	INIT_LIST_HEAD(&ctx->tracees_list);
	rwlock_init(&ctx->tracees_rwlock);
	atomic_set(&ctx->usage, 1);
	ctx->tracer = up_tracer_get(tracer);
}

struct up_context* up_context_alloc(struct up_tracer *tracer)
{
  struct up_context *ctx = NULL;

  ctx = kmalloc(sizeof(struct up_context), GFP_KERNEL);
  
  if (unlikely(!ctx))
    goto out;

  up_context_init(ctx, tracer);

 out:
  return ctx;
}

static void up_context_free(struct up_context* ctx) {
  if (unlikely(!ctx))
    return;

  if (unlikely(atomic_read(&ctx->usage) > 0))
    return;

  up_tracer_put(ctx->tracer);

  /* 
   * There is no need to iterate over all tracees here, because
   * usage indicates that there are no tracees left.
   */
  if (ctx != &ctx->tracer->null_context)
  	kfree(ctx);
}

int up_context_add(struct up_context* ctx,
		   struct up_tracee* tracee)
{
  unsigned long flags;
  struct up_tracer *tracer = up_tracer_get(ctx->tracer);

  if (unlikely(!tracer))
    return -EINVAL;

  tracee->context = ctx;
  up_context_get(ctx);
  write_lock_irqsave(&ctx->tracees_rwlock, flags);
  list_add(&tracee->list, &ctx->tracees_list);
  write_unlock_irqrestore(&ctx->tracees_rwlock, flags);
  atomic_inc(&tracer->tracee_count);

  up_tracer_put(tracer);
  return 0;
}

void up_context_remove(struct up_context* ctx,
		       struct up_tracee* tracee) {
  int rc;
  int notification_queued = 0;
  struct up_tracer *tracer = up_tracer_get(ctx->tracer);
  unsigned long flags;

  if (unlikely(!tracer))
    return;

  if (unlikely(tracee->context != ctx))
    goto out;

  write_lock_irqsave(&ctx->tracees_rwlock, flags);
  list_del(&tracee->list);
  write_unlock_irqrestore(&ctx->tracees_rwlock, flags);

  up_dprintk(CONTEXT, "removed tracee@%p from context@%p (id=%d)\n", tracee, ctx,
  		ctx->id);

  if (unlikely(ctx != &tracer->null_context && list_empty(&ctx->list)
  		&& up_context_wants_event(ctx, UPOLICY_EVENT(CTX_ALL_TRACEES_EXITED)))) {
  	/* Context has become empty, send notification */
  	if ((rc = up_worker_add(UP_WORKER_CTX_ALL_TRACEES_EXITED, up_context_get(ctx),
  			NULL, GFP_ATOMIC)) < 0) {
  		up_eprintk("up_worker_add failed for CTX_ALL_TRACEES_EXITED item: %d\n", rc);
  		up_context_put(ctx);
  	}
  }
  if (unlikely(atomic_dec_and_test(&tracer->tracee_count))) {
  	if (ctx != &tracer->null_context) {
  		if ((rc = up_worker_add(UP_WORKER_ALL_TRACEES_EXITED, up_tracer_get(tracer),
  				NULL, GFP_ATOMIC)) < 0) {
  			up_eprintk("up_worker_add failed for ALL_TRACEES_EXITED item: %d\n", rc);
  			up_tracer_put(tracer);
  		} else {
  			notification_queued = 1;
  		}
  	} else {
  		up_dprintk(CONTEXT,
  				"ctx@%p: no all tracees exited notification: is null context.\n", ctx);
  	}
  }

  up_dprintk(CONTEXT, "tracer@%p: %d tracees remaining\n", tracer,
			atomic_read(&tracer->tracee_count));

  if (likely(!notification_queued)) {
  	tracee->context = NULL;
  }

  up_context_put(ctx);
 out:
  up_tracer_put(tracer);
}

void up_context_killtracees(struct up_context *ctx)
{
  struct up_context *c = up_context_get(ctx);
  struct list_head *tmp;
  struct up_tracee *tracee;
  unsigned long flags;
  if (unlikely(!c))
    return;

  write_lock_irqsave(&ctx->tracees_rwlock, flags);
  list_for_each(tmp, &ctx->tracees_list) {
    tracee = list_entry(tmp, struct up_tracee, list);
    up_tracee_kill(tracee);
  }
  write_unlock_irqrestore(&ctx->tracees_rwlock, flags);
  up_context_put(c);
}

void __up_context_put(struct up_context *ctx) {
	BUG_ON(atomic_read(&ctx->usage) == 0);

  if (atomic_dec_and_test(&ctx->usage)) {
    up_context_free(ctx);
  } else {
  	up_dprintk(REFCOUNT, "ctx@%p,usage=%d\n", ctx, atomic_read(&ctx->usage));
  }
}
