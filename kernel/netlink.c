/* netlink.c
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
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/skbuff.h>
#include <linux/slab.h>

#include <net/netlink.h>
#include <net/genetlink.h>

#include <kupolicy/context.h>
#include <kupolicy/netlink.h>
#include <kupolicy/tracee.h>
#include <kupolicy/tracer.h>
#include <kupolicy/upolicy.h>

/*
 * Struct holding basic question information.
 *
 * The binary semaphore inside this struct is used
 * to block the tracee until the tracer has answered
 * the question, whilst all other information is used
 * for looking up the correct instance of this structure
 * after receiving an answer from the tracer.
 */
struct up_question { 
  /*
   * List member for socket-local question list.
   */
  struct list_head list;

  /*
   * Binary semaphore used to lay the requester to sleep
   * until a response has been received.
   */
  struct semaphore sem;

  /*
   * Context
   */
  struct up_context  *ctx;

  /*
   * Tracee which we are asking a question for.
   */
  struct up_tracee*   tracee;

  /*
   * threadgroup (process) ID of tracee
   */
  pid_t 		          pid;

  /*
   * thread-id of the tracee's thread.
   */
  pid_t                tid;

  /*
   * Decision
   */
  enum UP_EV_DECISION  decision;

  /*
   * Response pointer.
   */
  struct up_nl_response *response;
};

/* forward declarations */
static struct up_question* q_lookup(struct up_socket* socket, 
				    pid_t tid);
static int q_handle_response(struct up_question *q, struct sk_buff *skb,
			    struct genl_info *info);

#define up_genl_func_name(name) genl_ ##name## _doit
#define up_genl_func(name) static int up_genl_func_name(name)	\
  (struct sk_buff *skb, struct genl_info *info)
up_genl_func(init);
up_genl_func(ctx_create);
up_genl_func(ctx_destroy);
up_genl_func(decision);

static int genl_handle_release(struct notifier_block *nb,
			       unsigned long ev,
			       void *nl_notify);

static void q_unlink(struct up_tracer *tracer, struct up_question *q);


/* file-local variables */
static int netlink_registered = 0;
static struct notifier_block genl_release_nb = {
  .notifier_call = genl_handle_release,
};
static struct semaphore q_semaphore;

static struct nla_policy genl_policy_noattr[UP_NLA_MAX + 1] = {
  /* empty */
};

static struct nla_policy genl_policy_ctx_create[UP_NLA_MAX + 1] = {
  [UP_NLA_EVENTMASK] = { .type = NLA_U64, },
  [UP_NLA_NOTIFYMASK] = { .type = NLA_U64, },
  [UP_NLA_UCONTEXT_ID] = { .type = NLA_U16, },
};

static struct nla_policy genl_policy_decision[UP_NLA_MAX + 1] = {
  [UP_NLA_DECISION] = { .type = NLA_U8, },
};

static struct genl_family genl_family = {
  .id = GENL_ID_GENERATE,
  .hdrsize = sizeof(struct up_nlhdr),
  .name = UP_NL_FAMILY_NAME,
  .version = UP_NL_VERSION,
  .maxattr = UP_NLA_MAX
};

#define up_genl_ops(cmd_name, doit_name, policy_name)	\
  {							\
    .cmd = UP_NLC_ ##cmd_name,				\
    .flags = 0, 		  			\
    .policy = genl_policy_ ##policy_name,		\
    .doit = up_genl_func_name(doit_name),		\
    .dumpit = NULL,					\
   }

#define UP_GENL_NCMDS 4
static struct genl_ops genl_ops[UP_GENL_NCMDS] = {
  up_genl_ops(INIT, init, noattr),
  up_genl_ops(CTX_CREATE, ctx_create, ctx_create),
  up_genl_ops(CTX_DESTROY, ctx_destroy, noattr),
  up_genl_ops(DECISION, decision, decision),
};

/* file-local functions */
static int genl_handle_release(struct notifier_block *nb,
			       unsigned long ev,
			       void *nl_notify)
{
  /* WARNING: We are running in atomic context here! */
  struct netlink_notify* n = nl_notify;
  struct upolicy* up = current_upolicy();
  struct up_tracer* tracer = NULL;

  if (likely(!up || ev != NETLINK_URELEASE))
    return NOTIFY_DONE;

  tracer = up_tracer_get(up->tracer);
  if (tracer) {
    /* 
     * We received the NETLINK_URELEASE event, the originator is
     * known by upolicy and is a tracer. At this point we need
     * to check if the tracer closed its socket...
     */

    if (unlikely(tracer->socket.nlpid == n->pid)) {
      /* 
       * Seems like the tracer has closed its socket.
       * Because we are in atomic context here the only thing
       * we can do for now is marking the socket as invalid.
       * The next call that would send data to the socket will
       * do the actual work because at that point we will be in
       * process context and can then execute possibly blocking calls.
       */
      tracer->socket.nlpid = UP_NL_PID_INVALID;
      up_dprintk(NETLINK, "genl_handle_release: tracer@%p closed socket with nlpid=%d\n",
      		tracer, n->pid);
    }
    up_tracer_put(tracer);
  }
  /* fall-through */
  
  return NOTIFY_DONE;
}

up_genl_func(init)
{
  /* 
   * When this one is called the caller should become a upolicy
   * tracer.
   * This however is only possible if it is not a tracer yet.
   */
  struct upolicy *up = current_upolicy();
  struct up_tracer *tracer = NULL;
  struct up_tracee *tracee = NULL;

  if (!try_module_get(THIS_MODULE)) {
    /* try_module_get failed which means we cannot init right now. */
  	up_dprintk(NETLINK, "try_module_get failed, task@%p\n", current);
    return -ENOTCONN;
  }

  if (!up) {
    struct cred *c = NULL;

    /* Not known by upolicy yet. */
    up = up_alloc(GFP_KERNEL);
    if (!up) {
    	up_dprintk(NETLINK, "up_alloc failed, task@%p\n", current);
      module_put(THIS_MODULE);
      return -ENOMEM;
    }
    c = (struct cred*) current->cred;
    c->security = (void*) up;
  }

  tracer = up_tracer_get(up->tracer);
  if (unlikely(tracer)) {
    /* The caller is already a tracer... */
  	up_dprintk(NETLINK, "up_tracer_get failed. task@%p\n", current);
    module_put(THIS_MODULE);
    up_tracer_put(tracer);
    return -EALREADY;
  }
  
  tracee = up_tracee_get(up->tracee);
  if (tracee) {
    /*
     * The task who wants to become a tracer is a tracee
     * already. This means we might need to ask its tracer
     * whether it can become a tracer in the first place.
     */
    enum UP_EV_DECISION decision = UP_DECISION(KILL);
    decision = up_nlevent_send_simple(tracee, UPOLICY_EVENT(TRACER_INIT), NULL);
    up_tracee_put(tracee);
    if (decision != UP_DECISION(ALLOW)) {
    	/* We do not have to free up here, because we can assume it was allocated before. */
    	module_put(THIS_MODULE);
    	up_tracer_put(tracer);
    	up_dprintk(NETLINK, "tracer@%p disallowed tracee@%p becoming a tracer.\n", tracee, tracee->tracer);
    	return -EPERM;
    }
  }
  
  /* If we get this far we can set everything up. */  
  up->tracer = up_tracer_alloc(up, GFP_KERNEL);
  up_socket_init(&up->tracer->socket, info->snd_pid);
  up->tracer->pid_ns = current->nsproxy->pid_ns;

  up_dprintk(NETLINK, "task@%p with pid=%d is now a tracer.\n",
		  current, task_pid_nr(current));
  return 0;
}

up_genl_func(ctx_create) {
  struct up_context *ctx = NULL;
  struct upolicy *up = current_upolicy();
  struct up_tracer *up_tracer = NULL;
  struct sk_buff *reply_skb = NULL;
  struct up_nlhdr *up_nlhdr = NULL;
  struct nlmsghdr *nlhdr = NULL;
  struct genlmsghdr *genlhdr = NULL;
  struct up_tracee *up_tracee = NULL;
  up_event_mask evmask = 0;
  up_event_mask notifymask = 0;

  up_ctx_id ucontext_id = 0;
  int error = 0;

  if (unlikely(!up)) {
    /* No upolicy information at all. */
  	up_dprintk(NETLINK, "cred->security not present, task@%p.\n", current);
    return -EPERM;
  }

  up_tracer = up_tracer_get(up->tracer);

  /*
   * Check if this is a tracer.
   * If not: deny call.
   */
  if (unlikely(!up_tracer)) {
  	up_dprintk(NETLINK, "up->tracer not present, task@%p\n", current);
    return -EPERM;
  }

  /*
   * UCONTEXT_ID has to be present in any case and
   * at last event mask or notify mask have to be present.
   */
  if (!info->attrs[UP_NLA_UCONTEXT_ID] ||
  		(!info->attrs[UP_NLA_EVENTMASK] && !info->attrs[UP_NLA_NOTIFYMASK])) {
    up_tracer_put(up_tracer);
    up_dprintk(NETLINK, "ucontext_id or event masks not present, task@%p,tracer@%p.\n",
    		current, up_tracer);
    return -EINVAL;
  }

  if (info->attrs[UP_NLA_EVENTMASK]) {
    evmask = nla_get_u64(info->attrs[UP_NLA_EVENTMASK]);
  }

  if (info->attrs[UP_NLA_NOTIFYMASK]) {
    notifymask = nla_get_u64(info->attrs[UP_NLA_NOTIFYMASK]);
  }

  if (info->attrs[UP_NLA_UCONTEXT_ID]) {
  	ucontext_id = nla_get_u16(info->attrs[UP_NLA_UCONTEXT_ID]);
  }

  /*
   * Event mask must be present and valid.
   */
  if (unlikely((!evmask && !notifymask) || evmask > UPOLICY_EV_FLAG_ALL
	       || notifymask > UPOLICY_EV_FLAG_ALL)) {
    up_tracer_put(up_tracer);
    up_dprintk(NETLINK, "evmasks invalid, task@%p,tracer@%p\n", current, up_tracer);
    return -EINVAL;
  }

  /*
   * Allocate context memory.
   */
  ctx = up_context_alloc(up_tracer);

  if (unlikely(!ctx)) {
  	up_dprintk(NETLINK, "context alloc failed, trask@%p, tracer@%p\n", current,
  				up_tracer);
    up_tracer_put(up_tracer);
    return -ENOMEM;
  }

  /* Set event masks. */
  ctx->question_mask = evmask;
  ctx->notify_mask = notifymask;

  /* Set the combined mask */
  ctx->combined_mask = evmask | notifymask;

  if ((up_tracee = up_tracee_get(up->tracee))) {
  	/* Tracer is being traced. */
  	up_dprintk(NETLINK, "Tracer@%p is being traced, context@%p\n", up_tracer,
  			up_tracee->context);
  	up_dprintk(NETLINK, "combining masks this=%x and parent=%x to combined=%x\n",
  			ctx->combined_mask, up_tracee->context->combined_mask,
  			ctx->combined_mask | up_tracee->context->combined_mask);
  	ctx->combined_mask |= up_tracee->context->combined_mask;
  	up_tracee_put(up_tracee);
  }

  /* 
   * Memory allocated. We now need to attach this context
   * to the tracer.
   */
  error = up_tracer_attach_ctx(up_tracer, ctx);

  if (error) {
  	up_dprintk(NETLINK, "attach failed, task@%p,tracer@%p,ctx@%p\n",
  			current, up_tracer, ctx);
    up_context_put(ctx);
    up_tracer_put(up_tracer);
    return error;
  }

  /* Attaching was fine, now send back the context id. */
  reply_skb = up_nlevent_prepare(UPOLICY_EVENT(CONTEXT_CREATED), &up_nlhdr);

  if (unlikely(!reply_skb)) {
  	up_dprintk(NETLINK, "nlevent_prepare failed, task@%p.\n", current);
    up_context_put(ctx);
    up_tracer_put(up_tracer);
    return -ENOMEM;
  }

  if (unlikely((error = up_nlmsg_headers(reply_skb, &nlhdr, &genlhdr, NULL)))) {
  	up_dprintk(NETLINK, "up_nlmsg_headers failed, task@%p,rc=%d\n", current, error);
  	kfree_skb(reply_skb);
  	up_context_put(ctx);
  	up_tracer_put(up_tracer);
  	return error;
  }

  genlhdr->cmd = UPOLICY_COMMAND(NOTIFICATION);

  up_nlhdr->context_id = ctx->id;
  NLA_PUT_U16(reply_skb, UP_NLA_UCONTEXT_ID, ucontext_id);
  goto no_nla_failure;

  nla_put_failure:
  up_eprintk("NLA_PUT failed, skb@%p\n", skb);

  no_nla_failure:

  if (unlikely((error = up_nlmsg_send(reply_skb, up_tracer)) < 0)) {


  	up_eprintk("up_nlmsg_send failed, task@%p,rc=%d\n", current, error);

  	kfree_skb(reply_skb);
  	up_context_put(ctx);
  	up_tracer_put(up_tracer);
  	return error;
  }

  up_dprintk(NETLINK, "created context@%p, attached to tracer@%p, ctx_id=%u\n",
  		ctx, up_tracer, ctx->id);
  up_dprintk(NETLINK, "context@%p: masks={question:%x,notify:%x,combined:%x}\n",
  		ctx, ctx->question_mask, ctx->notify_mask, ctx->combined_mask);
  up_tracer_put(up_tracer);
  return 0;
}

up_genl_func(ctx_destroy) {
  struct upolicy *up = current_upolicy();
  struct up_context *ctx = NULL;
  struct up_tracer *tracer = NULL;
  struct up_nlhdr *nlhdr = info->userhdr;
  int rc = -EPERM;

  if (unlikely(!nlhdr)) {
    rc = -EINVAL;
    goto out;
  }

  if (unlikely(!up))
    goto out;

  tracer = up_tracer_get(up->tracer);

  if (unlikely(!tracer))
    goto out;

  ctx = up_tracer_find_ctx(tracer, nlhdr->context_id);

  if (unlikely(!ctx)) {
    rc = -ENOENT;
    goto out_put_tracer;
  }

  up_tracer_detach_ctx(tracer, ctx);
  up_context_put(ctx);
  rc = 0;
  
 out_put_tracer:
  up_tracer_put(tracer);
 out:
  return rc;
}

up_genl_func(decision) {
  struct up_question *q = NULL;
  struct upolicy *upol= current_upolicy();
  struct up_nlhdr *nlhdr = info->userhdr;
  struct up_tracer *tracer = NULL;
  int rc = 0;

  if (unlikely(!nlhdr))
    return -EFAULT;

  if (unlikely(!upol))
    return -EPERM;

  tracer = up_tracer_get(upol->tracer);

  if (unlikely(!tracer)) {
    return -EPERM;
  }

  q = q_lookup(&tracer->socket, nlhdr->tid);

  if (unlikely(!q))
    goto out_put;

  /* 
   * up_nlq_handle_response will take care of waking up the tracee
   * again and actually acting on the decision received.
   */
  up_dprintk(NETLINK, "received response, q@%p, skb@%p, info@%p\n", q, skb, info);
  rc = q_handle_response(q, skb, info);

 out_put:
  up_tracer_put(tracer);
  return rc;
}

/* module-local functions */
int __init up_netlink_init(void)
{
  int error = 0;

  error = genl_register_family_with_ops(&genl_family,
					genl_ops, UP_GENL_NCMDS);
  if (error)
    goto out_error;

  error = netlink_register_notifier(&genl_release_nb);
  if (error)
    goto out_genl_unregister;

  sema_init(&q_semaphore, UP_NL_MAX_QUESTIONS);

  netlink_registered = 1;

  return 0;
 out_genl_unregister:
  genl_unregister_family(&genl_family);
 out_error:
  return error;
}

void up_netlink_cleanup(void)
{
  if (netlink_registered) {
    genl_unregister_family(&genl_family);
    netlink_unregister_notifier(&genl_release_nb);
  }
}

static int q_setup(struct up_question *q, struct up_tracee *tracee,
		    struct up_context *ctx, struct up_nl_response *response, struct task_struct *tsk) {
  struct up_tracee *ref_tracee = up_tracee_get(tracee);
  struct up_context *ref_context = NULL;
  int rc = -EINVAL;

  while(down_trylock(&q->sem) == 0) ; /* empty loop that resets the semaphore's value to 0. */

  if (unlikely(!ref_tracee)) {
  	up_eprintk("ref_tracee is NULL.\n");
  	goto out;
  }

  if (!q) {
  	up_eprintk("q is NULL.\n");
  	goto out_put_tracee;
  }


  if (!ctx)
    ctx = tracee->context;

  ref_context = up_context_get(ctx);
  if (unlikely(!ref_context)) {
  	up_eprintk("up_context_get failed.\n");
  	goto out_put_tracee;
  }


  if (unlikely(q->ctx))
    up_context_put(q->ctx);

  if (q->response && q->response->skb) {
  	kfree_skb(q->response->skb);
  	q->response->skb = NULL;
  }

  q->ctx = ref_context;
  if (tsk) {
  	q->pid = task_tgid_nr_ns(tsk, ref_context->tracer->pid_ns);
  	q->tid = task_pid_nr_ns(tsk, ref_context->tracer->pid_ns);
  } else {
  	q->pid = q->tid = 0;
  }

  if (q->tracee)
  	up_tracee_put(q->tracee);

  q->tracee = ref_tracee;
  q->response = response;

  rc = 0;
  goto out;

  up_context_put(ref_context);
 out_put_tracee:
  up_tracee_put(ref_tracee);
 out:
  return rc;
}

static enum UP_EV_DECISION q_send(struct up_question *q, struct sk_buff *skb,
		struct up_tracer *tracer, struct up_nl_response *response) {
	enum UP_EV_DECISION decision = UP_DECISION(KILL);
	int rc;
	int retries = 0;

	if ((rc = up_nlmsg_send(skb, tracer)) >= 0) {
		/* Sending was okay. */
		while((rc = down_timeout(&q->sem, UP_QUESTION_WAIT_SECS * HZ))
				&& (retries < UP_QUESTION_MAX_RETRIES))
		{
			up_dprintk(NETLINK, "timeout, strike %d/%d\n", retries+1, UP_QUESTION_MAX_RETRIES);
			retries++;
		}

		if (!rc) {
			/* Response received. Move on. */
			decision = q->decision;
			up_dprintk(NETLINK, "received decision: %d\n", decision);
		} else {
			q_unlink(tracer, q);
			up_dprintk(NETLINK, "question timed out.\n");
			decision = UP_DECISION(DENY);
		}
	} else {
		q_unlink(tracer, q);
		up_eprintk("failed, up_nlmsg_send returned %d.\n", rc);
	}

	if (tracer->socket.nlpid == UP_NL_PID_INVALID) {
		up_dprintk(NETLINK, "tracer socket was closed, changing decision to KILL\n");
		decision = UP_DECISION(KILL);
	}

	return decision;
}

static struct up_question* q_alloc(struct up_tracee *tracee) {
  struct up_question *q;
  struct up_tracee *t = up_tracee_get(tracee);
  
  if (unlikely(!t))
    return NULL;

  down(&q_semaphore);
  q = kzalloc(sizeof(struct up_question), GFP_KERNEL);

  if (unlikely(!q)) {
    up(&q_semaphore);
    up_tracee_put(t);
    return NULL;
  }

  /* 
   * As the question gets a reference to the tracee
   * we keep that reference around and do NOT put it.
   * This has to be done in the corresponding free function.
   */
  q->tracee = t;
  sema_init(&q->sem, 0);

  return q;
}

static void q_link(struct up_tracer *tracer, struct up_question *q) {
	unsigned long flags;

	write_lock_irqsave(&tracer->socket.question_rwlock, flags);
	list_add(&q->list, &tracer->socket.question_list);
	write_unlock_irqrestore(&tracer->socket.question_rwlock, flags);
}

static void q_unlink(struct up_tracer *tracer, struct up_question *q) {
	unsigned long flags;
	write_lock_irqsave(&tracer->socket.question_rwlock, flags);
	list_del(&q->list);
	write_unlock_irqrestore(&tracer->socket.question_rwlock, flags);
}

static struct up_question* q_lookup(struct up_socket* socket, 
				    pid_t tid)
{
  unsigned long flags;
  struct up_question *q = NULL;
  struct list_head *tmp;

  read_lock_irqsave(&socket->question_rwlock, flags);
  list_for_each(tmp, &socket->question_list) {
    q = list_entry(tmp, struct up_question, list);
    if (q->tid == tid) {
    	/* It should be safe to call list_del here, because we jump out of the loop
    	 * immediately after doing so.
    	 */
    	list_del(&q->list);
      goto out;
    }
  }

  q = NULL;

 out:
  read_unlock_irqrestore(&socket->question_rwlock, flags);
  return q;
}

static int q_handle_response(struct up_question *q, struct sk_buff *skb,
		struct genl_info *info) {
	u32 i = 0;

	if (unlikely(!q)) {
		up_dprintk(NETLINK, "q_handle_response: q=%p.\n", q);
		return -EINVAL;
	}

	if (unlikely(!info->attrs[UP_NLA_DECISION])) {
		q->decision = UP_DECISION(KILL);
		up_dprintk(NETLINK, "UP_NLA_DECISION missing in info=%p\n", info);
		up(&q->sem);
		return -EINVAL;
	}

	q->decision = nla_get_u8(info->attrs[UP_NLA_DECISION]);

	/* Postpone is not a valid decision... */
	if (q->decision == UP_DECISION(POSTPONE)) {
		up_dprintk(NETLINK, "UP_NLA_DECISION was postpone.\n");
		return -EINVAL;
	}

	if (q->response) {
		/* Increment reference count on skb, so it does not get free'd
		 * when we leave the function that received the response.
		 * This is crucial, because the task waiting for the response
		 * needs to access the information received.
		 */
		q->response->skb = skb_get(skb);
		up_dprintk(NETLINK, "q->response->skb@%p, skb@%p\n", q->response->skb, skb);

		/* We can safely copy over the complete response info. */
		memcpy(&q->response->info, info, sizeof(struct genl_info));

		/* However, we need to fix up all nl attributes. */
		q->response->info.attrs = kzalloc((genl_family.maxattr + 1) * sizeof(struct nlattr*),
		   				   GFP_KERNEL);
		genl_info_net_set(&q->response->info, info->_net);
		if (unlikely(!q->response->info.attrs)) {
		    /* Out of memory */
		    kfree_skb(skb);
		    q->response = NULL;
		    q->decision = UP_DECISION(KILL);
		}

		/*
		 * Because each nlattr inside the array described by info.nlattr
		 * points inside the skb again we can safely just copy over the
		 * information.
		 */
		for(i = 0; i < genl_family.maxattr; i++) {
			q->response->info.attrs[i] = info->attrs[i];
		}
	}
	up_dprintk(NETLINK, "waking up task waiting for question q@%p to complete.\n", q);
	up(&q->sem);

	return 0;
}

static void q_free(struct up_question *q) {
  struct up_tracee *tracee = NULL;
  struct up_context *ctx = NULL;
  if (unlikely(!q))
    return;

  tracee = q->tracee;
  ctx = q->ctx;
  kfree(q);
  up(&q_semaphore);

  if (tracee)
  	up_tracee_put(tracee);
  if (ctx)
  	up_context_put(ctx);
}

void up_socket_init(struct up_socket* socket, u32 nlpid) {
  socket->nlpid = nlpid;
  socket->net_ns = current->nsproxy->net_ns;
  INIT_LIST_HEAD(&socket->question_list);
  rwlock_init(&socket->question_rwlock);
}

void up_socket_cleanup(struct up_socket* socket) {
  unsigned long flags;
  struct list_head *tmp;
  struct up_question *q;
  
  write_lock_irqsave(&socket->question_rwlock, flags);
  socket->nlpid = UP_NL_PID_INVALID;
  /* Wake up all sleeping threads, no matter whether we received
   * a response yet or not.
   * This is fine because when socket_cleanup is called the tracer is shutting down.
   *
   * Note that those threads will partially resume, but will be sleeping
   * inside q_unlink until we release the write lock here.
   */
  list_for_each(tmp, &socket->question_list) {
    q = list_entry(tmp, struct up_question, list);
    if (!q->response) {
      q->decision = UP_DECISION(KILL);
      up(&q->sem);
    }
  }
  write_unlock_irqrestore(&socket->question_rwlock, flags);
}

struct sk_buff *__up_nlmsg_prepare(size_t size, u32 nlpid, enum UP_CMD cmd,
				 	 struct up_nlhdr **nlhdr) {
  struct sk_buff *skb = NULL;
  skb = nlmsg_new(size, GFP_KERNEL);

  if (unlikely(!skb))
    goto out;

  *nlhdr = genlmsg_put(skb, nlpid, 0, &genl_family, 0, cmd);
  if (unlikely(!(*nlhdr))) {
    nlmsg_free(skb);
    skb = NULL;
    goto out;
  }

  /* zero-out the header */
  (*nlhdr)->context_id = 0;
  (*nlhdr)->pid = (*nlhdr)->tid = 0;

 out:
  return skb;
}

int up_nlmsg_send(struct sk_buff *skb, struct up_tracer *tracer) {
  struct up_tracer *t = up_tracer_get(tracer);
  struct nlmsghdr* nlh;
  struct genlmsghdr *genlhdr;
  struct up_nlhdr *uphdr;
  int rc = 0;

  if (up_nlmsg_headers(skb, &nlh, &genlhdr, &uphdr)) {
  	up_eprintk("up_nlmsg_headers failed.\n");
  	return -EINVAL;
  }

  if (unlikely(!t)) {
    rc = -ENOENT;
    up_eprintk("up_tracer_get failed, tracer@%p.\n", tracer);
    goto out;
  }

  if (unlikely(t->socket.nlpid == UP_NL_PID_INVALID)) {
	  rc = -EINVAL;
	  up_eprintk("socket.nlpid is invalid, tracer@%p\n", tracer);
	  up_tracer_put(tracer);
	  goto out;
  }

  up_dprintk(NETLINK, "Setting nlmsg_pid to %u\n", t->socket.nlpid);
  nlh->nlmsg_pid = t->socket.nlpid;
  genlmsg_end(skb, uphdr);
  rc = genlmsg_unicast(t->socket.net_ns, skb, t->socket.nlpid);
  if (rc < 0) {
  	up_eprintk("genlmsg_unicast failed: %d\n", rc);
  } else {
  	up_dprintk(NETLINK, "message sent to %u: %d\n", t->socket.nlpid, rc);
  }
  up_tracer_put(tracer);
 out:
  return rc;
}

enum UP_EV_DECISION __up_nlevent_send_single(struct sk_buff *skb, struct up_tracee *tracee,
		enum UP_EVENT ev, struct up_nl_response *response, struct task_struct *tsk) {
	struct up_tracee *t = up_tracee_get(tracee);
	enum UP_EV_DECISION decision = UP_DECISION(KILL);
	enum UP_EVENT_TYPE ev_type = UP_EV_TYPE(SKIP);

	if (unlikely(!t)) {
		up_eprintk("tracee is NULL.\n");
		goto out;
	}

	if (unlikely(!t->context)) {
		up_eprintk("t->context is NULL.\n");
		goto out;
	}

	if (unlikely(!skb)) {
		up_eprintk("skb is NULL.\n");
		goto out_put_tracee;
	}

	ev_type = up_context_wants_event(t->context, ev);

	if (response) {
		memset(response, 0, sizeof(struct up_nl_response));
	}

	if (ev_type == UP_EV_TYPE(SKIP)) {
		up_dprintk(NETLINK, "Skipping event %d.\n", ev);
		decision = UP_DECISION(ALLOW);
		kfree_skb(skb);
		goto out_put_tracee;
	} else {
		struct nlmsghdr *nl_hdr;
		struct genlmsghdr *genl_hdr;
		struct up_nlhdr *up_nlhdr;

		if (unlikely(up_nlmsg_headers(skb, &nl_hdr, &genl_hdr, &up_nlhdr))) {
			up_eprintk("up_nlmsg_headers failed.\n");
			decision = UP_DECISION(KILL);
			goto out_put_tracee;
		}

		nl_hdr->nlmsg_pid = t->tracer->socket.nlpid;
		up_nlhdr->context_id = t->context->id;

		if (ev_type == UP_EV_TYPE(QUESTION)){
			struct up_question *q = q_alloc(t);

			if (unlikely(!q)) {
				up_eprintk("q_alloc failed.\n");
				decision = UP_DECISION(KILL);
				goto out_put_tracee;
			}

			if (unlikely(q_setup(q, t, t->context, response, tsk))) {
				up_eprintk("q_setup failed.\n");
				decision = UP_DECISION(KILL);
				kfree_skb(skb);
				q_free(q);
				goto out_put_tracee;
			}
			genl_hdr->cmd = UPOLICY_COMMAND(QUESTION);
			up_nlhdr->pid = q->pid;
			up_nlhdr->tid = q->tid;
			q_link(t->context->tracer, q);
			decision = q_send(q, skb, t->context->tracer, response);
			q_free(q);
		} else {
			/* type == UP_EV_TYPE(NOTIFICATION) */
			genl_hdr->cmd = UPOLICY_COMMAND(NOTIFICATION);
			if (unlikely(up_nlmsg_send(skb, t->context->tracer) < 0)) {
		  	/* Sending the notification failed. */
				up_eprintk("up_nlmsg_send failed.\n");
				decision = UP_DECISION(KILL);
			}
			else {
		  	decision = UP_DECISION(ALLOW);
			}
		}
	}

out_put_tracee:
	up_tracee_put(t);
out:
  return decision;
}

enum UP_EV_DECISION __up_nlevent_send(struct sk_buff *skb,
		struct up_tracee *tracee, enum UP_EVENT ev, struct up_nl_response *response,
		struct task_struct *tsk, up_pre_send_cb_t cb, void *cb_data) {
	enum UP_EV_DECISION decision = UP_DECISION(KILL);
	struct up_tracee *t = up_tracee_get(tracee);
	struct up_question *q = NULL;
	struct up_tracee *t_current = NULL;

	if (unlikely(!t))
		goto out;

	/*
	 * fast-path check: does the combined mask indicate that either this context
	 * or any parent context actually wants the event as either notification or question.
	 */
	if (!(t->context->combined_mask & upolicy_ev_flag(ev))) {
		up_dprintk(NETLINK, "combined mask does not contain event %d, fast-path ALLOW.\n", ev);
		up_tracee_put(t);
		kfree_skb(skb);
		return UP_DECISION(ALLOW);
	}

	if (unlikely(!skb))
		goto out_put_tracee;

	q = q_alloc(t);

	if (unlikely(!q))
		goto out_put_tracee;

	if (response) {
		memset(response, 0, sizeof(struct up_nl_response));
	}

	t_current = t;
	decision = UP_DECISION(ALLOW);

	while(t_current && decision == UP_DECISION(ALLOW)) {
		struct up_tracer *tracer = t_current->tracer;
		struct up_context *ctx = t_current->context;
		enum UP_EVENT_TYPE ev_type = up_context_wants_event(ctx, ev);
		up_dprintk(NETLINK,
				"Preparing event for tracee@%p,tracer@%p,ctx@%p,orig_tracer@%p\n",
				t, tracer, ctx, t->tracer);

		if (ev_type != UP_EV_TYPE(SKIP)) {
			struct sk_buff *skb_current = skb_copy(skb, GFP_KERNEL);
			struct nlmsghdr *nl_hdr;
			struct genlmsghdr *genl_hdr;
			struct up_nlhdr *up_nlhdr;

			if (cb) {
				int rc = 0;
				if ((rc = cb(skb_current, tracee, tracer, cb_data))) {
					up_eprintk("Pre-Send-Callback %p returned error %d.\n",
							cb, rc);
					decision = UP_DECISION(KILL);
					kfree_skb(skb_current);
					goto out_free_question;
				}
			}

			if (unlikely(up_nlmsg_headers(skb_current, &nl_hdr, &genl_hdr, &up_nlhdr))) {
				decision = UP_DECISION(KILL);
				kfree_skb(skb_current);
				goto out_free_question;
			}

			nl_hdr->nlmsg_pid = tracer->socket.nlpid;
			up_dprintk(NETLINK, "Set nlmsg_pid to %u\n", tracer->socket.nlpid);

			/* Always call q_setup so we get normalized PID/TID values for use in both cases. */
			if (unlikely(q_setup(q, t, ctx, response, tsk))) {
				decision = UP_DECISION(KILL);
				kfree_skb(skb_current);
				goto out_free_question;
			}
			up_nlhdr->context_id = ctx->id;
			up_nlhdr->pid = q->pid;
			up_nlhdr->tid = q->tid;

			if (ev_type == UP_EV_TYPE(QUESTION)) {
				/* Question */
				genl_hdr->cmd = UPOLICY_COMMAND(QUESTION);
				q_link(tracer, q);
				decision = q_send(q, skb_current, tracer, response);
			} else {
				/* Notification */
				genl_hdr->cmd = UPOLICY_COMMAND(NOTIFICATION);
				if (unlikely(up_nlmsg_send(skb_current, tracer) < 0)) {
					/* Sending the notification failed. */
					kfree_skb(skb_current);
					decision = UP_DECISION(KILL);
				}
				else {
					decision = UP_DECISION(ALLOW);
				}
			}
		}
		t_current = t_current->parent_tracee;
	}

	out_free_question:
	q_free(q);
	out_put_tracee:
	up_tracee_put(t);
	kfree_skb(skb);
	out:
	return decision;
}

void up_nl_response_free(struct up_nl_response *response) {
	if (response->skb) {
		kfree_skb(response->skb);
		response->skb = NULL;
	}

	if (response->info.attrs) {
		kfree(response->info.attrs);
		response->info.attrs = NULL;
	}
	memset(&response->info, 0, sizeof(struct genl_info));
}
