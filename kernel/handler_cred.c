/* handler_cred.c
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
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/types.h>

#include <kupolicy/handler.h>
#include <kupolicy/tracer.h>
#include <kupolicy/upolicy.h>

void up_cred_free(struct cred *cred) {
  struct upolicy* up = NULL;

  if (unlikely((up = cred_upolicy(cred)) != NULL)) {
    up_free(cred);
  }
}

int up_cred_prepare(struct cred *new, const struct cred *old,
			 gfp_t gfp)
{
  if (unlikely(cred_upolicy(old))) {
  	up_dprintk(HANDLER_CRED, "new=%p, old=%p\n", new, old);
    return up_copy(new, old, gfp);
  }
  return 0;
}

void up_cred_transfer(struct cred *new, const struct cred *old) {
  up_dprintk(HANDLER_CRED, "new=%p,old=%p\n", new, old);
  /* TODO: needs to be implemented. */
  new->security = old->security;
}
