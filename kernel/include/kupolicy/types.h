/* types.h
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
#ifndef _KUPOLICY_TYPES_H
#define _KUPOLICY_TYPES_H

#include <linux/types.h>

#ifndef __KERNEL__
#include <sys/types.h>
#endif /* !__KERNEL__ */

#ifdef __ECLIPSE_HACK
#include <generated/autoconf.h>
#endif /* __ECLIPSE_HACK */

/*
 * up_ctx_id - upolicy context id type
 *
 * 16 bits allow for up to 65536
 * contexts per tracer.
 */
typedef __u16 up_ctx_id;

/*
 * Context ID for unknown context (reserved).
 * This is also used as response for the WANT_TRACE
 * event when the tracee should not be traced.
 */
#define UP_CTX_ID_UNKNOWN 0x0

/*
 * Maximum context ID value.
 */
#define UP_CTX_ID_MAX ((up_ctx_id)			\
		       (1 << (sizeof(up_ctx_id)*8))-1)

/*
 * Event mask type.
 * 64bit, which means we can handle up to 64 
 * different events (for now).
 */
typedef __u64 up_event_mask;

#endif /* _KUPOLICY_TYPES_H */
