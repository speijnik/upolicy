/* netlink.h
 *
 * Copyright (C) 2012 Stephan Peijnik <stephan@peijnik.at>
 *
 * This file is part of upolicy.
 *
 *  upolicy is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  upolicy is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with upolicy.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef UPOLICY_NETLINK_H
#define UPOLICY_NETLINK_H

#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <kupolicy/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct upolicy_event_info;

/**
 * @defgroup Netlink Netlink
 * @{
 */

/**
 * Allocate and initialize netlink message
 *
 * @param up_nlhdr Pointer to struct upnlhdr pointer
 * @param cmd Command
 * @returns Pointer to newly allocated message on success, NULL on error
 */
struct nl_msg *upolicy_msg_init(struct up_nlhdr **nlhdr, enum UP_CMD cmd);

/**
 * Destroy a previously allocated netlink message and all data associated with it.
 *
 * @param msg Netlink message previous allocated with @ref upolicy_msg_init
 */
void upolicy_msg_destroy(struct nl_msg *msg);

/**
 * Send a netlink message synchronously.
 * Synchronously in this case means that the function will block until
 * the kernel has acknowledged that it received the message.
 *
 * @param msg Netlink message previously allocated with @ref upolicy_msg_init
 * @returns Negative value on failure, positive value (including 0) on success
 */
int upolicy_msg_send_sync(struct nl_msg *msg);

/**
 * Send a netlink message.
 * In contrast to @ref upolicy_msg_send_sync this function will *not* block
 * until the kernel has acknowledged that it received the message.
 *
 * @param msg Netlink message previously allocated with @ref upolicy_msg_init
 * @returns Negative value on failure, positive value (including 0) on success
 */
int upolicy_msg_send(struct nl_msg *msg);

/**
 * Joins all running tracees.
 *
 * This function will block until all tracees (that means all traced processes,
 * not just the immediate children) have exited.
 *
 * @returns 0 on success, negative value on error.
 */
int upolicy_join(void);

/**
 * Sends event decision to kernel.
 *
 * @param info Event info
 * @param decision Decision
 *
 * @returns 0 on success, negative value on error
 *
 */
int upolicy_event_decide(struct upolicy_event_info *info, upolicy_decision decision);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UPOLICY_NETLINK_H */
