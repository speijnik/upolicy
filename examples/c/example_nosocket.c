/* examples/example_nosocket.c
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <upolicy/core.h>
#include <upolicy/context.h>
#include <upolicy/netlink.h>

static upolicy_decision socket_create_handler(struct upolicy_event_info *info,
					 int family, int type, int protocol) {
  printf("socket(%d,%d,%d) called by child PID=%d,TID=%d,CTX=%d.\n",
	 family, type, protocol, info->pid, info->tid, 
	 info->ctx ? info->ctx->id : 0);
  return UP_DECISION(DENY);
}

static struct upolicy_ops question_ops = {
  .socket_create = socket_create_handler,
};

static struct upolicy_context ctx = {
  .question_ops = &question_ops,
};

int main(int argc, char **argv) {
  int rc = upolicy_init();
  pid_t pid;

  if(getenv("UP_EX_DEBUG"))
    up_debug_flag_set(UPOLICY_DEBUG_FLAG(NETLINK));

  if (rc < 0) {
    fprintf(stderr, "upolicy_init() failed: %s [%d]\n", strerror(rc*-1),
	    rc);
    return rc;
  } 

  rc = upolicy_context_create(&ctx);
  if (rc) {
    fprintf(stderr, "upolicy_context_created() failed: %s [%d]\n", 
	    strerror(rc*-1), rc);
    return rc;
  }
  printf("Context created, ID=%u\n", ctx.id);

  printf("Forking into context...\n");
  pid = upolicy_context_fork(&ctx);
  
  if (pid == 0) {
    int fd = 0;
    printf("Child running, PID=%d\n", getpid());
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      printf("OK: socket() failed: %s (%d).\n", strerror(errno), errno);
    } else {
      printf("FAIL: socket() did not fail.\n");
    }
    return 0;
  } 

  printf("Child with PID %d running in context ID=%u\n", pid, ctx.id);
  upolicy_join();
  printf("All childs exited.\n");

  rc = upolicy_context_destroy(&ctx);
  if (rc) {
    fprintf(stderr, "upolicy_context_destroy() failed: %s [%d]\n",
	    strerror(rc * -1), rc);
    return rc;
  }
  printf("Context destroyed.\n");
  
  return rc;
}
