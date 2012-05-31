/* examples/example_socket_nolisten.c
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

static upolicy_decision socket_listen_handler(struct upolicy_event_info *info,
					 int family, struct sockaddr *sa,
					 int addrlen) {
  printf("Tracee PID=%d,TID=%d,CTX=%d tried to listen on socket.\n", 
	 info->pid, info->tid, info->ctx ? info->ctx->id : 0);
  printf("Socket: family=%d,addrlen=%d,address=%p\n", family, addrlen, sa);

  return UP_DECISION(DENY);
}

static struct upolicy_ops question_ops = {
  .socket_listen = socket_listen_handler,
};

static struct upolicy_context ctx = {
  .question_ops = &question_ops,
};

int main(int argc, char **argv) {
  int rc = 0;
  pid_t pid;

  if(getenv("UP_EX_DEBUG"))
	up_debug_flag_set(UPOLICY_DEBUG_FLAG(NETLINK));

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <command>\n", argv[0]);
    return 1;
  }

  rc = upolicy_init();
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
    printf("Child running, PID=%d\n", getpid());
    rc = execv(argv[1], &argv[1]);
    if (rc) {
      printf("execv(%s,%p) failed: %s (%d)\n", argv[1], &argv[2], 
	     strerror(errno), errno);
      return 1;
    }
    return 0;
  } 

  printf("Waiting for child to exit...\n");
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
