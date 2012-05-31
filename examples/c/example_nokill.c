/* examples/example_nokill.c
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
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <upolicy/core.h>
#include <upolicy/context.h>
#include <upolicy/netlink.h>

static upolicy_decision kill_handler(struct upolicy_event_info *info, pid_t pid, 
				int signo) {
  printf("[DENY] PID=%d sent signal=%d to pid=%d.\n", info->pid, signo, pid);
  return UP_DECISION(DENY);
}

static struct upolicy_ops question_ops = {
  .kill = kill_handler,
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

  printf("Creating context...\n");
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
    pid_t child_child = 0;
    int rc = 0;
    printf("IN CHILD!\n");
    child_child = fork();
    if (child_child == 0) {
      printf("CHILD_CHILD running.\n");
      sleep(5);
      printf("CHILD_CHILD exiting...\n");
      return 0;
    } else {
      int status = 0;
      printf("Trying to send signal to child_child=%d\n", child_child);
      status = kill(child_child, SIGTERM);
      if (status) {
	printf("kill() failed: %s (%d)\n", strerror(errno), errno);
      }
      printf("Waiting for child_child to exit.\n");
      waitpid(child_child, &status, 0);
      if (WIFSIGNALED(status)) {
	printf("child_child was killed by signal: %d\n", WTERMSIG(status));
      } else {
	printf("child_child exited normally.\n");
      }
    }
    printf("[CHILD] Trying to kill tracer...\n");
    rc = kill(getppid(), SIGTERM);
    if (rc) {
      printf("kill() failed: %s (%d)\n", strerror(errno), errno);
    } else {
      printf("BUG: tracer successfully killed!\n");
    }
    return 0;
  } 

  printf("Child with PID %d running in context ID=%u\n", pid, ctx.id);
  upolicy_join();

  rc = upolicy_context_destroy(&ctx);
  if (rc) {
    fprintf(stderr, "upolicy_context_destroy() failed: %s [%d]\n",
	    strerror(rc * -1), rc);
    return rc;
  }
  printf("Context destroyed.\n");
   
  return rc;
}
