/* examples/example_exec.c
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
#include <unistd.h>

#include <upolicy/core.h>
#include <upolicy/context.h>
#include <upolicy/netlink.h>

static upolicy_decision exec_handler(struct upolicy_event_info *info, const char *path) {
	printf("EXEC event: path=%s\n", path);
	return UP_DECISION(ALLOW);
}

static struct upolicy_ops notify_ops = {
		.exec = exec_handler,
};

static struct upolicy_ops question_ops = {

};

static struct upolicy_context ctx = {
  .question_ops = &question_ops,
  .notify_ops = &notify_ops,
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
	char *const exec_argv[2] = {"/bin/ls", NULL};
	int rc = 0;
	printf("CHILD: running, about to execv()...\n");
    rc = execv(exec_argv[0], exec_argv);
	if (rc) {
		printf("CHILD: exec() failed: %s (%d)\n", strerror(errno), errno);
		return errno;
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

