/* examples/example_localhost_only.c
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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <upolicy/core.h>
#include <upolicy/context.h>
#include <upolicy/netlink.h>

static upolicy_decision check_loopback_addr(const char *action, int family,
		struct sockaddr *address, int addrlen) {
  upolicy_decision decision = UP_DECISION(ALLOW);
  char addr_str[256];

  if (family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in*) address;

    if (inet_ntop(family, &sin->sin_addr, addr_str, sizeof(addr_str)) == NULL) {
	  printf("<action:%s> [FAIL ] inet_ntop failed: %s (%d)\n", action,
			  strerror(errno), errno);
	  return UP_DECISION(DENY);
    }

    if ((sin->sin_addr.s_addr & 0xff) != 0x7f) {
      decision = UP_DECISION(DENY);
      printf("<action:%s> [DENY ] %s:%d\n", action, addr_str, sin->sin_port);
    } else {
      printf("<action:%s> [ALLOW] %s:%d\n", action, addr_str, sin->sin_port);
    }
  } else if (family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6*) address;

    int i = 0;
    int ok = 1;

    if (inet_ntop(family, &sin6->sin6_addr, addr_str, sizeof(addr_str)) == NULL) {
	  printf("<action:%s> [FAIL ] inet_ntop failed: %s (%d)\n", action,
			  strerror(errno), errno);
	  return UP_DECISION(DENY);
	}

    for(i = 0; i < 15; i++) {
      if (sin6->sin6_addr.s6_addr[i] != 0) {
	ok = 0;
	break;
      }
    }
    if (ok) {
      if (sin6->sin6_addr.s6_addr[15] != 1)
    	  ok = 0;
    }

    if (!ok) {
      decision = UP_DECISION(DENY);
      printf("<action:%s> [DENY] IPv6=[%s]:%d\n", action, addr_str,
    		  sin6->sin6_port);
    } else {
    	printf("<action:%s> [ALLOW] IPv6=[%s]:%d\n", action, addr_str,
    			sin6->sin6_port);
    }
  }

  return decision;
}

static upolicy_decision socket_bind_handler(struct upolicy_event_info *info,
				       int family, struct sockaddr *address,
				       int addrlen) {
  if (family != AF_INET && family != AF_INET6) {
    /* Only check AF_INET and AF_INET6 */
    return UP_DECISION(ALLOW);
  }

  return check_loopback_addr("bind", family, address, addrlen);
}

static upolicy_decision socket_listen_handler(struct upolicy_event_info *info,
					 int family, struct sockaddr *address,
					 int addrlen) {
  if (family != AF_INET && family != AF_INET6) {
    return UP_DECISION(ALLOW);
  }
  return check_loopback_addr("listen", family, address, addrlen);
}

static upolicy_decision socket_connect_handler(struct upolicy_event_info *info,
					  int family, 
					  struct sockaddr *local_address,
					  int local_addrlen,
					  struct sockaddr *remote_address,
					  int remote_addrlen) {
  if (family != AF_INET && family != AF_INET6) {
    return UP_DECISION(ALLOW);
  }
  return check_loopback_addr("connect", family, remote_address, remote_addrlen);
}

static struct upolicy_ops question_ops = {
  .socket_bind = socket_bind_handler,
  .socket_connect = socket_connect_handler,
  .socket_listen = socket_listen_handler,
};

static struct upolicy_context ctx = {
  .question_ops = &question_ops,
};

int main(int argc, char **argv) {
  int rc = 0;
  pid_t pid;

  if(getenv("UP_EX_DEBUG"))
    up_debug_flags_set(UPOLICY_DEBUG_FLAG(NETLINK), UPOLICY_DEBUG_FLAG(CONTEXT));

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
