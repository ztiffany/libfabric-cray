/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2015 Los Alamos National Security, LLC. Allrights reserved.
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "gnix.h"
#include "gnix_util.h"

#define BUF_SIZE 256

/*
 * get gni nic addr from AF_INET  ip addr, also return local device id on same
 *subnet
 * as the input ip_addr.
 *
 * returns 0 if ipogif entry found
 * otherwise  -errno
 */
static int gnixu_get_pe_from_ip(const char *ip_addr, uint32_t *gni_nic_addr)
{
	int scount;
	/* return this if no ipgogif for this ip-addr found */
	int ret = -FI_ENODATA;
	FILE *fd = NULL;
	char line[BUF_SIZE], *tmp;
	char dummy[64], iface[64], fnd_ip_addr[64];
	char mac_str[64];
	int w, x, y;

	fd = fopen("/proc/net/arp", "r");
	if (fd == NULL) {
		return -errno;
	}

	if (fd == NULL) {
		return -errno;
	}

	while (1) {
		tmp = fgets(line, BUF_SIZE, fd);
		if (!tmp) {
			break;
		}

		/*
		 * check for a match
		 */
		if ((strstr(line, ip_addr) != NULL) &&
		    (strstr(line, "ipogif") != NULL)) {
			ret = 0;
			scount = sscanf(line, "%s%s%s%s%s%s", fnd_ip_addr,
					dummy, dummy, mac_str, dummy, iface);
			if (scount != 6) {
				ret = -EIO;
				goto err;
			}

			/*
			 * check exact match of ip addr
			 */
			if (!strcmp(fnd_ip_addr, ip_addr)) {

				scount =
				    sscanf(mac_str, "00:01:01:%02x:%02x:%02x",
					   &w, &x, &y);
				if (scount != 3) {
					ret = -EIO;
					goto err;
				}

				/*
				 * mysteries of XE/XC mac to nid mapping, see
				 * nid2mac in xt sysutils
				 */
				*gni_nic_addr = (w << 16) | (x << 8) | y;
				ret = FI_SUCCESS;
				break;
			}
		}
	}

err:
	fclose(fd);
	return ret;
}

/*
 * gnixu name resolution function,
 */
int gnix_resolve_name(const char *node, const char *service,
		      struct gnix_ep_name *resolved_addr)
{
	int s, rc = 0;
	struct addrinfo *result, *rp;
	uint32_t pe = -1;
	struct addrinfo hints;
	struct sockaddr_in *sa;

	if (resolved_addr == NULL) {
		return -FI_EINVAL;
	}

	memset(&hints, 0, sizeof hints);

	/* don't support IPv6 on XC internal networks */
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_CANONNAME;

	s = getaddrinfo(node, "domain", &hints, &result);
	if (s != 0) {
		fprintf(stderr, PFX "getaddrinfo: %s\n", gai_strerror(s));
		rc = -FI_EINVAL;
		goto err;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		assert(rp->ai_addr->sa_family == AF_INET);
		sa = (struct sockaddr_in *)rp->ai_addr;
		rc = gnixu_get_pe_from_ip(inet_ntoa(sa->sin_addr), &pe);
		if (!rc) {
			break;
		}
	}

	if (pe == -1) {
		rc = -FI_EADDRNOTAVAIL;
		goto err;
	}

	/*
	 * try to fill in the gnix_ep_name struct with what we can now
	 */
	memset(resolved_addr, 0, sizeof(struct gnix_ep_name));

	resolved_addr->gnix_addr.device_addr = pe;
	/* TODO: have to write a nameserver to get this info */
	resolved_addr->gnix_addr.cdm_id = 0;
	/* TODO: likely depend on service? */
	resolved_addr->name_type = 0;
	freeaddrinfo(result);
err:
	return rc;
}
