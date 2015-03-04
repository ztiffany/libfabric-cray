/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 * Copyright (c) 2015 Los Alamos National Security, LLC. Allrights reserved.
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

//
// Address vector common code
//
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "gnix.h"
#include "gnix_util.h"

static int gnix_av_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
			  size_t *addrlen)
{
	struct gnix_fid_ep *int_av;

	int_av = container_of(av, struct gnix_fid_ep, av);

	if (int_av->type == FI_AV_TABLE) {

	} else {

	}

	return -FI_ENOSYS;
}

static int gnix_av_insert(struct fid_av *av, const void *addr, size_t count,
			  fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	return -FI_ENOSYS;
}

static int gnix_av_remove(struct fid_av *av, fi_addr_t *fi_addr, size_t count,
			  uint64_t flags)
{
	return -FI_ENOSYS;
}

int gnix_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
			struct fid_av **av, void *context)
{
	return -FI_ENOSYS;
}

static const char *gnix_av_straddr(struct fid_av *av, const void *addr,
				   char *buf, size_t *len)
{
	char int_buf[64];
	int size;

	size =
	    snprintf(int_buf, sizeof(int_buf), "0x%08" PRIx32 ":0x%08" PRIx32,
		     ((struct gnix_address *) addr)->device_addr,
		     ((struct gnix_address *) addr)->cdm_id);

	snprintf(buf, *len, "%s", int_buf);
	*len = size + 1;

	return buf;
}

static struct fi_ops_av gnix_av_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = gnix_av_insert,
	.remove = gnix_av_remove,
	.lookup = gnix_av_lookup,
	.straddr = gnix_av_straddr
};
