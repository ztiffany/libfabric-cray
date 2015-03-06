/*
 * Copyright (c) 2015 Cray Inc.  All rights reserved.
 * Copyright (c) 2015 Los Alamos National Security, LLC. All rights reserved.
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

#include "gnix.h"

/*
 * Retrieve the local endpoint address.
 *
 * addrlen: Should indicate the size of the addr buffer. On output will contain
 *     the size necessary to copy the proper address structure.
 *
 * addr: Pointer to memory that will conatin the address structure. Should be
 *     allocated and of size addrlen. If addrlen is less than necessary to copy
 *     the proper address structure then addr will contain a truncated address.
 *
 * return: FI_SUCCESS or negative error value.
 */
static int gnix_getname(fid_t fid, void *addr, size_t *addrlen)
{
	struct gnix_ep_name name = {{0}};
	struct gnix_fid_ep *ep;
	int ret = FI_SUCCESS;
	size_t copy_len;

	copy_len = sizeof(struct gnix_ep_name);

	/*
	 * If addrlen is less than the size necessary then continue copying with
	 * truncation and return error value -FI_ETOOSMALL.
	 */
	if (*addrlen < copy_len) {
		copy_len = *addrlen;
		*addrlen = sizeof(struct gnix_ep_name);
		ret = -FI_ETOOSMALL;
	}

	if (!addr) {
		ret = -FI_ETOOSMALL;
		goto err;
	}

	ep = container_of(fid, struct gnix_fid_ep, ep_fid.fid);
	if (!ep || !ep->nic) {
		ret = -FI_EINVAL;
		goto err;
	}

	/*
	 * Retrieve the cdm_id & device_addr from the gnix_nic structure.
	 */
	name.gnix_addr.cdm_id = ep->nic->cdm_id;
	name.gnix_addr.device_addr = ep->nic->device_addr;
	name.cookie = ep->domain->cookie;

	memcpy(addr, &name, copy_len);

err:
	return ret;
}

struct fi_ops_cm gnix_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.getname = gnix_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown
};
