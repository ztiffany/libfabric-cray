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

/*
 * CQ common code
 */
#include <stdlib.h>
#include <string.h>

#include "gnix.h"
#include "gnix_util.h"


static int gnix_cq_close(fid_t fid)
{
	struct gnix_fid_cq *cq;

	cq = container_of(fid, struct gnix_fid_cq, cq_fid);
	if (atomic_get(&cq->ref_cnt) != 0)
		return -FI_EBUSY;

	atomic_dec(&cq->domain->ref_cnt);

#if 0
	while (!slist_empty(&cq->free_list)) {
		entry = slist_remove_head(&cq->free_list);
		item = container_of(entry, struct gnix_cq_event, list_entry);
		free(item);
	}
#endif

	free(cq);

	return FI_SUCCESS;
}

static struct fi_ops gnix_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = gnix_cq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
};

static ssize_t gnix_cq_readfrom(struct fid_cq *cq, void *buf, size_t count,
				fi_addr_t *src_addr)
{
	return -FI_ENOSYS;
}

static ssize_t gnix_cq_read(struct fid_cq *cq, void *buf, size_t count)
{
	return gnix_cq_readfrom(cq, buf, count, NULL);
}

static ssize_t gnix_cq_readerr(struct fid_cq *cq, struct fi_cq_err_entry *buf,
			       uint64_t flags)
{
#if 0
	struct gnix_fid_cq *cq_priv;

	cq_priv = container_of(cq, struct gnix_fid_cq, cq);

	if (cq_priv->pending_error) {
		memcpy(buf, &cq_priv->pending_error->cqe, sizeof(*buf));
		free(cq_priv->pending_error);
		cq_priv->pending_error = NULL;
		return sizeof(*buf);
	}
#endif

	return -FI_ENOSYS;
}

static ssize_t gnix_cq_sreadfrom(struct fid_cq *cq, void *buf, size_t count,
				 fi_addr_t *src_addr, const void *cond,
				 int timeout)
{
	return -FI_ENOSYS;
}

static ssize_t gnix_cq_sread(struct fid_cq *cq, void *buf, size_t count,
			     const void *cond, int timeout)
{
	return gnix_cq_sreadfrom(cq, buf, count, NULL, cond, timeout);
}

static const char *gnix_cq_strerror(struct fid_cq *cq, int prov_errno,
				    const void *prov_data, char *buf,
				    size_t len)
{
	return NULL;
}


static struct fi_ops_cq gnix_cq_ops = {
	.size = sizeof(struct fi_ops_cq),
	.read = gnix_cq_read,
	.readfrom = gnix_cq_readfrom,
	.readerr = gnix_cq_readerr,
	.write = fi_no_cq_write,
	.writeerr = fi_no_cq_writeerr,
	.sread = gnix_cq_sread,
	.sreadfrom = gnix_cq_sreadfrom,
	.strerror = gnix_cq_strerror,
};

int gnix_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context)
{
	int ret = FI_SUCCESS;
	struct gnix_fid_domain *domain_priv;
	struct gnix_fid_cq *cq_priv;
	size_t entry_size = sizeof(struct fi_cq_entry); /* the default */
	uint64_t cq_flags = 0UL;

	/*
	 * appears that a pointer to an fi_cq_attr must be supplied
	 * by the application, undocumented rule? Fix up fi_cq.3.md.
	 */
	if (attr == NULL)
		return -FI_EINVAL;

	domain_priv = container_of(domain, struct gnix_fid_domain, domain_fid);

	/*
	 * process cq attr atributes
	 */

	/*
	 * GNI prov doesn't support this
	 */
	if (attr->flags & FI_WRITE) {
		ret = -FI_ENOSYS;
		goto err;
	}

	cq_flags = attr->flags;

	switch (attr->format) {
	/*
	 * default CQE format for gni provider is context
	 */
	case FI_CQ_FORMAT_UNSPEC:
		attr->format = FI_CQ_FORMAT_CONTEXT;
		entry_size = sizeof(struct fi_cq_entry);
		break;
	case FI_CQ_FORMAT_CONTEXT:
		entry_size = sizeof(struct fi_cq_entry);
		break;

	case FI_CQ_FORMAT_MSG:
		entry_size = sizeof(struct fi_cq_msg_entry);
		break;

	case FI_CQ_FORMAT_DATA:
		entry_size = sizeof(struct fi_cq_data_entry);
		break;

	case FI_CQ_FORMAT_TAGGED:
		entry_size = sizeof(struct fi_cq_tagged_entry);
		break;

	default:
		ret = -FI_EINVAL;
		goto err;
	}

	switch (attr->wait_obj) {
	case FI_WAIT_NONE:
	case FI_WAIT_UNSPEC:
		break;

	/*
	 * TODO: need to implement various blocking forms of CQ
	 */
	case FI_WAIT_SET:
	case FI_WAIT_FD:
	case FI_WAIT_MUTEX_COND:
	default:
		ret = -FI_ENOSYS;
		goto err;
	}

	/*
	 * TODO: may want to have a default CQ size associated with the domain
	 */

	cq_priv = (struct gnix_fid_cq *) calloc(1, sizeof(*cq_priv));
	if (!cq_priv) {
		ret = -FI_ENOMEM;
		goto err;
	}

	cq_priv->domain = domain_priv;
	cq_priv->format = attr->format;
	cq_priv->entry_size = entry_size;
	cq_priv->flags = cq_flags;
	atomic_set(&cq_priv->ref_cnt, 1);

	cq_priv->cq_fid.fid.fclass = FI_CLASS_CQ;
	cq_priv->cq_fid.fid.context = context;
	cq_priv->cq_fid.fid.ops = &gnix_fi_ops;
	cq_priv->cq_fid.ops = &gnix_cq_ops;

	slist_init(&cq_priv->event_queue);
	slist_init(&cq_priv->free_list);

#if 0
#define PSMX_FREE_LIST_SIZE	64
	for (i = 0; i < PSMX_FREE_LIST_SIZE; i++) {
		event = calloc(1, sizeof(*event));
		if (!event) {
			PSMX_WARN("%s: out of memory.\n", __func__);
			exit(-1);
		}
		slist_insert_tail(&event->list_entry, &cq_priv->free_list);
	}
#endif

	*cq = &cq_priv->cq_fid;
	return ret;
err:
	return ret;
}
