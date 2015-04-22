/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
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

/*
 * CQ common code
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "gnix.h"

/*******************************************************************************
 * Function pointer for filling specific entry format type.
 ******************************************************************************/
typedef void (*fill_entry)(void *cq_entry, void *op_context, uint64_t flags,
			   size_t len, void *buf, uint64_t data, uint64_t tag);

/*******************************************************************************
 * Forward declarations for filling functions.
 ******************************************************************************/
static void fill_cq_entry(void *cq_entry, void *op_context, uint64_t flags,
			  size_t len, void *buf, uint64_t data, uint64_t tag);
static void fill_cq_msg(void *cq_entry, void *op_context, uint64_t flags,
			size_t len, void *buf, uint64_t data, uint64_t tag);
static void fill_cq_data(void *cq_entry, void *op_context, uint64_t flags,
			size_t len, void *buf, uint64_t data, uint64_t tag);
static void fill_cq_tagged(void *cq_entry, void *op_context, uint64_t flags,
			size_t len, void *buf, uint64_t data, uint64_t tag);

/*******************************************************************************
 * Forward declarations for ops structures.
 ******************************************************************************/
static const struct fi_ops gnix_cq_fi_ops;
static const struct fi_ops_cq gnix_cq_ops;

/*******************************************************************************
 * Size array corresponding format type to format size.
 ******************************************************************************/
static const size_t const format_sizes[] = {
	[FI_CQ_FORMAT_UNSPEC]  = sizeof(GNIX_CQ_DEFAULT_FORMAT),
	[FI_CQ_FORMAT_CONTEXT] = sizeof(struct fi_cq_entry),
	[FI_CQ_FORMAT_MSG]     = sizeof(struct fi_cq_msg_entry),
	[FI_CQ_FORMAT_DATA]    = sizeof(struct fi_cq_data_entry),
	[FI_CQ_FORMAT_TAGGED]  = sizeof(struct fi_cq_tagged_entry)
};

static const fill_entry const fill_function[] = {
	[FI_CQ_FORMAT_UNSPEC]  = fill_cq_entry,
	[FI_CQ_FORMAT_CONTEXT] = fill_cq_entry,
	[FI_CQ_FORMAT_MSG]     = fill_cq_msg,
	[FI_CQ_FORMAT_DATA]    = fill_cq_data,
	[FI_CQ_FORMAT_TAGGED]  = fill_cq_tagged
};

/*******************************************************************************
 * Internal helper functions
 ******************************************************************************/
static struct gnix_cq_entry *alloc_cq_entry(size_t size)
{
	struct gnix_cq_entry *entry = malloc(sizeof(*entry));

	if (!entry) {
		GNIX_ERR(FI_LOG_CQ, "out of memory\n");
		goto err;
	}

	GNIX_INFO(FI_LOG_CQ, "generating entry of size %d\n", size);
	entry->the_entry = malloc(size);
	if (!entry->the_entry) {
		GNIX_ERR(FI_LOG_CQ, "out of memory\n");
		goto cleanup;
	}

	return entry;

cleanup:
	free(entry);
	entry = NULL;
err:
	return entry;
}


static void fill_cq_entry(void *cq_entry, void *op_context, uint64_t flags,
			  size_t len, void *buf, uint64_t data, uint64_t tag)
{
	struct fi_cq_entry *entry = cq_entry;

	entry->op_context = op_context;
}

static void fill_cq_msg(void *cq_entry, void *op_context, uint64_t flags,
			size_t len, void *buf, uint64_t data, uint64_t tag)
{
	struct fi_cq_msg_entry *entry = cq_entry;

	entry->op_context = op_context;
	entry->flags = flags;
	entry->len = len;
}

static void fill_cq_data(void *cq_entry, void *op_context, uint64_t flags,
			 size_t len, void *buf, uint64_t data, uint64_t tag)
{
	struct fi_cq_data_entry *entry = cq_entry;

	entry->op_context = op_context;
	entry->flags = flags;
	entry->len = len;
	entry->buf = buf;
	entry->data = data;
}

static void fill_cq_tagged(void *cq_entry, void *op_context, uint64_t flags,
			   size_t len, void *buf, uint64_t data, uint64_t tag)
{
	struct fi_cq_tagged_entry *entry = cq_entry;

	entry->op_context = op_context;
	entry->flags = flags;
	entry->buf = buf;
	entry->data = data;
	entry->tag = tag;
}

static inline void cq_enqueue(struct gnix_fid_cq *cq,
			      struct gnix_cq_entry *event)
{
	if (!cq || !event)
		return;

	fastlock_acquire(&cq->lock);

	slist_insert_tail(&event->item, &cq->ev_queue);

	if (cq->wait)
		_gnix_signal_wait_obj(cq->wait);

	fastlock_release(&cq->lock);
}

static ssize_t cq_dequeue(struct gnix_fid_cq *cq, void *buf, size_t count,
			  fi_addr_t *src_addr)
{
	struct gnix_cq_entry *event;
	ssize_t read_count = 0;

	if (slist_empty(&cq->ev_queue))
		return -FI_EAGAIN;

	fastlock_acquire(&cq->lock);

	GNIX_INFO(FI_LOG_CQ, "Attempting to dequeue %d items.\n",
		  count);

	while (count--) {
		event = container_of(slist_remove_head(&cq->ev_queue),
				     struct gnix_cq_entry,
				     item);

		assert(buf);
		assert(event->the_entry);
		memcpy(buf, event->the_entry, cq->entry_size);
		slist_insert_tail(&event->item, &cq->ev_free);

		buf += cq->entry_size;
		src_addr++;

		read_count++;
	}

	fastlock_release(&cq->lock);

	return read_count;
}

static int verify_cq_attr(struct fi_cq_attr *attr, struct fi_ops_cq *ops,
			  struct fi_ops *fi_cq_ops)
{
	if (!attr || !ops || !fi_cq_ops)
		return -FI_EINVAL;

	if (!attr->size)
		attr->size = GNIX_CQ_DEFAULT_SIZE;

	switch (attr->format) {
	case FI_CQ_FORMAT_UNSPEC:
		attr->format = FI_CQ_FORMAT_CONTEXT;
	case FI_CQ_FORMAT_CONTEXT:
	case FI_CQ_FORMAT_MSG:
	case FI_CQ_FORMAT_DATA:
	case FI_CQ_FORMAT_TAGGED:
		break;
	default:
		GNIX_WARN(FI_LOG_CQ, "format: %d unsupported\n.",
			  attr->format);
		return -FI_EINVAL;
	}

	switch (attr->wait_obj) {
	case FI_WAIT_NONE:
		ops->sread = fi_no_cq_sread;
		ops->signal = fi_no_cq_signal;
		ops->sreadfrom = fi_no_cq_sreadfrom;
		fi_cq_ops->control = fi_no_control;
		break;
	case FI_WAIT_SET:
		if (!attr->wait_set) {
			GNIX_WARN(FI_LOG_CQ,
				  "FI_WAIT_SET is set, but wait_set field doesn't reference a wait object.\n");
			return -FI_EINVAL;
		}
		break;
	case FI_WAIT_UNSPEC:
		attr->wait_obj = FI_WAIT_FD;
	case FI_WAIT_FD:
	case FI_WAIT_MUTEX_COND:
		break;
	default:
		GNIX_WARN(FI_LOG_CQ, "wait type: %d unsupported.\n",
			  attr->wait_obj);
		return -FI_EINVAL;
	}

	return FI_SUCCESS;
}

static int gnix_cq_set_wait(struct gnix_fid_cq *cq)
{
	int ret = FI_SUCCESS;

	struct fi_wait_attr requested = {
		.wait_obj = cq->attr.wait_obj,
		.flags = 0
	};

	switch (cq->attr.wait_obj) {
	case FI_WAIT_FD:
	case FI_WAIT_MUTEX_COND:
		ret = gnix_wait_open(&cq->domain->fabric->fab_fid,
				&requested, &cq->wait);
		break;
	case FI_WAIT_SET:
		cq->wait = cq->attr.wait_set;
		ret = _gnix_wait_set_add(cq->wait, &cq->cq_fid.fid);

		if (!ret)
			cq->wait = cq->attr.wait_set;

		break;
	default:
		break;
	}

	return ret;
}

static void free_cq(struct slist *cq)
{
	struct slist_entry *entry;
	struct gnix_cq_entry *item;

	while (!slist_empty(cq)) {
		entry = slist_remove_head(cq);
		item = container_of(entry, struct gnix_cq_entry, item);
		free(item->the_entry);
		free(item);
	}
}

/*******************************************************************************
 * Exposed helper functions
 ******************************************************************************/
ssize_t _gnix_cq_add_event(struct gnix_fid_cq *cq, void *op_context,
			   uint64_t flags, size_t len, void *buf,
			   uint64_t data, uint64_t tag)
{
	struct gnix_cq_entry *event;

	fastlock_acquire(&cq->lock);

	if (!slist_empty(&cq->ev_free)) {
		event = container_of(slist_remove_head(&cq->ev_free),
				     struct gnix_cq_entry, item);
	} else {
		event = alloc_cq_entry(cq->entry_size);
	}

	fastlock_release(&cq->lock);

	if (!event) {
		GNIX_ERR(FI_LOG_CQ, "error creating cq_entry\n");
		return -FI_ENOMEM;
	}

	assert(event->the_entry);

	fill_function[cq->attr.format](event->the_entry, op_context, flags,
			len, buf, data, tag);

	cq_enqueue(cq, event);

	return FI_SUCCESS;
}

ssize_t _gnix_cq_add_error(struct gnix_fid_cq *cq, void *op_context,
			   uint64_t flags, size_t len, void *buf,
			   uint64_t data, uint64_t tag, size_t olen,
			   int err, int prov_errno, void *err_data)
{
	struct gnix_cq_entry *event;
	struct fi_cq_err_entry *error;

	fastlock_acquire(&cq->lock);

	if (!slist_empty(&cq->err_free)) {
		event = container_of(slist_remove_head(&cq->ev_free),
				     struct gnix_cq_entry, item);
	} else {
		event = alloc_cq_entry(sizeof(struct fi_cq_err_entry));
	}

	if (!event) {
		GNIX_ERR(FI_LOG_CQ, "error creating error entry\n");
		return -FI_ENOMEM;
	}

	error = event->the_entry;

	error->op_context = op_context;
	error->flags = flags;
	error->len = len;
	error->buf = buf;
	error->data = data;
	error->tag = tag;
	error->olen = olen;
	error->err = err;
	error->prov_errno = prov_errno;
	error->err_data = err_data;

	slist_insert_tail(&event->item, &cq->err_queue);

	fastlock_release(&cq->lock);

	return FI_SUCCESS;
}

/*******************************************************************************
 * API functions.
 ******************************************************************************/
static int gnix_cq_close(fid_t fid)
{
	struct gnix_fid_cq *cq;

	cq = container_of(fid, struct gnix_fid_cq, cq_fid);
	if (atomic_get(&cq->ref_cnt) != 0) {
		GNIX_INFO(FI_LOG_CQ, "CQ ref count: %d, not closing.\n",
			  cq->ref_cnt);
		return -FI_EBUSY;
	}

	atomic_dec(&cq->domain->ref_cnt);
	assert(atomic_get(&cq->domain->ref_cnt) >= 0);

	if (cq->attr.wait_obj == FI_WAIT_SET)
		_gnix_wait_set_remove(cq->wait, &cq->cq_fid.fid);

	fastlock_acquire(&cq->lock);

	GNIX_INFO(FI_LOG_CQ, "Freeing all resources associated with CQ.\n");

	free_cq(&cq->ev_free);
	free_cq(&cq->err_free);
	free_cq(&cq->ev_queue);
	free_cq(&cq->err_queue);

	fastlock_release(&cq->lock);

	fastlock_destroy(&cq->lock);
	free(cq->cq_fid.ops);
	free(cq->cq_fid.fid.ops);
	free(cq);

	return FI_SUCCESS;
}

static ssize_t gnix_cq_readfrom(struct fid_cq *cq, void *buf, size_t count,
				fi_addr_t *src_addr)
{
	struct gnix_fid_cq *cq_priv;
	ssize_t read_count;

	if (!cq || !buf || !count)
		return -FI_EINVAL;

	cq_priv = container_of(cq, struct gnix_fid_cq, cq_fid);

	if (!slist_empty(&cq_priv->err_queue))
		return -FI_EAVAIL;

	read_count = cq_dequeue(cq_priv, buf, count, src_addr);

	return read_count;
}

static ssize_t gnix_cq_read(struct fid_cq *cq, void *buf, size_t count)
{
	return gnix_cq_readfrom(cq, buf, count, NULL);
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

static ssize_t gnix_cq_readerr(struct fid_cq *cq, struct fi_cq_err_entry *buf,
			       uint64_t flags)
{
	struct gnix_fid_cq *cq_priv;
	struct gnix_cq_entry *event;
	ssize_t read_count = 0;

	if (!cq || !buf)
		return -FI_EINVAL;

	cq_priv = container_of(cq, struct gnix_fid_cq, cq_fid);

	if (slist_empty(&cq_priv->err_queue))
		return -FI_EAGAIN;

	fastlock_acquire(&cq_priv->lock);

	event = container_of(slist_remove_head(&cq_priv->err_queue),
			     struct gnix_cq_entry, item);

	memcpy(buf, event->the_entry, sizeof(struct fi_cq_err_entry));
	slist_insert_tail(&event->item, &cq_priv->err_free);
	read_count++;

	fastlock_release(&cq_priv->lock);

	return read_count;
}

static const char *gnix_cq_strerror(struct fid_cq *cq, int prov_errno,
				    const void *prov_data, char *buf,
				    size_t len)
{
	return NULL;
}

static int gnix_cq_signal(struct fid_cq *cq)
{
	struct gnix_fid_cq *cq_priv;

	cq_priv = container_of(cq, struct gnix_fid_cq, cq_fid);

	if (cq_priv->wait)
		_gnix_signal_wait_obj(cq_priv->wait);

	return FI_SUCCESS;
}

static int gnix_cq_control(struct fid *cq, int command, void *arg)
{
	struct gnix_fid_cq *cq_priv;

	cq_priv = container_of(cq, struct gnix_fid_cq, cq_fid);

	switch (command) {
	case FI_GETWAIT:
		return _gnix_get_wait_obj(cq_priv->wait, arg);
	default:
		return -FI_EINVAL;
	}
}

int gnix_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context)
{
	struct gnix_fid_domain *domain_priv;
	struct gnix_cq_entry *entry;
	struct gnix_fid_cq *cq_priv;
	struct fi_ops_cq *cq_ops;
	struct fi_ops *fi_cq_ops;

	int ret = FI_SUCCESS;

	cq_ops = calloc(1, sizeof(*cq_ops));
	if (!cq_ops) {
		ret = -FI_ENOMEM;
		goto err;
	}

	fi_cq_ops = calloc(1, sizeof(*fi_cq_ops));
	if (!fi_cq_ops) {
		ret = -FI_ENOMEM;
		goto err1;
	}

	*cq_ops = gnix_cq_ops;
	*fi_cq_ops = gnix_cq_fi_ops;

	ret = verify_cq_attr(attr, cq_ops, fi_cq_ops);
	if (ret)
		goto err2;

	domain_priv = container_of(domain, struct gnix_fid_domain, domain_fid);
	if (!domain_priv) {
		ret = -FI_EINVAL;
		goto err2;
	}

	cq_priv = calloc(1, sizeof(*cq_priv));
	if (!cq_priv) {
		ret = -FI_ENOMEM;
		goto err2;
	}

	cq_priv->domain = domain_priv;
	cq_priv->attr = *attr;
	atomic_initialize(&cq_priv->ref_cnt, 0);
	atomic_inc(&cq_priv->domain->ref_cnt);

	cq_priv->cq_fid.fid.fclass = FI_CLASS_CQ;
	cq_priv->cq_fid.fid.context = context;
	cq_priv->cq_fid.fid.ops = fi_cq_ops;
	cq_priv->cq_fid.ops = cq_ops;

	/*
	 * Although we don't need to store entry_size since we're already
	 * storing the format, this might provide a performance benefit
	 * when allocating storage.
	 */
	cq_priv->entry_size = format_sizes[cq_priv->attr.format];

	slist_init(&cq_priv->ev_queue);
	slist_init(&cq_priv->ev_free);
	slist_init(&cq_priv->err_queue);
	slist_init(&cq_priv->err_free);

	ret = gnix_cq_set_wait(cq_priv);
	if (ret)
		goto err2;

	fastlock_init(&cq_priv->lock);

	fastlock_acquire(&cq_priv->lock);

	for (int i = 0; i < attr->size; i++) {
		entry = alloc_cq_entry(cq_priv->entry_size);
		if (!entry) {
			GNIX_WARN(FI_LOG_CQ, "Out of memory.\n");
			ret = -FI_ENOMEM;
			goto err3;
		}

		slist_insert_tail(&entry->item, &cq_priv->ev_free);
	}

	fastlock_release(&cq_priv->lock);

	*cq = &cq_priv->cq_fid;
	return ret;

/*
 *  TODO: Cleanup allocated CQ entries in the event of FI_ENOMEM
 */
err3:
	atomic_dec(&cq_priv->domain->ref_cnt);
	fastlock_release(&cq_priv->lock);
	fastlock_destroy(&cq_priv->lock);
	free(cq_priv);
err2:
	free(fi_cq_ops);
err1:
	free(cq_ops);
err:
	return ret;
}


/*******************************************************************************
 * FI_OPS_* data structures.
 ******************************************************************************/
static const struct fi_ops gnix_cq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = gnix_cq_close,
	.bind = fi_no_bind,
	.control = gnix_cq_control
};

static const struct fi_ops_cq gnix_cq_ops = {
	.size = sizeof(struct fi_ops_cq),
	.read = gnix_cq_read,
	.readfrom = gnix_cq_readfrom,
	.readerr = gnix_cq_readerr,
	.sread = gnix_cq_sread,
	.sreadfrom = gnix_cq_sreadfrom,
	.signal = gnix_cq_signal,
	.strerror = gnix_cq_strerror
};
