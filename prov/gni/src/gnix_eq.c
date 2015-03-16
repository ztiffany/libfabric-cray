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

#include <assert.h>

#include "gnix.h"
#include "gnix_util.h"

/*******************************************************************************
 * Forward declaration for ops structures.
 ******************************************************************************/
static struct fi_ops_eq gnix_eq_ops;
static struct fi_ops gnix_fi_eq_ops;


/*******************************************************************************
 * Aids in distinguishing queues when using generic write.
 ******************************************************************************/
enum q_type {
	EVENT,
	ERROR
};

/*******************************************************************************
 * Helper functions.
 ******************************************************************************/
static int gnix_verify_eq_attr(struct fi_eq_attr *attr)
{
	/*
	 * Initial implementation doesn't support any type of wait object.
	 */
	switch (attr->wait_obj) {
	case FI_WAIT_NONE:
	case FI_WAIT_UNSPEC:
		break;
	case FI_WAIT_SET:
	case FI_WAIT_FD:
	case FI_WAIT_MUTEX_COND:
		return -FI_ENOSYS;
	default:
		break;
	}

	return FI_SUCCESS;
}

/*
 * TODO: Free buf?
 */
static void free_queue(struct slist *list)
{
	struct slist_entry *current = NULL;
	struct slist_entry *next = NULL;
	struct gnix_event *temp = NULL;

	if (slist_empty(list))
		return;

	for (current = list->head; current; current = next) {
		next = current->next;
		temp = container_of(current, struct gnix_event, entry);

		/*
		 * For the event queue this is the extraneous data that was
		 * copied in. For the error queue this is the actual
		 * fi_eq_err_entry.
		 */
		free(temp->buf);
		free(temp);
	}
}

static ssize_t queue_read(struct fid_eq *eq, uint32_t *event, void *buf,
			  size_t len, uint64_t flags, enum q_type type)
{
	struct gnix_fid_eq *gnix_eq = NULL;
	struct gnix_event *ev = NULL;
	struct slist *queue;
	int ret = len;

	gnix_eq = container_of(eq, struct gnix_fid_eq, eq_fid);
	if (!gnix_eq) {
		ret = -FI_EINVAL;
		goto err;
	}

	fastlock_acquire(&gnix_eq->lock);

	switch (type) {
	case EVENT:
		if (!slist_empty(&gnix_eq->err_queue)) {
			ret = -FI_EAVAIL;
			goto cleanup;
		}

		if (slist_empty(&gnix_eq->ev_queue)) {
			ret = -FI_EAGAIN;
			goto cleanup;
		}

		queue = &gnix_eq->ev_queue;
		break;
	case ERROR:
		if (slist_empty(&gnix_eq->err_queue)) {
			ret = -FI_EAGAIN;
			goto cleanup;
		}

		queue = &gnix_eq->err_queue;
		break;
	default:
		ret = -FI_EINVAL;
		goto cleanup;
	}

	ev = container_of(queue->head, struct gnix_event, entry);
	if (!event) {
		ret = -FI_EINVAL;
		goto cleanup;
	}

	if (len < ev->len) {
		ret = -FI_ETOOSMALL;
		goto cleanup;
	}

	if (type == EVENT)
		*event = ev->type;

	memcpy(buf, ev->buf, len);

	/*
	 * Remove if FI_PEEK isn't specified.
	 */
	if (!(flags & FI_PEEK)) {
		ev = container_of(slist_remove_head(&gnix_eq->ev_queue),
				  struct gnix_event, entry);
		free(ev->buf);
		free(ev);
	}

	fastlock_release(&gnix_eq->lock);

	return ret;

cleanup:
	fastlock_release(&gnix_eq->lock);
err:
	return ret;
}

static ssize_t queue_write(struct fid_eq *eq, uint32_t event, void *buf,
			   size_t len, uint64_t flags, enum q_type type)
{
	struct gnix_fid_eq *gnix_eq = NULL;
	struct gnix_event *q_entry = NULL;
	struct slist *queue = NULL;
	ssize_t ret = len;

	q_entry = calloc(1, sizeof(*q_entry));
	if (!q_entry) {
		ret = -FI_ENOMEM;
		goto err;
	}

	gnix_eq = container_of(eq, struct gnix_fid_eq, eq_fid);
	if (!gnix_eq) {
		ret = -FI_EINVAL;
		goto cleanup_q_entry;
	}

	switch (type) {
	case EVENT:
		queue = &gnix_eq->ev_queue;
		break;
	case ERROR:
		queue = &gnix_eq->err_queue;
		break;
	default:
		ret = -FI_EINVAL;
		goto cleanup_q_entry;
	}

	q_entry->len = len;
	q_entry->buf = buf;
	q_entry->type = event;
	q_entry->flags = flags;

	fastlock_acquire(&gnix_eq->lock);

	slist_insert_tail(&q_entry->entry, queue);

	fastlock_release(&gnix_eq->lock);

	return ret;

cleanup_q_entry:
	free(q_entry);
err:
	return ret;
}

static ssize_t gnix_eq_write_error(struct fid_eq *eq, fid_t fid,
				   void *context, uint64_t index, int err,
				   int prov_errno, void *err_data,
				   size_t err_size)
{
	struct fi_eq_err_entry *err_entry = calloc(1, sizeof(*err_entry));

	if (!err_entry)
		return -FI_ENOMEM;

	err_entry->fid = fid;
	err_entry->context = context;
	err_entry->data = index;
	err_entry->err = err;
	err_entry->prov_errno = prov_errno;
	err_entry->err_data = err_data;
	err_entry->err_data_size = err_size;

	/*
	 * Event and flag entries are irrelevant for error queue entries.
	 */
	return queue_write(eq, 0, err_entry, sizeof(*err_entry), 0, ERROR);
}


/*******************************************************************************
 * API function implementations.
 ******************************************************************************/
/*
 * TODO:
 * - Increment fabric ref_cnt.
 * - Handle FI_WRITE flag. When not included, replace write function with
 *   fi_no_eq_write.
 * - Handle wait objects.
 */
int gnix_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		 struct fid_eq **eq, void *context)
{
	struct gnix_fid_eq *gnix_eq = NULL;
	int ret = FI_SUCCESS;

	if (!fabric) {
		ret = -FI_EINVAL;
		goto err;
	}

	gnix_eq = calloc(1, sizeof(*gnix_eq));
	if (!gnix_eq) {
		ret = -FI_ENOMEM;
		goto err;
	}

	if (attr) {
		ret = gnix_verify_eq_attr(attr);
		if (ret)
			goto cleanup;
	}

	gnix_eq->eq_fabric = container_of(fabric, struct gnix_fid_fabric,
					  fab_fid);
	atomic_inc(&gnix_eq->eq_fabric->ref_cnt);

	gnix_eq->eq_fid.fid.fclass = FI_CLASS_EQ;
	gnix_eq->eq_fid.fid.context = context;
	gnix_eq->eq_fid.fid.ops = &gnix_fi_eq_ops;
	gnix_eq->eq_fid.ops = &gnix_eq_ops;
	fastlock_init(&gnix_eq->lock);

	slist_init(&gnix_eq->ev_queue);
	slist_init(&gnix_eq->err_queue);

	*eq = &gnix_eq->eq_fid;

	return ret;

cleanup:
	free(gnix_eq);
err:
	return ret;
}

/*
 * TOOD:
 * - Decrement fabric ref_cnt.
 */
static int gnix_eq_close(struct fid *fid)
{
	struct gnix_fid_eq *gnix_eq = NULL;

	if (!fid)
		return -FI_EINVAL;

	gnix_eq = container_of(fid, struct gnix_fid_eq, eq_fid);

	if (!gnix_eq)
		return -FI_EINVAL;

	if (atomic_get(&gnix_eq->ref_cnt) != 0)
		return -FI_EBUSY;

	atomic_dec(&gnix_eq->eq_fabric->ref_cnt);
	assert(atomic_get(&gnix_eq->eq_fabric->ref_cnt) >= 0);

	fastlock_destroy(&gnix_eq->lock);
	free_queue(&gnix_eq->ev_queue);
	free_queue(&gnix_eq->err_queue);
	free(gnix_eq);

	return FI_SUCCESS;
}

static ssize_t gnix_eq_sread(struct fid_eq *eq, uint32_t *event, void *buf,
			     size_t len, int timeout, uint64_t flags)
{
	return -FI_ENOSYS;
}

static ssize_t gnix_eq_read(struct fid_eq *eq, uint32_t *event, void *buf,
			    size_t len, uint64_t flags)
{
	return queue_read(eq, event, buf, len, flags, EVENT);
}

static ssize_t gnix_eq_readerr(struct fid_eq *eq, struct fi_eq_err_entry *buf,
			       uint64_t flags)
{
	return queue_read(eq, NULL, buf, sizeof(*buf), flags, ERROR);
}

static ssize_t gnix_eq_write(struct fid_eq *eq, uint32_t event,
			     const void *buf, size_t len, uint64_t flags)
{
	void *ev_buf = NULL;

	ev_buf = calloc(1, len);
	if (!ev_buf)
		return -FI_ENOMEM;

	memcpy(ev_buf, buf, len);

	return queue_write(eq, event, ev_buf, len, flags, EVENT);
}

static const char *gnix_eq_strerror(struct fid_eq *eq, int prov_errno,
				    const void *err_data, char *buf, size_t len)
{
	return NULL;
}

/*******************************************************************************
 * FI_OPS_* data structures.
 ******************************************************************************/
static struct fi_ops_eq gnix_eq_ops = {
	.size = sizeof(struct fi_ops_eq),
	.read = gnix_eq_read,
	.readerr = gnix_eq_readerr,
	.write = gnix_eq_write,
	.sread = gnix_eq_sread,
	.strerror = gnix_eq_strerror
};

static struct fi_ops gnix_fi_eq_ops = {
	.size = sizeof(struct fi_ops),
	.close = gnix_eq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open
};
