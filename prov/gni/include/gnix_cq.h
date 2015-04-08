#ifndef _GNIX_CQ_H_
#define _GNIX_CQ_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fi.h>
#include <fi_list.h>

#define GNIX_CQ_DEFAULT_FORMAT struct fi_cq_entry
#define GNIX_CQ_DEFAULT_SIZE   256

struct gnix_cq_entry {
	void *the_entry;
	fi_addr_t source;
	struct slist_entry item;
};

/*
 * TODO:
 * - Should we consider separate locks for each queue (EV v. ERR) for concurrent
 *   access?
 */
struct gnix_fid_cq {
	struct fid_cq cq_fid;
	struct gnix_fid_domain *domain;

	struct slist ev_queue;
	struct slist err_queue;
	struct slist ev_free;
	struct slist err_free;

	struct fi_cq_attr attr;
	size_t entry_size;

	fastlock_t lock;
	atomic_t ref_cnt;
};


ssize_t _gnix_cq_add_event(struct gnix_fid_cq *cq, void *op_context,
			  uint64_t flags, size_t len, void *buf,
			  uint64_t data, uint64_t tag);

ssize_t _gnix_cq_add_error(struct gnix_fid_cq *cq, void *op_context,
			  uint64_t flags, size_t len, void *buf,
			  uint64_t data, uint64_t tag, size_t olen,
			  int err, int prov_errno, void *err_data);

#ifdef __cplusplus
}
#endif

#endif
