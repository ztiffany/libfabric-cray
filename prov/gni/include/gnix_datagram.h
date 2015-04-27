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

#ifndef _GNIX_DATAGRAM_H_
#define _GNIX_DATAGRAM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "gnix.h"

/*
 * GNI datagram related structs and defines.
 * The GNI_EpPostDataWId, etc. are used to manage
 * connecting VC's for the FI_EP_RDM endpoint
 * type.
 *
 * There are two types of datagrams used by the
 * gni provider: bound (bnd) datagrams and wildcard (wc)
 * datagrams.
 *
 * Bound datagrams are those that are bound to a particular
 * target nic address by means of the GNI_EpBind function
 * When a bound datagram is submitted to the datagram system via
 * a GNI_EpPostDataWId, kgni forwards the datagram to
 * the target node/cdm_id. Note that once a datagram exchange
 * has been completed, the datagram can be unbound using
 * the GNI_EpUnbind, and subsequently reused to target a different
 * gni nic address/cdm_id.
 *
 * Wildcard datagrams have semantics similar to listening
 * sockets.  When a wildcard datagram is submitted to the
 * datagram system, kgni adds the datagram to the list of
 * datagrams to match for the given gni nic/cdm_id.  When an
 * incoming bound datagram matches the wildcard, the datagram
 * exchange is completed.
 */

/*
 * gnix_dgram_hndl - handle to a datagram management
 * instance.
 *
 * nic: pointer to gnix_cm_nic associated with this dgram_hndl
 * bnd_dgram_free_list: head of a linked list of available bnd dgrams
 * bnd_dgram_acive_list: head of linked list of active bnd dgrams
 * wc_dgram_free_list: head of linked list of available
 *			wildcard datagrams
 * wc_dgram_active_list: head of linked list of active
 *			wildcard datagrams
 * dgram_base: base address for allocated vector of dgrams
 * n_dgrams: number of bound dgrams
 * n_wc_dgrams: number of wildcard dgrams
 */

struct gnix_dgram_hndl {
	struct gnix_cm_nic *cm_nic;
	struct list_head bnd_dgram_free_list;
	struct list_head bnd_dgram_active_list;
	struct list_head wc_dgram_free_list;
	struct list_head wc_dgram_active_list;
	struct gnix_datagram *dgram_base;
	pthread_t progress_thread;
	int n_dgrams;
	int n_wc_dgrams;
};

enum gnix_dgram_type {
	GNIX_DGRAM_WC = 100,
	GNIX_DGRAM_BND
};

enum gnix_dgram_state {
	GNIX_DGRAM_STATE_FREE,
	GNIX_DGRAM_STATE_CONNECTING,
	GNIX_DGRAM_STATE_LISTENING,
	GNIX_DGRAM_STATE_CONNECTED,
	GNIX_DGRAM_STATE_ALREADY_CONNECTING
};

enum gnix_dgram_buf {
	GNIX_DGRAM_IN_BUF,
	GNIX_DGRAM_OUT_BUF
};

enum gnix_dgram_poll_type {
	GNIX_DGRAM_NOBLOCK,
	GNIX_DGRAM_BLOCK
};

struct gnix_datagram {
	struct list_node        list;
	struct list_head        *free_list_head;
	gni_ep_handle_t         gni_ep;
	struct gnix_cm_nic      *nic;
	struct gnix_address     target_addr;
	enum gnix_dgram_state   state;
	enum gnix_dgram_type    type;
	struct gnix_dgram_hndl  *d_hndl;
	int  (*callback_fn)(struct gnix_datagram *,
			    struct gnix_address,
			    gni_post_state_t);
	int r_index_in_buf;
	int w_index_in_buf;
	int r_index_out_buf;
	int w_index_out_buf;
	char dgram_in_buf[GNI_DATAGRAM_MAXSIZE];
	char dgram_out_buf[GNI_DATAGRAM_MAXSIZE];
};

/*
 * prototypes for gni datagram internal functions
 */

int _gnix_dgram_hndl_alloc(const struct gnix_fid_fabric *fabric,
				struct gnix_cm_nic *cm_nic,
				enum fi_progress progress,
				struct gnix_dgram_hndl **hndl_ptr);
int _gnix_dgram_hndl_free(struct gnix_dgram_hndl *hndl);
int _gnix_dgram_alloc(struct gnix_dgram_hndl *hndl,
			enum gnix_dgram_type type,
			struct gnix_datagram **d_ptr);
int _gnix_dgram_free(struct gnix_datagram *d);
int _gnix_dgram_wc_post(struct gnix_datagram *d,
			gni_return_t *status_ptr);
int _gnix_dgram_bnd_post(struct gnix_datagram *d,
				gni_return_t *status_ptr);
ssize_t _gnix_dgram_pack_buf(struct gnix_datagram *d, enum gnix_dgram_buf,
			 void *data, uint32_t nbytes);
ssize_t _gnix_dgram_unpack_buf(struct gnix_datagram *d, enum gnix_dgram_buf,
			   void *data, uint32_t nbytes);
int _gnix_dgram_rewind_buf(struct gnix_datagram *d, enum gnix_dgram_buf);
int _gnix_dgram_poll(struct gnix_dgram_hndl *hndl_ptr,
			enum gnix_dgram_poll_type type);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _GNIX_DATAGRAM_H_ */
