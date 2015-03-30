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

#include "alps/alps.h"
#include "alps/alps_toolAssist.h"
#include "alps/libalpsutil.h"
#include "alps/libalpslli.h"

#include "gnix.h"
#include "gnix_util.h"

int gnixu_get_rdma_credentials(void *addr, uint8_t *ptag, uint32_t *cookie)
{
	int ret = FI_SUCCESS;
	int alps_status = 0;
	uint64_t apid;
	size_t alps_count;
	alpsAppLLIGni_t *rdmacred_rsp = NULL;
	alpsAppGni_t *rdmacred_buf = NULL;

	if ((ptag == NULL) || (cookie == NULL)) {
		ret = -FI_EINVAL;
		goto err;
	}

	/*
	 * TODO: need to handle non null addr differently at some point,
	 * a non-NULL addr can be used to acquire RDMA credentials other than
	 * those assigned by ALPS/nativized slurm.
	 */
	/* lli_lock doesn't return anything useful */
	ret = alps_app_lli_lock();

	/*
	 * First get our apid
	 */
	ret = alps_app_lli_put_request(ALPS_APP_LLI_ALPS_REQ_APID, NULL, 0);
	if (ret != ALPS_APP_LLI_ALPS_STAT_OK) {
		GNIX_ERR(FI_LOG_FABRIC, "lli put failed, ret=%d(%s)\n", ret,
			       strerror(errno));
		ret = -FI_EIO;
		goto err;
	}

	ret = alps_app_lli_get_response(&alps_status, &alps_count);
	if (alps_status != ALPS_APP_LLI_ALPS_STAT_OK) {
		GNIX_ERR(FI_LOG_FABRIC, "lli get response failed, "
			       "alps_status=%d(%s)\n",alps_status,
			       strerror(errno));
		ret = -FI_EIO;
		goto err;
	}

	ret = alps_app_lli_get_response_bytes(&apid, sizeof(apid));
	if (ret != ALPS_APP_LLI_ALPS_STAT_OK) {
		GNIX_ERR(FI_LOG_FABRIC,
			 "lli get response failed, ret=%d(%s)\n",
			 ret, strerror(errno));
		ret = -FI_EIO;
		goto err;
	}

	/*
	 * now get the GNI rdma credentials info
	 */
	ret = alps_app_lli_put_request(ALPS_APP_LLI_ALPS_REQ_GNI, NULL, 0);
	if (ret != ALPS_APP_LLI_ALPS_STAT_OK) {
		GNIX_ERR(FI_LOG_FABRIC, "lli put failed, ret=%d(%s)\n",
			       ret, strerror(errno));
		ret = -FI_EIO;
		goto err;
	}

	ret = alps_app_lli_get_response(&alps_status, &alps_count);
	if (alps_status != ALPS_APP_LLI_ALPS_STAT_OK) {
		GNIX_ERR(FI_LOG_FABRIC,
			 "lli get response failed, alps_status=%d(%s)\n",
			 alps_status, strerror(errno));
		ret = -FI_EIO;
		goto err;
	}

	rdmacred_rsp = malloc(alps_count);
	if (rdmacred_rsp == NULL) {
		ret = -FI_ENOMEM;
		goto err;
	}

	memset(rdmacred_rsp, 0, alps_count);

	ret = alps_app_lli_get_response_bytes(rdmacred_rsp, alps_count);
	if (ret != ALPS_APP_LLI_ALPS_STAT_OK) {
		GNIX_ERR(FI_LOG_FABRIC,
			 "lli get response failed, ret=%d(%s)\n",
			 ret, strerror(errno));
		ret = -FI_EIO;
		goto err;
	}

	rdmacred_buf = (alpsAppGni_t *) rdmacred_rsp->u.buf;

	/*
	 * just use the first ptag/cookie for now
	 */

	*ptag = rdmacred_buf[0].ptag;
	*cookie = rdmacred_buf[0].cookie;
err:
	alps_app_lli_unlock();
	if (rdmacred_rsp != NULL) {
		free(rdmacred_rsp);
	}
	return ret;
}

#define NUM_GNI_RC (GNI_RC_ERROR_NOMEM+1)
static int gnix_rc_table[NUM_GNI_RC] = {
	[GNI_RC_SUCCESS] = FI_SUCCESS,
	[GNI_RC_NOT_DONE] = -FI_EOPBADSTATE,
	[GNI_RC_INVALID_PARAM] = -FI_EINVAL,
	[GNI_RC_ERROR_RESOURCE] = -FI_EBUSY,
	[GNI_RC_TIMEOUT] = -FI_ETIMEDOUT,
	[GNI_RC_PERMISSION_ERROR] = -FI_EACCES,
	[GNI_RC_DESCRIPTOR_ERROR] = -FI_EOTHER,
	[GNI_RC_ALIGNMENT_ERROR] = -FI_EINVAL,
	[GNI_RC_INVALID_STATE] = -FI_EOPBADSTATE,
	[GNI_RC_NO_MATCH] = -FI_EINVAL,
	[GNI_RC_SIZE_ERROR] = -FI_ETOOSMALL,
	[GNI_RC_TRANSACTION_ERROR] = -FI_ECANCELED,
	[GNI_RC_ILLEGAL_OP] = -FI_EOPNOTSUPP,
	[GNI_RC_ERROR_NOMEM] = -FI_ENOMEM
};

int gnixu_to_fi_errno(int err)
{
	if (err >= 0 && err < NUM_GNI_RC)
		return gnix_rc_table[err];
	else
		return -FI_EOTHER;
}
