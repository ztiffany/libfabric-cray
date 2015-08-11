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

#ifndef _GNIX_AV_H_
#define _GNIX_AV_H_

#include "gnix.h"


/*
 * prototypes for GNI AV helper functions for managing the av
 * system.
 */

/**
 * @brief  lookup the real address based on the input fi_addr
 *	   and the given av.
 *
 * @param[in] int_av	 pointer to a previously allocated gnix_fid_av
 * @param[in] fi_addr    address to be translated
 * @param[out] real_addr pointer to memory to copy translated address to
 * @return		 FI_SUCCESS on success, -FI_EINVAL on error
 */
int _gnix_av_addr_retrieve(struct gnix_fid_av *int_av, fi_addr_t fi_addr,
			fi_addr_t *real_addr);

#endif /* _GNIX_AV_H_ */
