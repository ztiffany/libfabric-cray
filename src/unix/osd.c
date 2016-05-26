/*
 * Copyright (c) 2013-2016 Intel Corporation. All rights reserved.
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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include "fi_osd.h"
#include "fi_file.h"

int fi_fd_nonblock(int fd)
{
	long flags = 0;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		return -errno;
	}

	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK))
		return -errno;

	return 0;
}

int fi_wait_cond(pthread_cond_t *cond, pthread_mutex_t *mut, int timeout)
{
	struct timespec ts;

	if (timeout < 0)
		return pthread_cond_wait(cond, mut);

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += timeout / 1000;
	ts.tv_nsec += (timeout % 1000) * 1000000;
	return pthread_cond_timedwait(cond, mut, &ts);
}



