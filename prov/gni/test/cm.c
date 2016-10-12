/*
 * Copyright (c) 2016 Cray Inc. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>

#include "gnix_vc.h"
#include "gnix_cm_nic.h"
#include "gnix_hashtable.h"
#include "gnix_atomic.h"

#include <criterion/criterion.h>
#include "gnix_rdma_headers.h"

#if 0
#define dbg_printf(...)
#else
#define dbg_printf(...)				\
	do {					\
		printf(__VA_ARGS__);		\
		fflush(stdout);			\
	} while (0)
#endif

#define NUMEPS 2

#define DEF_PORT "1973"

static struct fid_fabric *cli_fab;
static struct fid_domain *cli_dom;
static struct fid_ep *cli_ep;
static struct fi_info *cli_hints;
static struct fi_info *cli_fi;
static void *cli_ep_name;
static struct fid_eq *cli_eq;
static struct fid_cq *cli_cq;

static struct fid_fabric *srv_fab;
static struct fid_domain *srv_dom;
static struct fid_pep *srv_pep;
static struct fid_ep *srv_ep;
static struct fi_info *srv_hints;
static struct fi_info *srv_fi;
static void *srv_ep_name;
static struct fid_eq *srv_eq;
static struct fid_cq *srv_cq;

struct fi_eq_attr eq_attr = {
	.wait_obj = FI_WAIT_UNSPEC
};

struct fi_cq_attr cq_attr = {
	.wait_obj = FI_WAIT_NONE
};

int cm_local_ip(struct sockaddr_in *sa)
{
	struct ifaddrs *ifap;
	struct ifaddrs *ifa;
	int ret = -1;

	getifaddrs(&ifap);

	ifa = ifap;
	while (ifa) {
		fprintf(stderr, "IF: %s, IP ADDR: %s\n",
			ifa->ifa_name,
			inet_ntoa(((struct sockaddr_in *)
					(ifa->ifa_addr))->sin_addr));
		/* Return first non loopback interface. */
		if (ifa->ifa_addr &&
		    ifa->ifa_addr->sa_family == AF_INET &&
		    ((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr.s_addr !=
		     inet_addr("127.0.0.1")) {
			ret = 0;
			break;
		}
		ifa = ifa->ifa_next;
	}

	if (!ret) {
		memcpy((void *)sa, (void *)ifa->ifa_addr,
		       sizeof(struct sockaddr));
	}

	freeifaddrs(ifap);

	return ret;
}

int cm_server_start(void)
{
	int ret;
	struct sockaddr_in loc_sa;

	cm_local_ip(&loc_sa);

	srv_hints = fi_allocinfo();
	srv_hints->fabric_attr->name = strdup("gni");
	srv_hints->ep_attr->type = FI_EP_MSG;

	ret = fi_getinfo(FI_VERSION(1, 0), inet_ntoa(loc_sa.sin_addr),
			 DEF_PORT, FI_SOURCE, srv_hints, &srv_fi);
	cr_assert(!ret);

	ret = fi_fabric(srv_fi->fabric_attr, &srv_fab, NULL);
	cr_assert(!ret);

	ret = fi_eq_open(srv_fab, &eq_attr, &srv_eq, NULL);
	cr_assert(!ret);

	ret = fi_passive_ep(srv_fab, srv_fi, &srv_pep, NULL);
	cr_assert(!ret);

	ret = fi_pep_bind(srv_pep, &srv_eq->fid, 0);
	cr_assert(!ret);

	ret = fi_listen(srv_pep);
	cr_assert(!ret);

	dbg_printf("Server start complete.\n");

	return 0;
}

void cm_stop_server(void)
{
	fi_close(&srv_cq->fid);
	fi_close(&srv_ep->fid);
	fi_close(&srv_dom->fid);
	fi_close(&srv_pep->fid);
	fi_close(&srv_eq->fid);
	fi_close(&srv_fab->fid);
	fi_freeinfo(srv_fi);
}

int cm_server_accept(void)
{
	uint32_t event;
	struct fi_eq_cm_entry entry;
	ssize_t rd;
	int ret;

	rd = fi_eq_sread(srv_eq, &event, &entry, sizeof(entry), -1, 0);
	cr_assert(rd == sizeof(entry));

	cr_assert(event == FI_CONNREQ);

	ret = fi_domain(srv_fab, entry.info, &srv_dom, NULL);
	cr_assert(!ret);

	ret = fi_endpoint(srv_dom, entry.info, &srv_ep, NULL);
	cr_assert(!ret, "fi_endpoint");

	cq_attr.format = FI_CQ_FORMAT_TAGGED;
	cq_attr.size = 1024;
	cq_attr.wait_obj = 0;

	ret = fi_cq_open(srv_dom, &cq_attr, &srv_cq, &srv_cq);
	cr_assert(!ret);

	ret = fi_ep_bind(srv_ep, &srv_eq->fid, 0);
	cr_assert(!ret);

	ret = fi_ep_bind(srv_ep, &srv_cq->fid, FI_SEND | FI_RECV);
	cr_assert(!ret);

	ret = fi_enable(srv_ep);
	cr_assert(!ret);

	ret = fi_accept(srv_ep, NULL, 0);
	cr_assert(!ret);

	dbg_printf("Server accept complete.\n");

	return 0;
}

int cm_server_finish_connect(void)
{
	uint32_t event;
	struct fi_eq_cm_entry entry;
	ssize_t rd;

	rd = fi_eq_read(srv_eq, &event, &entry, sizeof(entry), 0);
	if (rd > 0) {
		dbg_printf("got event: %d\n", event);
		cr_assert(rd == sizeof(entry));
		cr_assert(event == FI_CONNECTED && entry.fid == &srv_ep->fid);
		return 1;
	}

	return 0;
}

int cm_client_start_connect(void)
{
	int ret;
	struct sockaddr_in loc_sa;

	cm_local_ip(&loc_sa);

	cli_hints = fi_allocinfo();
	cli_hints->fabric_attr->name = strdup("gni");
	cli_hints->caps = GNIX_EP_PRIMARY_CAPS;
	cli_hints->ep_attr->type = FI_EP_MSG;

	ret = fi_getinfo(FI_VERSION(1, 0), inet_ntoa(loc_sa.sin_addr),
			 DEF_PORT, 0, cli_hints, &cli_fi);
	cr_assert(!ret);

	ret = fi_fabric(cli_fi->fabric_attr, &cli_fab, NULL);
	cr_assert(!ret);

	ret = fi_eq_open(cli_fab, &eq_attr, &cli_eq, NULL);
	cr_assert(!ret);

	ret = fi_domain(cli_fab, cli_fi, &cli_dom, NULL);
	cr_assert(!ret);

	ret = fi_endpoint(cli_dom, cli_fi, &cli_ep, NULL);
	cr_assert(!ret, "fi_endpoint");

	cq_attr.format = FI_CQ_FORMAT_TAGGED;
	cq_attr.size = 1024;
	cq_attr.wait_obj = 0;

	ret = fi_cq_open(cli_dom, &cq_attr, &cli_cq, &cli_cq);
	cr_assert(!ret);

	ret = fi_ep_bind(cli_ep, &cli_eq->fid, 0);
	cr_assert(!ret);

	ret = fi_ep_bind(cli_ep, &cli_cq->fid, FI_SEND | FI_RECV);
	cr_assert(!ret);

	ret = fi_enable(cli_ep);
	cr_assert(!ret);

	ret = fi_connect(cli_ep, cli_fi->dest_addr, NULL, 0);
	cr_assert(!ret);

	dbg_printf("Client connect complete.\n");

	return 0;
}

int cm_client_finish_connect(void)
{
	uint32_t event;
	struct fi_eq_cm_entry entry;
	ssize_t rd;

	rd = fi_eq_read(cli_eq, &event, &entry, sizeof(entry), 0);
	if (rd > 0) {
		dbg_printf("got event: %d\n", event);
		cr_assert(rd == sizeof(entry));
		cr_assert(event == FI_CONNECTED && entry.fid == &cli_ep->fid);
		return 1;
	}

	return 0;
}

void cm_stop_client(void)
{
	fi_close(&cli_cq->fid);
	fi_close(&cli_ep->fid);
	fi_close(&cli_dom->fid);
	fi_close(&cli_eq->fid);
	fi_close(&cli_fab->fid);
	fi_freeinfo(cli_fi);
}

void cm_basic_send(void)
{
	int ret;
	int source_done = 0, dest_done = 0;
	struct fi_cq_tagged_entry cqe;
	ssize_t sz;
	uint64_t source = 0xa4321234a4321234,
		 target = 0xb5678901b5678901;

	sz = fi_send(cli_ep, &source, 8, 0, 0, &target);
	cr_assert_eq(sz, 0);

	sz = fi_recv(srv_ep, &target, 8, 0, 0, &source);
	cr_assert_eq(sz, 0);

	/* need to progress both CQs simultaneously for rendezvous */
	do {
		ret = fi_cq_read(cli_cq, &cqe, 1);
		if (ret == 1) {
			cr_assert_eq(cqe.op_context, &target);
			source_done = 1;
		}

		ret = fi_cq_read(srv_cq, &cqe, 1);
		if (ret == 1) {
			cr_assert_eq(cqe.op_context, &source);
			dest_done = 1;
		}
	} while (!source_done || !dest_done);

	cr_assert_eq(source, target);
	dbg_printf("Basic send/recv complete! (0x%lx, 0x%lx)\n",
		   source, target);
}

Test(cm_basic, srv_setup)
{
	int cli_connected = 0, srv_connected = 0;

	/* Start listening PEP. */
	cm_server_start();
	/* Create EP and fi_connect() to server. */
	cm_client_start_connect();
	/* Wait for EQE and fi_accept() new EP. */
	cm_server_accept();

	/* Wait for FI_CONNECTED EQES on client and server EQ. */
	do {
		if (!srv_connected) {
			srv_connected += cm_server_finish_connect();
			if (srv_connected)
				dbg_printf("Server connect complete!\n");
		}

		if (!cli_connected) {
			cli_connected += cm_client_finish_connect();
			if (cli_connected)
				dbg_printf("Client connect complete!\n");
		}
	} while (!srv_connected || !cli_connected);

	/* Perform basic send/recv. */
	cm_basic_send();

	cm_stop_server();
	cm_stop_client();
}

