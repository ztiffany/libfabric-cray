/*
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

#include <stdio.h>
#include <stddef.h>

#include "gnix.h"
#include "gnix_mbox_allocator.h"

#ifdef assert
#undef assert
#endif

#include <criterion/criterion.h>

static struct fid_fabric *fab;
static struct fid_domain *dom;
static struct fid_ep *ep;
static struct fi_info *hints;
static struct fi_info *fi;
static struct gnix_fid_ep *ep_priv;
static struct gnix_mbox_alloc_handle *allocator;

void allocator_setup(void)
{
	int ret = 0;

	hints = fi_allocinfo();
	assert(hints, "fi_allocinfo");

	hints->domain_attr->cq_data_size = 4;
	hints->mode = ~0;

	hints->fabric_attr->name = strdup("gni");

	ret = fi_getinfo(FI_VERSION(1, 0), NULL, 0, 0, hints, &fi);
	assert_eq(ret, FI_SUCCESS, "fi_getinfo");

	ret = fi_fabric(fi->fabric_attr, &fab, NULL);
	assert_eq(ret, FI_SUCCESS, "fi_fabric");

	ret = fi_domain(fab, fi, &dom, NULL);
	assert_eq(ret, FI_SUCCESS, "fi_domain");

	ret = fi_endpoint(dom, fi, &ep, NULL);
	assert_eq(ret, FI_SUCCESS, "fi_endpoint");

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
}

void allocator_teardown(void)
{
	int ret = 0;

	ret = fi_close(&ep->fid);
	assert_eq(ret, FI_SUCCESS, "failure in closing ep.");
	ret = fi_close(&dom->fid);
	assert_eq(ret, FI_SUCCESS, "failure in closing domain.");
	ret = fi_close(&fab->fid);
	assert_eq(ret, FI_SUCCESS, "failure in closing fabric.");
	fi_freeinfo(fi);
	fi_freeinfo(hints);
}

/*
 * Count how many slabs are present in an allocator.
 */
static size_t count_slabs(struct gnix_mbox_alloc_handle *handle)
{
	size_t count = 0;

	for (struct slist_entry *entry = handle->slab_list.head; entry;
	     entry = entry->next) {
		count++;
	}

	return count;
}

/*
 * Absolute value function that returns a ptrdiff_t.
 */
static ptrdiff_t abs_value(ptrdiff_t x)
{
	return x * ((x > 0) - (x < 0));
}

/*
 * Open /proc/self/maps and count the number of times the hugetlbfs
 * string is present. Return value is the count;
 */
static int verify_hugepages(void)
{
	int ret = 0;
	FILE *fd;
	char *line;
	size_t size = 1024;

	fd = fopen("/proc/self/maps", "r");
	if (!fd) {
		fprintf(stderr, "error opening /proc/self/maps.\n");
		return ret;
	}

	line = malloc(size);
	if (!line) {
		fprintf(stderr, "error mallocing space for line.\n");
		return ret;
	}

	while (getline(&line, &size, fd) != -1) {
		if (strstr(line, "hugetlbfs")) {
			ret++;
		}
	}

	free(line);
	fclose(fd);

	return ret;
}

/*
 * Open an allocator with the given parameters and immediately close it. Verify
 * that everything returned a successful error code.
 */
static void open_close_allocator(enum gnix_page_size page_size,
				 size_t mbox_size,
				 size_t mpmmap)
{
	int ret;

	ret = gnix_mbox_allocator_create(ep_priv->nic, NULL, page_size,
					 mbox_size, mpmmap, &allocator);
	assert_eq(ret, FI_SUCCESS, "gnix_mbox_allocator_create failed.");
	expect_eq(verify_hugepages(), 2,
		  "memory not found in /proc/self/maps.");

	ret = gnix_mbox_allocator_destroy(allocator);
	assert_eq(ret, FI_SUCCESS, "gnix_mbox_allocator_destroy failed.");
	expect_eq(verify_hugepages(), 1,
		  "memory not released in /proc/self/maps.");
}


TestSuite(mbox_creation, .init = allocator_setup, .fini = allocator_teardown);

Test(mbox_creation, alloc_single_page)
{
	/*
	 * Test creation of all predefined page sizes.
	 */
	open_close_allocator(GNIX_PAGE_2MB, 100, 100);
	open_close_allocator(GNIX_PAGE_4MB, 100, 100);
	open_close_allocator(GNIX_PAGE_8MB, 100, 100);
	open_close_allocator(GNIX_PAGE_16MB, 100, 100);
	open_close_allocator(GNIX_PAGE_32MB, 100, 100);
	open_close_allocator(GNIX_PAGE_64MB, 100, 100);
	open_close_allocator(GNIX_PAGE_128MB, 100, 100);
	open_close_allocator(GNIX_PAGE_256MB, 100, 100);
	open_close_allocator(GNIX_PAGE_512MB, 100, 100);
}

Test(mbox_creation, alloc_three_pages)
{
	/*
	 * This should allocate a single slab that's 3 pages in size.
	 */
	open_close_allocator(GNIX_PAGE_4MB, 1000, 12000);
}

Test(mbox_creation, alloc_mbox)
{
	int ret;

	struct gnix_mbox *mail_box;
	struct slist_entry *entry;
	struct gnix_slab *slab;

	char test_string[] = "hello allocator.";

	ret = gnix_mbox_allocator_create(ep_priv->nic, NULL, GNIX_PAGE_4MB,
					 1000, 12000, &allocator);
	assert_eq(ret, FI_SUCCESS, "gnix_mbox_allocator_create failed.");

	/*
	 *value is 2 because the provider has internally already opened
	 * an mbox allocator at this point.
	 */
	expect_eq(verify_hugepages(), 2,
		  "memory not found in /proc/self/maps.");

	ret = gnix_mbox_alloc(allocator, &mail_box);
	expect_eq(ret, FI_SUCCESS, "gnix_mbox_alloc failed.");

	expect(mail_box);

	entry = allocator->slab_list.head;
	assert(entry);

	slab = container_of(entry, struct gnix_slab, list_entry);

	expect_eq(mail_box->slab, slab,
		  "slab list head and mail box slab pointer are not equal.");
	expect_eq(mail_box->memory_handle, &mail_box->slab->memory_handle,
		 "mail_box memory handle not equal to slab memory handle.");
	expect_eq(mail_box->offset, 0, "offset is not 0.");
	expect_eq(mail_box->base, mail_box->slab->base,
		  "mail_box base not equal to slab base.");

	/*
	 * Write our test strings and make sure they're equal.
	 */
	memcpy(mail_box->base, test_string, sizeof(test_string));
	expect_strings_eq((char *) mail_box->base, test_string);

	/*
	 * Mailboxes haven't been returned so destroy will return -FI_EBUSY.
	 */
	ret = gnix_mbox_allocator_destroy(allocator);
	assert_eq(ret, -FI_EBUSY,
		  "gnix_mbox_allocator_destroy should have returned -FI_EBUSY.");

	/*
	 * Free allocated mailboxes so we can destroy cleanly.
	 */
	ret = gnix_mbox_free(mail_box);
	expect_eq(ret, FI_SUCCESS, "gnix_mbox_free failed.");

	ret = gnix_mbox_allocator_destroy(allocator);
	assert_eq(ret, FI_SUCCESS, "gnix_mbox_allocator_destroy failed.");

	expect_eq(verify_hugepages(), 1,
		  "memory not released in /proc/self/maps.");
}

/*
 * Page size needs to be one of the predefined enums. 2200 is not a valid page
 * size. This actually gets expanded to 2200 * 1024 * 1024.
 */
Test(mbox_creation, page_size_fail)
{
	int ret;

	ret = gnix_mbox_allocator_create(ep_priv->nic, NULL, 2200,
					 1000, 12000, &allocator);
	assert_eq(ret, -FI_EINVAL,
		  "Creating allocator with bogus page size succeeded.");
	assert_eq(allocator, NULL);
	/*
	 *value is 1 because the provider has internally already opened
	 * an mbox allocator at this point.
	 */
	expect_eq(verify_hugepages(), 1,
		  "Huge page open, but shouldn't be");

	ret = gnix_mbox_allocator_destroy(allocator);
	assert_eq(ret, -FI_EINVAL,
		  "gnix_mbox_allocator_destroy succeeded on NULL handle.");
}

Test(mbox_creation, mbox_size_fail)
{
	int ret;

	/*
	 * mbox_size can't be zero.
	 */
	ret = gnix_mbox_allocator_create(ep_priv->nic, NULL, GNIX_PAGE_4MB,
					 0, 12000, &allocator);
	assert_eq(ret, -FI_EINVAL,
		  "Creating allocator with zero mbox size succeeded.");

	assert_eq(allocator, NULL);
	expect_eq(verify_hugepages(), 1,
		  "Huge page open, but shouldn't be");

	ret = gnix_mbox_allocator_destroy(allocator);
	assert_eq(ret, -FI_EINVAL,
		  "gnix_mbox_allocator_destroy succeeded on NULL handle.");
}

Test(mbox_creation, mpmmap_size_fail)
{
	int ret;

	/*
	 * Can't have zero mailboxes per mmap.
	 */
	ret = gnix_mbox_allocator_create(ep_priv->nic, NULL, GNIX_PAGE_4MB,
					 1000, 0, &allocator);
	assert_eq(ret, -FI_EINVAL,
		  "Creating allocator with zero mailboxes per mmap succeeded.");
	assert_eq(allocator, NULL);
	expect_eq(verify_hugepages(), 1,
		  "Huge page open, but shouldn't be");

	ret = gnix_mbox_allocator_destroy(allocator);
	assert_eq(ret, -FI_EINVAL,
		  "gnix_mbox_allocator_destroy succeeded on NULL handle.");
}

Test(mbox_creation, null_allocator_fail)
{
	int ret;

	/*
	 * Can't have a NULL allocator.
	 */
	ret = gnix_mbox_allocator_create(ep_priv->nic, NULL, GNIX_PAGE_4MB,
					 1000, 100, NULL);
	assert_eq(ret, -FI_EINVAL,
		  "Creating allocator with null allocator succeeded.");
	expect_eq(verify_hugepages(), 1,
		  "Huge page open, but shouldn't be");

	ret = gnix_mbox_allocator_destroy(allocator);
	assert_eq(ret, -FI_EINVAL,
		  "gnix_mbox_allocator_destroy succeeded on NULL handle.");
}

Test(mbox_creation, multi_allocation)
{
	int ret;

	size_t array_size = 5;
	size_t mbox_size = 1000;

	ptrdiff_t expected;
	ptrdiff_t actual;

	struct gnix_mbox *mbox_arr[array_size];

	ret = gnix_mbox_allocator_create(ep_priv->nic, NULL, GNIX_PAGE_4MB,
					 mbox_size, array_size, &allocator);
	assert_eq(ret, FI_SUCCESS, "gnix_mbox_allocator_create failed.");
	expect_eq(verify_hugepages(), 2,
		  "memory not found in /proc/self/maps.");

	/*
	 * Create an array of mailboxes of size array_size.
	 */
	for (int i = 0; i < array_size; i++) {
		ret = gnix_mbox_alloc(allocator, &(mbox_arr[i]));
		expect_eq(ret, FI_SUCCESS, "gnix_mbox_alloc failed.");
		expect(mbox_arr[i]);
	}

	/*
	 * Compare each mailbox to each other mailbox excluding the diagonal.
	 * The expected base should be a function of the mbox_size and the
	 * difference between their positions in the array. We can verify this
	 * against the offset inside the mailbox object.
	 */
	for (int i = 0; i < array_size; i++) {
		for (int j = 0; j < array_size; j++) {
			if (i == j)
				continue;

			actual = abs_value(mbox_arr[i]->offset -
					   mbox_arr[j]->offset);
			expected = abs_value(i - j) * mbox_size;

			expect_eq(actual, expected,
				  "Expected offsets and actual base offsets are not equal.");
		}
	}

	for (int i = 0; i < array_size; i++) {
		ret = gnix_mbox_free(mbox_arr[i]);
		expect_eq(ret, FI_SUCCESS, "gnix_mbox_free failed.");
	}

	ret = gnix_mbox_allocator_destroy(allocator);
	assert_eq(ret, FI_SUCCESS, "gnix_mbox_allocator_destroy failed.");

	expect_eq(verify_hugepages(), 1,
		  "memory not released in /proc/self/maps.");
}

Test(mbox_creation, double_free)
{
	int ret;

	struct gnix_mbox *mail_box;

	ret = gnix_mbox_allocator_create(ep_priv->nic, NULL, GNIX_PAGE_4MB,
					 1000, 12000, &allocator);
	assert_eq(ret, FI_SUCCESS, "gnix_mbox_allocator_create failed.");
	expect_eq(verify_hugepages(), 2,
		  "memory not found in /proc/self/maps.");

	ret = gnix_mbox_alloc(allocator, &mail_box);
	expect_eq(ret, FI_SUCCESS, "gnix_mbox_alloc failed.");

	expect(mail_box);
	/*
	 * Free allocated mailboxes so we can destroy cleanly.
	 */
	ret = gnix_mbox_free(mail_box);
	expect_eq(ret, FI_SUCCESS, "gnix_mbox_free failed.");

	/*
	 * Ensure double free fails.
	 */
	ret = gnix_mbox_free(mail_box);
	expect_eq(ret, -FI_EINVAL, "double free succeeded.");

	ret = gnix_mbox_allocator_destroy(allocator);
	assert_eq(ret, FI_SUCCESS, "gnix_mbox_allocator_destroy failed.");

	expect_eq(verify_hugepages(), 1,
		  "memory not released in /proc/self/maps.");
}

/*
 * Force the creation of two slabs by setting mpmmap to 1 and making a mailbox
 * the size of the entire page.
 */
Test(mbox_creation, two_slabs)
{
	int ret;

	/*
	 * Only have one mail box per slab.
	 */
	size_t mbox_size = GNIX_PAGE_4MB * 1024 * 1024;
	size_t mpmmap = 1;

	struct gnix_mbox *mbox_arr[2];

	ret = gnix_mbox_allocator_create(ep_priv->nic, NULL, GNIX_PAGE_4MB,
					 mbox_size, mpmmap, &allocator);
	assert_eq(ret, FI_SUCCESS, "gnix_mbox_allocator_create failed.");
	expect_eq(verify_hugepages(), 2,
		  "memory not found in /proc/self/maps.");

	/*
	 * Should use previously allocated slab
	 */
	ret = gnix_mbox_alloc(allocator, &(mbox_arr[0]));
	expect_eq(ret, FI_SUCCESS, "gnix_mbox_alloc failed.");

	/*
	 * Will need another slab. Allocation will occur.
	 */
	ret = gnix_mbox_alloc(allocator, &(mbox_arr[1]));
	expect_eq(ret, FI_SUCCESS, "gnix_mbox_alloc failed.");

	/*
	 * The bases should be different. The base is a per slab concept.
	 */
	expect_neq(mbox_arr[0]->base, mbox_arr[1]->base,
		   "Bases are the same.");

	/*
	 * The linked list should contain two slabs.
	 */
	expect_eq(2, count_slabs(allocator));

	ret = gnix_mbox_free(mbox_arr[0]);
	expect_eq(ret, FI_SUCCESS, "gnix_mbox_free failed.");

	ret = gnix_mbox_free(mbox_arr[1]);
	expect_eq(ret, FI_SUCCESS, "gnix_mbox_free failed.");

	ret = gnix_mbox_allocator_destroy(allocator);
	assert_eq(ret, FI_SUCCESS, "gnix_mbox_allocator_destroy failed.");

	expect_eq(verify_hugepages(), 1,
		  "memory not released in /proc/self/maps.");
}
