/*
 * Copyright (c) 2013 Mellanox Technologies®. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies® BSD license
 * below:
 *
 *      - Redistribution and use in source and binary forms, with or without
 *        modification, are permitted provided that the following conditions
 *        are met:
 *
 *      - Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 *      - Neither the name of the Mellanox Technologies® nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <xio_env.h>
#include <xio_os.h>
#include "xio_log.h"
#include "xio_common.h"
#include "xio_mem.h"
#ifdef HAVE_INFINIBAND_VERBS_H
#include <infiniband/verbs.h>
#include "xio_transport.h"
#include "xio_workqueue.h"
#include "xio_rdma_transport.h"
#endif

#define HUGE_PAGE_SZ			(2*1024*1024)
#ifndef WIN32
int			  disable_huge_pages	= 0;
#else
int			  disable_huge_pages	= 1; /* bypass hugepages */
#endif
int			  allocator_assigned	= 0;
struct xio_mem_allocator  g_mem_allocator;
struct xio_mem_allocator *mem_allocator = &g_mem_allocator;

#ifdef HAVE_INFINIBAND_VERBS_H

/*---------------------------------------------------------------------------*/
/* xio_register_transport						     */
/*---------------------------------------------------------------------------*/
static int xio_register_reg_mem_transports(void)
{
	static int init_transport;
	static int result;
	/* this may the first call in application so initialize the rdma */
	if (result)
		return init_transport;
	result = 1;
	if (!init_transport) {
		struct xio_transport *transport = xio_get_transport("rdma");

		if (!transport)
			return 0;

		init_transport = 1;
	}

	return init_transport;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_register_no_dev						     */
/*---------------------------------------------------------------------------*/
static inline int xio_mem_register_no_dev(void *addr, size_t length,
					  struct xio_reg_mem *reg_mem)
{
	static struct xio_mr dummy_mr;

	reg_mem->addr = addr;
	reg_mem->length = length;
	reg_mem->mr = &dummy_mr;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_dereg_no_dev							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mem_dereg_no_dev(struct xio_reg_mem *reg_mem)
{
	reg_mem->mr = NULL;
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_free_no_dev							     */
/*---------------------------------------------------------------------------*/
static int xio_mem_free_no_dev(struct xio_reg_mem *reg_mem)
{
	int retval = 0;

	if (reg_mem->addr)
		ufree(reg_mem->addr);

	retval = xio_mem_dereg_no_dev(reg_mem);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_alloc_no_dev							     */
/*---------------------------------------------------------------------------*/
static int xio_mem_alloc_no_dev(size_t length, struct xio_reg_mem *reg_mem)
{
	size_t			real_size;
	int			alloced = 0;

	real_size = ALIGN(length, page_size);
	reg_mem->addr = umemalign(page_size, real_size);
	if (!reg_mem->addr) {
		ERROR_LOG("xio_memalign failed. sz:%zu\n", real_size);
		goto cleanup;
	}
	/*memset(reg_mem->addr, 0, real_size);*/
	alloced = 1;

	xio_mem_register_no_dev(reg_mem->addr, length, reg_mem);
	if (!reg_mem->mr) {
		ERROR_LOG("xio_reg_mr failed. addr:%p, length:%d access %d\n",
			  reg_mem->addr, length, reg_mem->mr->access);

		goto cleanup1;
	}
	reg_mem->length = length;

	return 0;

cleanup1:
	if (alloced)
		ufree(reg_mem->addr);
cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_register							     */
/*---------------------------------------------------------------------------*/
int xio_mem_register(void *addr, size_t length, struct xio_reg_mem *reg_mem)
{
	if (!addr || length == 0) {
		xio_set_error(EINVAL);
		return -1;
	}
	if (list_empty(&dev_list) && !xio_register_reg_mem_transports())
		return xio_mem_register_no_dev(addr, length, reg_mem);

	reg_mem->mr = xio_reg_mr_ex(&addr, length,
			     IBV_ACCESS_LOCAL_WRITE  |
			     IBV_ACCESS_REMOTE_WRITE |
			     IBV_ACCESS_REMOTE_READ);
	if (!reg_mem->mr)
		return -1;

	reg_mem->addr	= addr;
	reg_mem->length = length;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_dereg							     */
/*---------------------------------------------------------------------------*/
int xio_mem_dereg(struct xio_reg_mem *reg_mem)
{
	int retval;

	if (!reg_mem->mr) {
		xio_set_error(EINVAL);
		return -1;
	}
	if (list_empty(&dev_list))
		return xio_mem_dereg_no_dev(reg_mem);

	retval = xio_dereg_mr(reg_mem->mr);

	reg_mem->mr = NULL;

	return  retval;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_alloc							     */
/*---------------------------------------------------------------------------*/
int xio_mem_alloc(size_t length, struct xio_reg_mem *reg_mem)
{
	struct xio_device	*dev;
	size_t			real_size;
	uint64_t		access;

	if (length == 0 || !reg_mem) {
		xio_set_error(EINVAL);
		ERROR_LOG("xio_mem_alloc failed. length:%zu\n", length);
		return -1;
	}
	if (list_empty(&dev_list)) {
		if (!xio_register_reg_mem_transports() && list_empty(&dev_list))
			return xio_mem_alloc_no_dev(length, reg_mem);
	}

	access = IBV_ACCESS_LOCAL_WRITE  |
		 IBV_ACCESS_REMOTE_WRITE |
		 IBV_ACCESS_REMOTE_READ;

	dev = list_first_entry(&dev_list, struct xio_device, dev_list_entry);

	if (dev && IBV_IS_MPAGES_AVAIL(&dev->device_attr)) {
		access |= IBV_XIO_ACCESS_ALLOCATE_MR;
		reg_mem->addr = NULL;
		reg_mem->mr = xio_reg_mr_ex(&reg_mem->addr, length, access);
		if (reg_mem->mr) {
			reg_mem->length			= length;
			reg_mem->mr->addr_alloced	= 0;
			goto exit;
		}
		WARN_LOG("Contig pages allocation failed. (errno=%d %m)\n",
			 errno);
	}

	real_size = ALIGN(length, page_size);
	reg_mem->addr = umemalign(page_size, real_size);
	if (unlikely(!reg_mem->addr)) {
		xio_set_error(ENOMEM);
		ERROR_LOG("memalign failed. sz:%zu\n", real_size);
		goto cleanup;
	}
	reg_mem->mr = xio_reg_mr_ex(&reg_mem->addr, length, access);
	if (unlikely(!reg_mem->mr)) {
		ERROR_LOG("xio_reg_mr_ex failed. "
			  "addr:%p, length:%d, access:0x%x\n",
			   reg_mem->addr, length, access);

		goto cleanup1;
	}
	/*memset(reg_mem->addr, 0, length);*/
	reg_mem->length			= length;
	reg_mem->mr->addr_alloced	= 1;

exit:
	return 0;

cleanup1:
	ufree(reg_mem->addr);
cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_free								     */
/*---------------------------------------------------------------------------*/
int xio_mem_free(struct xio_reg_mem *reg_mem)
{
	int retval;

	if (!reg_mem->mr) {
		xio_set_error(EINVAL);
		return -1;
	}
	if (list_empty(&dev_list))
		return xio_mem_free_no_dev(reg_mem);

	if (reg_mem->mr->addr_alloced) {
		ufree(reg_mem->addr);
		reg_mem->addr = NULL;
		reg_mem->mr->addr_alloced = 0;
	}

	retval = xio_dereg_mr(reg_mem->mr);

	reg_mem->mr = NULL;

	return retval;
}

#else
/*---------------------------------------------------------------------------*/
/* xio_mem_register							     */
/*---------------------------------------------------------------------------*/
int xio_mem_register(void *addr, size_t length, struct xio_reg_mem *reg_mem)
{
	static struct xio_mr dummy_mr;

	if (!addr || !reg_mem) {
		xio_set_error(EINVAL);
		return -1;
	}

	reg_mem->addr = addr;
	reg_mem->length = length;
	reg_mem->mr = &dummy_mr;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_dereg							     */
/*---------------------------------------------------------------------------*/
int xio_mem_dereg(struct xio_reg_mem *reg_mem)
{
	reg_mem->mr = NULL;
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_alloc							     */
/*---------------------------------------------------------------------------*/
int xio_mem_alloc(size_t length, struct xio_reg_mem *reg_mem)
{
	size_t			real_size;
	int			alloced = 0;

	real_size = ALIGN(length, page_size);
	reg_mem->addr = umemalign(page_size, real_size);
	if (!reg_mem->addr) {
		ERROR_LOG("xio_memalign failed. sz:%zu\n", real_size);
		goto cleanup;
	}
	/*memset(reg_mem->addr, 0, real_size);*/
	alloced = 1;

	xio_mem_register(reg_mem->addr, length, reg_mem);
	if (!reg_mem->mr) {
		ERROR_LOG("xio_reg_mr failed. addr:%p, length:%d\n",
			  reg_mem->addr, length, access);

		goto cleanup1;
	}
	reg_mem->length = length;

	return 0;

cleanup1:
	if (alloced)
		ufree(reg_mem->addr);
cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_free								     */
/*---------------------------------------------------------------------------*/
int xio_mem_free(struct xio_reg_mem *reg_mem)
{
	int			retval = 0;

	if (reg_mem->addr)
		ufree(reg_mem->addr);

	retval = xio_mem_dereg(reg_mem);

	return retval;
}

#endif /*HAVE_INFINIBAND_VERBS_H*/

/*---------------------------------------------------------------------------*/
/* malloc_huge_pages	                                                     */
/*---------------------------------------------------------------------------*/
void *malloc_huge_pages(size_t size)
{
	int retval;
	size_t	real_size;
	void	*ptr = NULL;

	if (disable_huge_pages) {
		long page_size = xio_get_page_size();

		if (page_size < 0) {
			xio_set_error(errno);
			ERROR_LOG("sysconf failed. (errno=%d %m)\n", errno);
			return NULL;
		}

		real_size = ALIGN(size, page_size);
		retval = xio_memalign(&ptr, page_size, real_size);
		if (retval) {
			ERROR_LOG("posix_memalign failed sz:%zu. %s\n",
				  real_size, strerror(retval));
			return NULL;
		}
		memset(ptr, 0, real_size);
		return ptr;
	}

	/* Use 1 extra page to store allocation metadata */
	/* (libhugetlbfs is more efficient in this regard) */
	real_size = ALIGN(size + HUGE_PAGE_SZ, HUGE_PAGE_SZ);

	ptr = xio_mmap(real_size);
	if (!ptr || ptr == MAP_FAILED) {
		/* The mmap() call failed. Try to malloc instead */
		long page_size = xio_get_page_size();

		if (page_size < 0) {
			xio_set_error(errno);
			ERROR_LOG("sysconf failed. (errno=%d %m)\n", errno);
			return NULL;
		}
		WARN_LOG("huge pages allocation failed, allocating " \
			 "regular pages\n");

		DEBUG_LOG("mmap rdma pool sz:%zu failed (errno=%d %m)\n",
			  real_size, errno);
		real_size = ALIGN(size + HUGE_PAGE_SZ, page_size);
		retval = xio_memalign(&ptr, page_size, real_size);
		if (retval) {
			ERROR_LOG("posix_memalign failed sz:%zu. %s\n",
				  real_size, strerror(retval));
			return NULL;
		}
		memset(ptr, 0, real_size);
		real_size = 0;
	} else {
		DEBUG_LOG("Allocated huge page sz:%zu\n", real_size);
	}
	/* Save real_size since mmunmap() requires a size parameter */
	*((size_t *)ptr) = real_size;
	/* Skip the page with metadata */
	return sum_to_ptr(ptr, HUGE_PAGE_SZ);
}

/*---------------------------------------------------------------------------*/
/* free_huge_pages	                                                     */
/*---------------------------------------------------------------------------*/
void free_huge_pages(void *ptr)
{
	void	*real_ptr;
	size_t	real_size;

	if (!ptr)
		return;

	if (disable_huge_pages)  {
		free(ptr);
		return;
	}

	/* Jump back to the page with metadata */
	real_ptr = (char *)ptr - HUGE_PAGE_SZ;
	/* Read the original allocation size */
	real_size = *((size_t *)real_ptr);

	if (real_size != 0)
		/* The memory was allocated via mmap()
		   and must be deallocated via munmap()
		   */
		xio_munmap(real_ptr, real_size);
	else
		/* The memory was allocated via malloc()
		   and must be deallocated via free()
		   */
		free(real_ptr);
}

/*---------------------------------------------------------------------------*/
/* xio_numa_alloc	                                                     */
/*---------------------------------------------------------------------------*/
void *xio_numa_alloc(size_t bytes, int node)
{
	size_t real_size = ALIGN((bytes + page_size), page_size);
	void *p = xio_numa_alloc_onnode(real_size, node);

	if (!p) {
		ERROR_LOG("numa_alloc_onnode failed sz:%zu. %m\n",
			  real_size);
		return NULL;
	}
	/* force the OS to allocate physical memory for the region */
	memset(p, 0, real_size);

	/* Save real_size since numa_free() requires a size parameter */
	*((size_t *)p) = real_size;

	/* Skip the page with metadata */
	return sum_to_ptr(p, page_size);
}

/*---------------------------------------------------------------------------*/
/* xio_numa_free_ptr	                                                     */
/*---------------------------------------------------------------------------*/
void xio_numa_free_ptr(void *ptr)
{
	void	*real_ptr;
	size_t	real_size;

	if (!ptr)
		return;

	/* Jump back to the page with metadata */
	real_ptr = (char *)ptr - page_size;
	/* Read the original allocation size */
	real_size = *((size_t *)real_ptr);

	if (real_size != 0)
		/* The memory was allocated via numa_alloc()
		   and must be deallocated via numa_free()
		   */
		xio_numa_free(real_ptr, real_size);
}
