/*
 * Copyright (c) 2016 Mellanox Technologies(R). All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies(R) BSD license
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
 *      - Neither the name of the Mellanox Technologies(R) nor the names of its
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
#ifndef SRC_USR_TRANSPORT_UCX_XIO_UCX_TRANSPORT_H_
#define SRC_USR_TRANSPORT_UCX_XIO_UCX_TRANSPORT_H_

#include <xio_os.h>

#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_usr_transport.h"
#include "xio_transport.h"
#include "xio_protocol.h"
#include "get_clock.h"
#include "xio_mem.h"
#include "xio_mempool.h"
#include "xio_ev_data.h"
#include "xio_ev_loop.h"
#include "xio_sg_table.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"
#include "xio_ucx_transport.h"
#include "xio_context_priv.h"
#include "ucp/api/ucp.h"
#include <sys/socket.h>

/*---------------------------------------------------------------------------*/
/* externals								     */
/*---------------------------------------------------------------------------*/
extern double				g_mhz;


/* definitions */
#define NUM_TASKS			3264 /* 6 * (MAX_SEND_WR +
					      * MAX_RECV_WR + EXTRA_RQE)
					      */

#define RX_LIST_POST_NR			31   /* Initial number of buffers
					      * to put in the rx_list
					      */

#define COMPLETION_BATCH_MAX		64   /* Trigger TX completion every
					      * COMPLETION_BATCH_MAX
					      * packets
					      */

#define TX_BATCH			16   /* Number of TX tasks to batch */

#define RX_POLL_NR_MAX			16   /* Max num of RX messages
					      * to receive in one poll
					      */

#define XIO_TO_UCX_TASK(xt, tt)			\
		struct xio_ucx_task *(tt) =		\
			(struct xio_ucx_task *)(xt)->dd_data


/*---------------------------------------------------------------------------*/
/* enums								     */
/*---------------------------------------------------------------------------*/
enum xio_ucx_op_code {
	XIO_UCX_NULL,
	XIO_UCX_RECV		= 1,
	XIO_UCX_SEND,
	XIO_UCX_WRITE,
	XIO_UCX_READ
};

enum xio_ucx_rx_stage {
	XIO_UCX_RX_START,
	XIO_UCX_RX_TLV,
	XIO_UCX_RX_HEADER,
	XIO_UCX_RX_IO_DATA,
	XIO_UCX_RX_DONE
};

enum xio_ucx_tx_stage {
	XIO_UCX_TX_BEFORE,
	XIO_UCX_TX_IN_SEND,
	XIO_UCX_TX_DONE
};

/*---------------------------------------------------------------------------*/
struct xio_ucx_options {
	int			enable_mem_pool;
	int			enable_dma_latency;
	int			enable_mr_check;
	int			ucx_buf_threshold;
	int			ucx_buf_attr_rdonly;
	int			max_in_iovsz;
	int			max_out_iovsz;
	int			ucx_no_delay;
	int			ucx_so_sndbuf;
	int			ucx_so_rcvbuf;
};


#define XIO_UCX_REQ_HEADER_VERSION	1

struct __attribute__((__packed__)) xio_ucx_req_hdr {
	uint8_t			version;	/* request version	*/
	uint8_t			flags;
	uint16_t		req_hdr_len;	/* req header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		tid;		/* originator identifier*/
	uint8_t			opcode;		/* opcode  for peers	*/
	uint8_t			pad[1];

	uint16_t		recv_num_sge;
	uint16_t		read_num_sge;
	uint16_t		write_num_sge;

	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/
	uint32_t		remain_data_len;/* remaining data length */
	uint64_t		ulp_imm_len;	/* ulp data length	*/
};

#define XIO_UCX_RSP_HEADER_VERSION	1

struct __attribute__((__packed__)) xio_ucx_rsp_hdr {
	uint8_t			version;	/* response version     */
	uint8_t			flags;
	uint16_t		rsp_hdr_len;	/* rsp header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		tid;		/* originator identifier*/
	uint8_t			opcode;		/* opcode  for peers	*/
	uint8_t			pad[1];

	uint16_t		write_num_sge;

	uint32_t		status;		/* status		*/
	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/

	uint32_t		remain_data_len;/* remaining data length */
	uint64_t		ulp_imm_len;	/* ulp data length	*/
};

struct xio_ucp_addr {
	size_t addr_len;
	ucp_address_t addr;
};

struct __attribute__((__packed__)) xio_ucx_setup_msg {
	uint64_t		buffer_sz;
	uint32_t		max_in_iovsz;
	uint32_t		max_out_iovsz;
	struct xio_ucp_addr	ucp_addr;
};

struct __attribute__((__packed__)) xio_ucx_cancel_hdr {
	uint16_t		hdr_len;	 /* req header length	*/
	uint16_t		sn;		 /* msg serial number	*/
	uint32_t		result;
};

struct xio_ucx_work_req {
	struct iovec			*msg_iov;
	uint32_t			msg_len;
	uint32_t			tot_iov_byte_len;
	int				stage;
	uint32_t			pad;
	struct msghdr			msg;
};

struct xio_ucx_task {
	struct xio_ucx_transport	*ucx_hndl;

	enum xio_ucx_op_code		ucx_op;

	uint32_t			recv_num_sge;
	uint32_t			read_num_sge;
	uint32_t			write_num_sge;

	uint32_t			req_write_num_sge;
	uint32_t			rsp_write_num_sge;
	uint32_t			req_read_num_sge;
	uint32_t			req_recv_num_sge;

	uint16_t			sn;
	uint16_t			more_in_batch;

	uint16_t			pad[2];

	struct xio_ucx_work_req		txd;
	struct xio_ucx_work_req		rxd;

	/* User (from vmsg) or pool buffer used for */
	struct xio_mempool_obj		*read_sge;
	struct xio_mempool_obj		*write_sge;

	/* What this side got from the peer for SEND */
	/* What this side got from the peer for RDMA equivalent R/W
	 */
	struct xio_sge			*req_read_sge;
	struct xio_sge			*req_write_sge;

	/* What this side got from the peer for SEND
	 */
	struct xio_sge			*req_recv_sge;

	/* What this side writes to the peer on RDMA equivalent W
	 */
	struct xio_sge			*rsp_write_sge;


	xio_work_handle_t		comp_work;
};

struct xio_ucx_tasks_slab {
	void				*data_pool;
	struct xio_buf			*io_buf;
	int				buf_size;
	int				pad;
};

struct xio_ucx_transport {
	struct xio_transport_base	base;
	struct xio_mempool		*ucx_mempool;
	struct list_head		trans_list_entry;

	union xio_sockaddr		sa;

	/* UCX data */
	ucp_worker_h			ucp_worker;
	ucp_context_h			ucp_context;
	struct xio_ucp_addr		remote_addr;

	/*  tasks queues */
	struct list_head		tx_ready_list;
	struct list_head		tx_comp_list;
	struct list_head		in_flight_list;
	struct list_head		rx_list;
	struct list_head		io_list;

	int				sock_fd;

	/* fast path params */
	enum xio_transport_state	state;

	/* tx parameters */
	size_t				max_send_buf_sz;

	int				tx_ready_tasks_num;

	uint16_t			tx_comp_cnt;

	uint16_t			sn;	   /* serial number */

	uint16_t			pad[2];

	/* control path params */
	int				num_tasks;

	uint32_t			peer_max_in_iovsz;
	uint32_t			peer_max_out_iovsz;

	/* connection's flow control */
	size_t				alloc_sz;
	size_t				membuf_sz;

	struct xio_transport		*transport;
	struct xio_tasks_pool_cls	initial_pool_cls;
	struct xio_tasks_pool_cls	primary_pool_cls;

	struct xio_ucx_setup_msg	setup_rsp;

#ifdef HAVE_SENDMMSG
	struct mmsghdr			msgvec[TX_BATCH];
#endif
	/* too big to be on stack - use as temporaries */
	union {
		struct xio_msg		dummy_msg;
	};
};

int xio_ucx_send(struct xio_transport_base *transport,
		 struct xio_task *task);

int xio_ucx_rx_handler(struct xio_ucx_transport *ucx_hndl);

int xio_ucx_poll(struct xio_transport_base *transport,
		 long min_nr, long max_nr,
		 struct timespec *ts_timeout);

void xio_ucx_calc_pool_size(struct xio_ucx_transport *ucx_hndl);

struct xio_task *xio_ucx_primary_task_lookup(
					struct xio_ucx_transport *ucx_hndl,
					int tid);

struct xio_task *xio_ucx_primary_task_alloc(
					struct xio_ucx_transport *ucx_hndl);

void on_sock_disconnected(struct xio_ucx_transport *ucx_hndl,
			  int notify_observer);

int xio_ucx_cancel_req(struct xio_transport_base *transport,
		       struct xio_msg *req, uint64_t stag,
		       void *ulp_msg, size_t ulp_msg_sz);

int xio_ucx_cancel_rsp(struct xio_transport_base *transport,
		       struct xio_task *task, enum xio_status result,
		       void *ulp_msg, size_t ulp_msg_sz);

#endif /* XIO_UCX_TRANSPORT_H_ */

#endif /* SRC_USR_TRANSPORT_UCX_XIO_UCX_TRANSPORT_H_ */
