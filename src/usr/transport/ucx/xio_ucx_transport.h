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
#ifndef XIO_UCX_TRANSPORT_H_
#define XIO_UCX_TRANSPORT_H_

#include "ucp/api/ucp.h"


struct xio_ucx_transport;
struct xio_ucx_socket;

/*---------------------------------------------------------------------------*/
/* externals								     */
/*---------------------------------------------------------------------------*/
extern double				g_mhz;

/* definitions */
#define XIO_UCP_TAG			-1
#define XIO_TAG_MASK			1
#define XIO_UCX_REMOVE			1
#define XIO_CONTIG			ucp_dt_make_contig(1)
#define NUM_TASKS			54400 /* 100 * (MAX_SEND_WR +
					      * MAX_RECV_WR + EXTRA_RQE)
					      */

#define RX_LIST_POST_NR			31   /* Initial number of buffers
					      * to put in the rx_list
					      */

#define COMPLETION_BATCH_MAX		64   /* Trigger TX completion every
					      * COMPLETION_BATCH_MAX
					      * packets
					      */

#define TX_BATCH			32   /* Number of TX tasks to batch */

#define TX_EAGAIN_RETRY			2    /* Number of retries when send
					      * fail with EAGAIN before return.
					      */

#define RX_POLL_NR_MAX			4    /* Max num of RX messages
					      * to receive in one poll
					      */

#define RX_BATCH			32   /* Number of RX tasks to batch */

#define MAX_BACKLOG			1024 /* listen socket max backlog   */

#define TMP_RX_BUF_SIZE			(RX_BATCH * MAX_HDR_SZ)

#define XIO_TO_UCX_TASK(xt, tt)			\
		struct xio_ucx_task *(tt) =		\
			(struct xio_ucx_task *)(xt)->dd_data
#define XIO_TO_UCX_HNDL(xt, th)				\
		struct xio_ucx_transport *(th) =		\
			(struct xio_ucx_transport *)(xt)->context

#define PAGE_SIZE                       page_size

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
	XIO_UCX_TX_IN_SEND_CTL,
	XIO_UCX_TX_IN_SEND_DATA,
	XIO_UCX_TX_DONE
};

enum xio_ucx_sock_type {
	XIO_UCX_SINGLE_SOCK = 1,
	XIO_UCX_CTL_SOCK,
	XIO_UCX_DATA_SOCK
};

/*---------------------------------------------------------------------------*/
struct xio_ucx_options {
	int			enable_mem_pool;
	int			enable_dma_latency;
	int			enable_mr_check;
	int			max_in_iovsz;
	int			max_out_iovsz;
	int			ucx_no_delay;
	int			ucx_so_sndbuf;
	int			ucx_so_rcvbuf;
	int			ucx_dual_sock;
	int			pad;
};

#define XIO_UCX_REQ_HEADER_VERSION	1

PACKED_MEMORY(struct xio_ucx_req_hdr {
	uint8_t			version;	/* request version	*/
	uint8_t			flags;
	uint16_t		req_hdr_len;	/* req header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		pad0;

	uint32_t		ltid;		/* originator identifier*/
	uint16_t		pad;
	uint8_t			in_ucx_op;	/* opcode  for peers	*/
	uint8_t			out_ucx_op;

	uint16_t		in_num_sge;
	uint16_t		out_num_sge;
	uint32_t		pad1;

	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/
	uint32_t		remain_data_len;/* remaining data length */

	uint64_t		ulp_imm_len;	/* ulp data length	*/
});

#define XIO_UCX_RSP_HEADER_VERSION	1

PACKED_MEMORY(struct xio_ucx_rsp_hdr {
	uint8_t			version;	/* response version     */
	uint8_t			flags;
	uint16_t		rsp_hdr_len;	/* rsp header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		pad;

	uint32_t		ltid;		/* local task id	*/
	uint32_t                rtid;           /* remote task id       */

	uint8_t			out_ucx_op;	/* opcode  for peers	*/
	uint8_t			pad1;
	uint16_t		out_num_sge;
	uint32_t		status;		/* status		*/

	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/
	uint32_t		remain_data_len;/* remaining data length */

	uint64_t		ulp_imm_len;	/* ulp data length	*/
});

struct xio_ucp_worker {
	ucp_worker_h		worker;
	size_t			addr_len;
	ucp_address_t		*addr;
};

struct xio_ucp_callback_data {
	struct xio_ucx_transport	*transport;
	int				completed;
};

struct xio_ucp_container {
	struct xio_ucx_transport	*ucx_handler;
	size_t				data_length;
	void				*data;
};

struct xio_ucx_connect_msg {
	size_t			length;
	char			data[256];
};

PACKED_MEMORY(struct xio_ucx_setup_msg {
	uint64_t		buffer_sz;
	uint32_t		max_in_iovsz;
	uint32_t		max_out_iovsz;
	uint32_t		max_header_len;
	uint32_t		pad;
});

PACKED_MEMORY(struct xio_ucx_cancel_hdr {
	uint16_t		hdr_len;	 /* req header length	*/
	uint16_t		sn;		 /* msg serial number	*/
	uint32_t		result;
});

struct xio_ucx_work_req {
	struct iovec			*msg_iov;
	uint32_t			msg_len;
	uint32_t			pad;
	uint64_t			tot_iov_byte_len;
	void				*ctl_msg;
	uint32_t			ctl_msg_len;
	int				stage;
	struct msghdr			msg;
};

struct xio_ucx_task {
	enum xio_ucx_op_code		in_ucx_op;
	enum xio_ucx_op_code		out_ucx_op;

	struct xio_ucx_work_req		txd;
	struct xio_ucx_work_req		rxd;


	/* User (from vmsg) or pool buffer used for */
	uint16_t			read_num_reg_mem;
	uint16_t			write_num_reg_mem;
	uint32_t			pad0;

	struct xio_reg_mem		*read_reg_mem;
	struct xio_reg_mem		*write_reg_mem;

	uint16_t			req_in_num_sge;
	uint16_t			req_out_num_sge;
	uint16_t			rsp_out_num_sge;
	uint16_t			sn;

	/* What this side got from the peer for SEND */
	/* What this side got from the peer for RDMA equivalent R/W
	 */
	/* can serve send/rdma write  */
	struct xio_sge			*req_in_sge;

	/* can serve send/rdma read  */
	struct xio_sge			*req_out_sge;

	/* can serve send/rdma read response/rdma write  */
	struct xio_sge			*rsp_out_sge;

	xio_work_handle_t		comp_work;
};

struct xio_ucx_tasks_slab {
	void				*data_pool;
	struct xio_reg_mem		reg_mem;
	int				buf_size;
	int				pad;
};

struct xio_ucx_pending_conn {
	int				fd;
	int				waiting_for_bytes;
	union xio_sockaddr		sa;
	struct xio_ucx_connect_msg	msg;
	struct list_head		conns_list_entry;
};

struct xio_ucx_socket_ops {
	int (*open)(struct xio_ucx_socket *sock);
	int (*add_ev_handlers)(struct xio_ucx_transport *ucx_hndl);
	int (*del_ev_handlers)(struct xio_ucx_transport *ucx_hndl);
	int (*connect)(struct xio_ucx_transport *ucx_hndl,
		       struct sockaddr *sa, socklen_t sa_len);
	size_t (*set_txd)(struct xio_task *task);
	void (*set_rxd)(struct xio_task *task, void *buf, uint32_t len);
	int (*rx_ctl_work)(struct xio_ucx_transport *ucx_hndl, int fd,
			   struct xio_ucx_work_req *xio_recv,
			   int block);
	int (*rx_ctl_handler)(struct xio_ucx_transport *ucx_hndl);
	int (*rx_data_handler)(struct xio_ucx_transport *ucx_hndl,
			       int batch_nr);
	int (*shutdown)(struct xio_ucx_socket *sock);
	int (*close)(struct xio_ucx_socket *sock);
};

struct xio_ucx_socket {
	int				cfd;
	uint16_t			port_cfd;
	int				pad;
	struct xio_ucx_socket_ops	ops[1];
};
struct xio_ucx_transport {
	struct xio_transport_base	base;
	struct xio_mempool		*ucx_mempool;
	struct list_head		trans_list_entry;

	/*  tasks queues */
	struct list_head		tx_ready_list;
	struct list_head		tx_comp_list;
	struct list_head		in_flight_list;
	struct list_head		rx_list;
	struct list_head		io_list;

	ucp_ep_h			ucp_ep;
	struct xio_ucx_socket		sock;
	uint16_t			is_listen;
	uint8_t				in_epoll[2];
	/* fast path params */
	enum xio_transport_state	state;

	/* tx parameters */
	size_t				max_inline_buf_sz;

	int				tx_ready_tasks_num;

	uint16_t			tx_comp_cnt;

	uint16_t			sn;	   /* serial number */

	/* control path params */

	uint32_t			peer_max_in_iovsz;
	uint32_t			peer_max_out_iovsz;

	/* connection's flow control */
	size_t				membuf_sz;

	struct xio_transport		*transport;
	struct xio_tasks_pool_cls	initial_pool_cls;
	struct xio_tasks_pool_cls	primary_pool_cls;

	struct xio_ucx_setup_msg	setup_rsp;

	/* too big to be on stack - use as temporaries */
	union {
		struct xio_msg		dummy_msg;
	};

	struct list_head		pending_conns;

	void				*tmp_rx_buf;
	void				*tmp_rx_buf_cur;
	uint32_t			tmp_rx_buf_len;
	uint32_t			peer_max_header;

	uint32_t			trans_attr_mask;
	struct xio_transport_attr	trans_attr;

	struct xio_ucx_work_req		tmp_work;
	struct iovec			tmp_iovec[IOV_MAX];

	struct xio_ev_data		flush_tx_event;
	struct xio_ev_data		ctl_rx_event;
	struct xio_ev_data		disconnect_event;
};

int xio_ucx_get_max_header_size(void);
void xio_ucx_addr_send(void *user_context);
void xio_ucx_general_send_cb(void *user_context,ucs_status_t status);
void xio_ucx_pending_ucx_handler(int fd, int events, void *user_context);
int xio_ucx_get_inline_buffer_size(void);

int xio_ucx_send(struct xio_transport_base *transport,
		 struct xio_task *task);

int xio_ucx_rx_handler(struct xio_ucx_transport *ucx_hndl);

int xio_ucx_poll(struct xio_transport_base *transport,
		 long min_nr, long max_nr,
		 struct timespec *ts_timeout);

struct xio_task *xio_ucx_primary_task_lookup(
					struct xio_ucx_transport *ucx_hndl,
					int tid);

struct xio_task *xio_ucx_primary_task_alloc(
					struct xio_ucx_transport *ucx_hndl);

int xio_ucx_cancel_req(struct xio_transport_base *transport,
		       struct xio_msg *req, uint64_t stag,
		       void *ulp_msg, size_t ulp_msg_sz);

int xio_ucx_cancel_rsp(struct xio_transport_base *transport,
		       struct xio_task *task, enum xio_status result,
		       void *ulp_msg, size_t ulp_msg_sz);

int xio_ucx_send_connect_msg(int fd, struct xio_ucx_connect_msg *msg);

size_t xio_ucx_single_sock_set_txd(struct xio_task *task);
size_t xio_ucx_dual_sock_set_txd(struct xio_task *task);
void xio_ucx_single_sock_set_rxd(struct xio_task *task, void *buf,
				 uint32_t len);
void xio_ucx_dual_sock_set_rxd(struct xio_task *task, void *buf, uint32_t len);

int xio_ucx_rx_ctl_handler(struct xio_ucx_transport *ucx_hndl, int batch_nr);
int xio_ucx_rx_data_handler(struct xio_ucx_transport *ucx_hndl, int batch_nr);
int xio_ucx_recv_ctl_work(struct xio_ucx_transport *ucx_hndl, int fd,
			  struct xio_ucx_work_req *xio_recv, int block);
int xio_ucx_recvmsg_work(struct xio_ucx_transport *ucx_hndl, int fd,
			 struct xio_ucx_work_req *xio_recv, int block);

void xio_ucx_disconnect_helper(void *xio_ucx_hndl);

int xio_ucx_xmit(struct xio_ucx_transport *ucx_hndl);
void xio_ucx_get_ucp_server_adrs(int fd, int events, void *user_context);
#endif /* XIO_UCX_TRANSPORT_H_ */
