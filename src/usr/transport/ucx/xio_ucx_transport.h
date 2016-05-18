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

#define MAX_BACKLOG			1024 /* listen socket max backlog   */

enum xio_ucx_rx_stage {
	XIO_UCX_RX_START,
	XIO_UCX_RX_TLV,
	XIO_UCX_RX_HEADER,
	XIO_UCX_RX_IO_DATA,
	XIO_UCX_RX_DONE
};

enum xio_tcp_tx_stage {
	XIO_UCX_TX_BEFORE,
	XIO_UCX_TX_IN_SEND_CTL,
	XIO_UCX_TX_IN_SEND_DATA,
	XIO_UCX_TX_DONE
};

struct xio_ucx_options {
};

PACKED_MEMORY(struct xio_ucx_req_hdr {
	uint8_t		version;	/* request version     */
	uint8_t		flags;
	uint16_t	req_hdr_len;	/* req header length   */
	uint16_t	sn;		/* serial number	*/
	uint16_t	ack_sn;	/* ack serial number   */

	uint16_t	credits;	/* peer send credits   */
	uint32_t	ltid;		/* originator identifier*/
	uint16_t	pad;

	uint16_t	in_num_sge;
	uint16_t	out_num_sge;
	uint32_t	pad1;

	uint16_t	ulp_hdr_len;   /* ulp header length   */
	uint16_t	ulp_pad_len;   /* pad_len length      */
	uint32_t	remain_data_len;/* remaining data length */
	uint64_t	ulp_imm_len;   /* ulp data length     */
});

PACKED_MEMORY(struct xio_ucx_rsp_hdr {
	uint8_t		version;	/* response version     */
	uint8_t		flags;
	uint16_t	rsp_hdr_len;   /* rsp header length   */
	uint16_t	sn;    	/* serial number	*/
	uint16_t	ack_sn;	/* ack serial number   */

	uint16_t	credits;	/* peer send credits   */
	uint32_t	rtid;  	/* originator identifier*/
	uint32_t		pad;
	uint16_t	out_num_sge;
	uint32_t	status;	/* status      	*/

	uint32_t	ltid;  	/* local task id	*/
	uint16_t	ulp_hdr_len;   /* ulp header length   */
	uint16_t	ulp_pad_len;   /* pad_len length      */
	uint32_t	remain_data_len;/* remaining data length */
	uint64_t	ulp_imm_len;   /* ulp data length     */
});

struct xio_ucp_addrs {
	ucp_address_t * addr;
	size_t addr_len;
};

PACKED_MEMORY(struct xio_ucx_conn_msg {
	struct xio_ucp_addrs;
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


struct xio_ucx_transport {
	struct xio_transport_base	base;
	struct xio_mempool		*tcp_mempool;
	struct list_head		trans_list_entry;

	/* UCP related structs */
	ucp_context_h			ucp_context;
	ucp_worker_h			ucp_worker;
	struct xio_ucp_addrs		remote_addr;

	/*  tasks queues */
	struct list_head		tx_ready_list;
	struct list_head		tx_comp_list;
	struct list_head		in_flight_list;
	struct list_head		rx_list;
	struct list_head		io_list;

	int				fd_sock;
	uint16_t			port;
	uint8_t				is_listen;
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

	struct xio_tcp_setup_msg	setup_rsp;

	struct list_head		pending_conns;

	void				*tmp_rx_buf;
	void				*tmp_rx_buf_cur;
	uint32_t			tmp_rx_buf_len;
	uint32_t			peer_max_header;

	uint32_t			trans_attr_mask;
	struct xio_transport_attr	trans_attr;

	struct xio_tcp_work_req		tmp_work;
	struct iovec			tmp_iovec[IOV_MAX];

	struct xio_ev_data		flush_tx_event;
	struct xio_ev_data		ctl_rx_event;
	struct xio_ev_data		disconnect_event;
};
struct xio_ucx_work_req {
};
struct xio_ucx_task {
	enum xio_ib_op_code		out_ib_op;
	enum xio_ib_op_code		in_ib_op;

	/* The buffer mapped with the 3 xio_work_req
	 * used to transfer the headers
	 */
	struct xio_ucx_work_req		txd;
	struct xio_ucx_work_req		rxd;
	struct xio_ucx_work_req		rdmad;

	/* User (from vmsg) or pool buffer used for */
	uint16_t			read_num_reg_mem;
	uint16_t			write_num_reg_mem;
	uint32_t			pad0;

	/* What this side got from the peer for RDMA R/W
	 */
	uint16_t			req_in_num_sge;
	uint16_t			req_out_num_sge;
	uint16_t			rsp_out_num_sge;
	uint16_t			pad1;

	/* can serve send/rdma write  */
	struct xio_sge			*req_in_sge;

	/* can serve send/rdma read  */
	struct xio_sge			*req_out_sge;

};

};
#endif /* SRC_USR_TRANSPORT_UCX_XIO_UCX_TRANSPORT_H_ */
