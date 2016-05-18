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


};
#endif /* SRC_USR_TRANSPORT_UCX_XIO_UCX_TRANSPORT_H_ */
