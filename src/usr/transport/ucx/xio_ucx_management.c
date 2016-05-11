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

#include <xio_predefs.h>
#include <xio_env.h>
#include <xio_os.h>
#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_mempool.h"
#include "xio_sg_table.h"
#include "xio_transport.h"
#include "xio_usr_transport.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"
#include "xio_ucx_transport.h"
#include "xio_mem.h"

struct xio_transport xio_ucx_transport = {
	.name			= "ucx",
	.ctor			= NULL,
	.dtor			= NULL,
	.init			= NULL,
	.release		= NULL,
	.context_shutdown	= NULL,
	.open			= NULL,
	.connect		= NULL,
	.listen			= NULL,
	.accept			= NULL,
	.reject			= NULL,
	.close			= NULL,
	.dup2			= NULL,
	.update_task		= NULL,
	.update_rkey		= NULL,
	.send			= NULL,
	.poll			= NULL,
	.set_opt		= NULL,
	.get_opt		= NULL,
	.cancel_req		= NULL,
	.cancel_rsp		= NULL,
	.get_pools_setup_ops	= NULL,
	.set_pools_cls		= NULL,
	.modify			= NULL,
	.query			= NULL,

	.validators_cls.is_valid_in_req  = NULL,
	.validators_cls.is_valid_out_msg = NULL,
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_get_transport_func_list                                          */
/*---------------------------------------------------------------------------*/
struct xio_transport *xio_ucx_get_transport_func_list(void)
{
	return &xio_ucx_transport;
}
