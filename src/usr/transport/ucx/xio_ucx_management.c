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
#include "xio_tcp_transport.h"
#include "xio_mem.h"

/* default option values */
#define XIO_OPTVAL_DEF_ENABLE_MEM_POOL			1
#define XIO_OPTVAL_DEF_ENABLE_MR_CHECK			0
#define XIO_OPTVAL_DEF_UCX_ENABLE_DMA_LATENCY		0
#define XIO_OPTVAL_DEF_UCX_MAX_IN_IOVSZ			XIO_IOVLEN
#define XIO_OPTVAL_DEF_UCX_MAX_OUT_IOVSZ		XIO_IOVLEN
#define XIO_OPTVAL_DEF_UCX_NO_DELAY			0
#define XIO_OPTVAL_DEF_UCX_SO_SNDBUF			4194304
#define XIO_OPTVAL_DEF_UCX_SO_RCVBUF			4194304
#define XIO_OPTVAL_DEF_UCX_DUAL_SOCK			1

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static spinlock_t			mngmt_lock;
static thread_once_t			ctor_key_once = THREAD_ONCE_INIT;
static thread_once_t			dtor_key_once = THREAD_ONCE_INIT;
extern struct xio_transport		xio_ucx_transport;

static int				cdl_fd = -1;

struct xio_ucp_addr			local_addr;


/* ucx options */
struct xio_ucx_options			ucx_options = {
	.enable_mem_pool		= XIO_OPTVAL_DEF_ENABLE_MEM_POOL,
	.enable_dma_latency		= XIO_OPTVAL_DEF_UCX_ENABLE_DMA_LATENCY,
	.enable_mr_check		= XIO_OPTVAL_DEF_ENABLE_MR_CHECK,
	.ucx_buf_threshold		= 0,
	.ucx_buf_attr_rdonly		= 0,
	.max_in_iovsz			= XIO_OPTVAL_DEF_UCX_MAX_IN_IOVSZ,
	.max_out_iovsz			= XIO_OPTVAL_DEF_UCX_MAX_OUT_IOVSZ,
	.ucx_no_delay			= XIO_OPTVAL_DEF_UCX_NO_DELAY,
	.ucx_so_sndbuf			= XIO_OPTVAL_DEF_UCX_SO_SNDBUF,
	.ucx_so_rcvbuf			= XIO_OPTVAL_DEF_UCX_SO_RCVBUF,
};

/*---------------------------------------------------------------------------*/
/* xio_tcp_get_inline_buffer_size					     */
/*---------------------------------------------------------------------------*/
int xio_tcp_get_inline_buffer_size(void)
{
	int inline_buf_sz = ALIGN(xio_tcp_get_max_header_size() +
				  g_options.max_inline_xio_hdr +
				  g_options.max_inline_xio_data, 1024);
	return inline_buf_sz;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_flush_all_tasks						     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_flush_all_tasks(struct xio_ucx_transport *ucx_hndl)
{
	if (!list_empty(&ucx_hndl->in_flight_list)) {
		TRACE_LOG("in_flight_list not empty!\n");
		xio_transport_flush_task_list(&ucx_hndl->in_flight_list);
		/* for task that attched to senders with ref count = 2 */
		xio_transport_flush_task_list(&ucx_hndl->in_flight_list);
	}

	if (!list_empty(&ucx_hndl->tx_comp_list)) {
		TRACE_LOG("tx_comp_list not empty!\n");
		xio_transport_flush_task_list(&ucx_hndl->tx_comp_list);
	}
	if (!list_empty(&ucx_hndl->io_list)) {
		TRACE_LOG("io_list not empty!\n");
		xio_transport_flush_task_list(&ucx_hndl->io_list);
	}

	if (!list_empty(&ucx_hndl->tx_ready_list)) {
		TRACE_LOG("tx_ready_list not empty!\n");
		xio_transport_flush_task_list(&ucx_hndl->tx_ready_list);
		/* for task that attached to senders with ref count = 2 */
		xio_transport_flush_task_list(&ucx_hndl->tx_ready_list);
	}

	if (!list_empty(&ucx_hndl->rx_list)) {
		TRACE_LOG("rx_list not empty!\n");
		xio_transport_flush_task_list(&ucx_hndl->rx_list);
	}

	ucx_hndl->tx_ready_tasks_num = 0;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_sock_close							     */
/*---------------------------------------------------------------------------*/
static void on_sock_close(struct xio_ucx_transport *ucx_hndl)
{
	TRACE_LOG("on_sock_close ucx_hndl:%p, state:%d\n\n",
		  ucx_hndl, ucx_hndl->state);

	xio_ucx_flush_all_tasks(ucx_hndl);

	xio_transport_notify_observer(&ucx_hndl->base,
					XIO_TRANSPORT_EVENT_CLOSED,
					NULL);
}

/*---------------------------------------------------------------------------*/
/* on_sock_disconnected							     */
/*---------------------------------------------------------------------------*/
void on_sock_disconnected(struct xio_ucx_transport *ucx_hndl,
			  int notify_observer)
{
	int retval;

	TRACE_LOG("on_sock_disconnected. ucx_hndl:%p, state:%d\n",
		  ucx_hndl, ucx_hndl->state);
	if (ucx_hndl->state == XIO_TRANSPORT_STATE_DISCONNECTED ||
	    ucx_hndl->state == XIO_TRANSPORT_STATE_LISTEN) {
		TRACE_LOG("call to close. ucx_hndl:%p\n",
			  ucx_hndl);
		ucx_hndl->state = XIO_TRANSPORT_STATE_DISCONNECTED;

		retval = xio_context_del_ev_handler(ucx_hndl->base.ctx,
						    ucx_hndl->sock_fd);
		if (retval)
			DEBUG_LOG("ucx_hndl:%p del_ev_handler failed, %m\n",
				  ucx_hndl);

		if (!notify_observer) { /*active close*/
			retval = shutdown(ucx_hndl->sock_fd, SHUT_RDWR);
			if (retval) {
				xio_set_error(errno);
				DEBUG_LOG("ucx shutdown failed.(errno=%d %m)\n",
					  errno);
			}
		}
		retval = close(ucx_hndl->sock_fd);
		if (retval)
			DEBUG_LOG("ucx_hndl:%p close failed, %m\n",
				  ucx_hndl);

		if (notify_observer)
			xio_transport_notify_observer
				(&ucx_hndl->base,
				 XIO_TRANSPORT_STATE_CONNECTED,
				 NULL);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_post_close							     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_post_close(struct xio_ucx_transport *ucx_hndl)
{
	TRACE_LOG("ucx transport: [post close] handle:%p\n",
		  ucx_hndl);

	xio_observable_unreg_all_observers(&ucx_hndl->base.observable);

	ufree(ucx_hndl->base.portal_uri);

	ufree(ucx_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_close		                                             */
/*---------------------------------------------------------------------------*/
static void xio_ucx_close(struct xio_transport_base *transport)
{
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)transport;
	int was = __atomic_add_unless(&ucx_hndl->base.kref, -1, 0);

	/* was already 0 */
	if (!was)
		return;

	if (was == 1) {
		/* now it is zero */
		TRACE_LOG("xio_ucx_close: [close] handle:%p, fd:%d\n",
			  ucx_hndl, ucx_hndl->sock_fd);

		switch (ucx_hndl->state) {
		case XIO_TRANSPORT_STATE_LISTEN:
		case XIO_TRANSPORT_STATE_DISCONNECTED:
			on_sock_disconnected(ucx_hndl, 0);
			/*fallthrough*/
		case XIO_TRANSPORT_STATE_DISCONNECTED:
			ucx_hndl->state = XIO_TRANSPORT_STATE_CLOSED;
			on_sock_close(ucx_hndl);
			break;
		default:
			xio_transport_notify_observer(&ucx_hndl->base,
						      XIO_TRANSPORT_EVENT_CLOSED,
						      NULL);
			ucx_hndl->state = XIO_TRANSPORT_STATE_DESTROYED;
			break;
		}

		if (ucx_hndl->state  == XIO_TRANSPORT_STATE_DESTROYED)
			xio_ucx_post_close(ucx_hndl);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_reject		                                             */
/*---------------------------------------------------------------------------*/
static int xio_ucx_reject(struct xio_transport_base *transport)
{
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)transport;
	int				retval;

	retval = shutdown(ucx_hndl->sock_fd, SHUT_RDWR);
	if (retval) {
		xio_set_error(errno);
		DEBUG_LOG("ucx shutdown failed. (errno=%d %m)\n", errno);
	}

	retval = close(ucx_hndl->sock_fd);
	if (retval) {
		xio_set_error(errno);
		DEBUG_LOG("ucx close failed. (errno=%d %m)\n", errno);
		return -1;
	}
	TRACE_LOG("ucx transport: [reject] handle:%p\n", ucx_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_context_shutdown						     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_context_shutdown(struct xio_transport_base *trans_hndl,
				    struct xio_context *ctx)
{
	struct xio_ucx_transport *ucx_hndl =
			(struct xio_ucx_transport *)trans_hndl;

	TRACE_LOG("ucx transport context_shutdown handle:%p\n", ucx_hndl);

	on_sock_disconnected(ucx_hndl, 0);
	ucx_hndl->state = XIO_TRANSPORT_STATE_CLOSED;
	xio_ucx_flush_all_tasks(ucx_hndl);
	xio_ucx_post_close(ucx_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_conn_ev_handler						     */
/*---------------------------------------------------------------------------*/
void xio_ucx_conn_ready_ev_handler(int fd, int events, void *user_context)
{
	struct xio_ucx_transport	*ucx_hndl = user_context;
	int retval = 0, count = 0;

	if (events & XIO_POLLIN) {
		do {
			retval = xio_ucx_rx_handler(ucx_hndl);
			++count;
		} while (retval > 0 && count <  RX_POLL_NR_MAX);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_accept		                                             */
/*---------------------------------------------------------------------------*/
static int xio_ucx_accept(struct xio_transport_base *transport)
{
	struct xio_ucx_transport *ucx_hndl =
			(struct xio_ucx_transport *)transport;

	/* add to epoll */
	xio_context_add_ev_handler(
			ucx_hndl->base.ctx,
			ucx_hndl->sock_fd,
			XIO_POLLIN,
			xio_ucx_conn_ready_ev_handler,
			ucx_hndl);

	TRACE_LOG("ucx transport: [accept] handle:%p\n", ucx_hndl);

	xio_transport_notify_observer(
			&ucx_hndl->base,
			XIO_TRANSPORT_EVENT_ESTABLISHED,
			NULL);

	return 0;
}
struct xio_ucx_transport *xio_ucx_create(struct xio_ucx_transport *ucp_trans)
{
	/* UCP temporary vars */
	ucp_params_t ucp_params;
	ucp_config_t *config;
	ucs_status_t status;

	/* UCP initialization */
	status = ucp_config_read(NULL, NULL, &config);
	if (status != UCS_OK)
		goto err;

	ucp_params.features = UCP_FEATURE_TAG;
	ucp_params.request_size = 0;
	ucp_params.request_init = NULL;
	ucp_params.request_cleanup = NULL;
	status = ucp_init(&ucp_params, config, &ucp_trans->ucp_context);
	ucp_config_release(config);
	if (status != UCS_OK)
		goto err;

	status = ucp_worker_create(&ucp_trans->ucp_context,
				   UCS_THREAD_MODE_SINGLE,
				   &ucp_trans->ucp_worker);
	if (status != UCS_OK)
		goto err_cleanup;

	status = ucp_worker_get_address(&ucp_trans->ucp_worker,
					&local_addr.addr, &local_addr.addr_len);
	if (status != UCS_OK)
		goto err_worker;

	return 0;
	err_addr:
		ucp_worker_release_address(&ucp_trans->ucp_worker, local_addr);

	err_worker:
		ucp_worker_destroy(&ucp_trans->ucp_worker);

	err_cleanup:
		ucp_cleanup(&ucp_trans->ucp_context);

	err:
		return 1;
}
/*---------------------------------------------------------------------------*/
/* xio_ucx_transport_create		                                     */
/*---------------------------------------------------------------------------*/
struct xio_ucx_transport *xio_ucx_tcp_create(
		struct xio_transport	*transport,
		struct xio_context	*ctx,
		struct xio_observer	*observer,
		int			create_socket)
{
	struct xio_ucx_transport	*ucx_hndl;
	int				optval = 1;
	int				retval;


	/*allocate ucx handl */
	ucx_hndl = ucalloc(1, sizeof(struct xio_ucx_transport));
	if (!ucx_hndl) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc failed. %m\n");
		return NULL;
	}
	ucx_hndl = xio_ucx_create(ucx_hndl);
	if (!ucx_hndl) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucx setup failed. %m\n");
		ufree(ucx_hndl);
		return NULL;
	}
	XIO_OBSERVABLE_INIT(&ucx_hndl->base.observable, ucx_hndl);

	if (ucx_options.enable_mem_pool) {
		xio_transport_mempool_get(ctx, 0);
		if (ucx_hndl->ucx_mempool == NULL) {
			xio_set_error(ENOMEM);
			ERROR_LOG("allocating ucx mempool failed. %m\n");
			goto cleanup;
		}
	}

	ucx_hndl->base.portal_uri	= NULL;
	ucx_hndl->base.proto		= XIO_PROTO_UCX;
	atomic_set(&ucx_hndl->base.kref, 1);
	ucx_hndl->transport		= transport;
	ucx_hndl->base.ctx		= ctx;

	/* create ucx socket */
	if (create_socket) {
		ucx_hndl->sock_fd = socket(AF_INET,
					   SOCK_STREAM | SOCK_NONBLOCK,
					   0);
		if (ucx_hndl->sock_fd < 0) {
			xio_set_error(errno);
			ERROR_LOG("create socket failed. (errno=%d %m)\n",
				  errno);
			goto cleanup;
		}

		retval = setsockopt(ucx_hndl->sock_fd,
				    SOL_SOCKET,
				    SO_REUSEADDR,
				    &optval,
				    sizeof(optval));
		if (retval) {
			xio_set_error(errno);
			ERROR_LOG("setsockopt failed. (errno=%d %m)\n",
				  errno);
			goto cleanup;
		}

		if (ucx_options.ucx_no_delay) {
			retval = setsockopt(ucx_hndl->sock_fd,
					    IPPROTO_TCP,
					    TCP_NODELAY,
					    (char *)&optval,
					    sizeof(int));
			if (retval) {
				xio_set_error(errno);
				ERROR_LOG("setsockopt failed. (errno=%d %m)\n",
					  errno);
				goto cleanup;
			}
		}


		optval = ucx_options.ucx_so_sndbuf;
		retval = setsockopt(ucx_hndl->sock_fd, SOL_SOCKET, SO_SNDBUF,
				    (char *)&optval, sizeof(optval));
		if (retval) {
			xio_set_error(errno);
			ERROR_LOG("setsockopt failed. (errno=%d %m)\n", errno);
			goto cleanup;
		}
		optval = ucx_options.ucx_so_rcvbuf;
		retval = setsockopt(ucx_hndl->sock_fd, SOL_SOCKET, SO_RCVBUF,
				    (char *)&optval, sizeof(optval));
		if (retval) {
			xio_set_error(errno);
			ERROR_LOG("setsockopt failed. (errno=%d %m)\n",
				  errno);
			goto cleanup;
		}
	}

	/* from now on don't allow changes */
	ucx_options.ucx_buf_attr_rdonly = 1;
	ucx_hndl->max_send_buf_sz	= ucx_options.ucx_buf_threshold;
	ucx_hndl->membuf_sz		= ucx_hndl->max_send_buf_sz;

	if (observer)
		xio_observable_reg_observer(&ucx_hndl->base.observable,
					    observer);

	INIT_LIST_HEAD(&ucx_hndl->in_flight_list);
	INIT_LIST_HEAD(&ucx_hndl->tx_ready_list);
	INIT_LIST_HEAD(&ucx_hndl->tx_comp_list);
	INIT_LIST_HEAD(&ucx_hndl->rx_list);
	INIT_LIST_HEAD(&ucx_hndl->io_list);

	TRACE_LOG("xio_ucx_open: [new] handle:%p\n", ucx_hndl);

	return ucx_hndl;

cleanup:
	ufree(ucx_hndl);

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_new_connection						     */
/*---------------------------------------------------------------------------*/
void xio_ucx_new_connection(struct xio_ucx_transport *parent_hndl)
{
	struct xio_ucx_transport *child_hndl;
	union xio_transport_event_data ev_data;
	int retval;
	socklen_t		 len = sizeof(struct sockaddr_storage);

	/* no observer , don't create socket yet */
	child_hndl = xio_ucx_tcp_create(parent_hndl->transport,
					      parent_hndl->base.ctx,
					      NULL,
					      0);
	if (!child_hndl) {
		ERROR_LOG("failed to create ucx child\n");
		xio_transport_notify_observer_error(&parent_hndl->base,
						    xio_errno());
		return;
	}

	/* "accept" the connection */
	retval = accept4(parent_hndl->sock_fd,
			 (struct sockaddr *)&child_hndl->base.peer_addr,
			 &len,
			 SOCK_NONBLOCK);
	if (retval < 0) {
		xio_set_error(errno);
		ERROR_LOG("ucx accept failed. (errno=%d %m)\n", errno);
		child_hndl->sock_fd = retval;
		return;
	}
	child_hndl->sock_fd = retval;

	child_hndl->base.proto = XIO_PROTO_UCX;

	len = sizeof(child_hndl->base.local_addr);
	retval = getsockname(child_hndl->sock_fd,
			     (struct sockaddr *)&child_hndl->base.local_addr,
			     &len);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("ucx getsockname failed. (errno=%d %m)\n", errno);
	}

	ev_data.new_connection.child_trans_hndl =
		(struct xio_transport_base *)child_hndl;
	xio_transport_notify_observer((struct xio_transport_base *)parent_hndl,
				      XIO_TRANSPORT_EVENT_NEW_CONNECTION,
				      &ev_data);
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_listener_ev_handler						     */
/*---------------------------------------------------------------------------*/
void xio_ucx_listener_ev_handler(int fd, int events, void *user_context)
{
	struct xio_ucx_transport *ucx_hndl = user_context;

	if (events | XIO_POLLIN)
		xio_ucx_new_connection(ucx_hndl);
	/* ORK TODO */
	/*else if (events | XIO_HUP) {
		 notify_observable(..., DISCONNECTED/CLOSED)
	}*/
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_listen							     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_listen(struct xio_transport_base *transport,
			  const char *portal_uri, uint16_t *src_port,
			  int backlog)
{
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)transport;
	union xio_sockaddr	sa;
	int			sa_len;
	int			retval = 0;
	uint16_t		sport;

	/* resolve the portal_uri */
	sa_len = xio_uri_to_ss(portal_uri, &sa.sa_stor);
	if (sa_len == -1) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("address [%s] resolving failed\n", portal_uri);
		return -1;
	}
	ucx_hndl->base.is_client = 0;

	/* bind */
	retval = bind(ucx_hndl->sock_fd,
		      (struct sockaddr *)&sa.sa_stor,
		      sa_len);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("ucx bind failed. (errno=%d %m)\n", errno);
		goto exit;
	}

	/* add to epoll */
	retval = xio_context_add_ev_handler(
			ucx_hndl->base.ctx,
			ucx_hndl->sock_fd,
			XIO_POLLIN, /* ORK ToDo: XIO_ERR, XIO_HUP */
			xio_ucx_listener_ev_handler,
			ucx_hndl);

	retval  = listen(ucx_hndl->sock_fd, backlog);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("ucx listen failed. (errno=%d %m)\n", errno);
		goto exit;
	}

	retval  = getsockname(ucx_hndl->sock_fd,
			      (struct sockaddr *)&sa.sa_stor,
			      (socklen_t *)&sa_len);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("getsockname failed. (errno=%d %m)\n", errno);
		goto exit;
	}

	switch (sa.sa_stor.ss_family) {
	case AF_INET:
		sport = ntohs(sa.sa_in.sin_port);
		break;
	case AF_INET6:
		sport = ntohs(sa.sa_in6.sin6_port);
		break;
	default:
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("invalid family type %d.\n", sa.sa_stor.ss_family);
		goto exit;
	}

	if (src_port)
		*src_port = sport;

	ucx_hndl->state = XIO_TRANSPORT_STATE_LISTEN;
	DEBUG_LOG("listen on [%s] src_port:%d\n", portal_uri, sport);

	return 0;

exit:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_conn_established_ev_handler	                                     */
/*---------------------------------------------------------------------------*/
void xio_ucx_conn_established_ev_handler(int fd, int events, void *user_context)
{
	struct xio_ucx_transport	*ucx_hndl = user_context;
	int				retval = 0;
	int				so_error = 0;
	socklen_t			len = sizeof(so_error);

	/* remove from epoll */
	retval = xio_context_del_ev_handler(
			ucx_hndl->base.ctx,
			ucx_hndl->sock_fd);
	if (retval) {
		ERROR_LOG("removing connection handler failed.(errno=%d %m)\n",
			  errno);
		so_error = errno;
	}

	/* add to epoll */
	retval = xio_context_add_ev_handler(
			ucx_hndl->base.ctx,
			ucx_hndl->sock_fd,
			XIO_POLLIN,
			xio_ucx_conn_ready_ev_handler,
			ucx_hndl);
	if (retval) {
		ERROR_LOG("setting connection handler failed. (errno=%d %m)\n",
			  errno);
		so_error = errno;
	}

	retval = getsockopt(ucx_hndl->sock_fd,
			    SOL_SOCKET,
			    SO_ERROR,
			    &so_error,
			    &len);
	if (retval) {
		ERROR_LOG("getsockopt failed. (errno=%d %m)\n", errno);
		so_error = errno;
	}

	len = sizeof(ucx_hndl->base.peer_addr);
	retval = getpeername(ucx_hndl->sock_fd,
			     (struct sockaddr *)&ucx_hndl->base.peer_addr,
			     &len);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("ucx getpeername failed. (errno=%d %m)\n", errno);
		so_error = errno;
	}

	if (so_error) {
		xio_transport_notify_observer_error(&ucx_hndl->base,
						    so_error ? so_error :
						    XIO_E_CONNECT_ERROR);
	} else {
		xio_transport_notify_observer(&ucx_hndl->base,
					      XIO_TRANSPORT_EVENT_ESTABLISHED,
					      NULL);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_connect		                                             */
/*---------------------------------------------------------------------------*/
static int xio_ucx_connect(struct xio_transport_base *transport,
			   const char *portal_uri, const char *out_if_addr)
{
	struct xio_ucx_transport	*ucx_hndl =
					(struct xio_ucx_transport *)transport;
	socklen_t			ss_len = 0;
	int				retval = 0;

	/* resolve the portal_uri */
	ss_len = xio_uri_to_ss(portal_uri, &ucx_hndl->sa.sa_stor);
	if (ss_len == -1) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("address [%s] resolving failed\n", portal_uri);
		return -1;
	}
	/* allocate memory for portal_uri */
	ucx_hndl->base.portal_uri = strdup(portal_uri);
	if (ucx_hndl->base.portal_uri == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("strdup failed. %m\n");
		return -1;
	}
	ucx_hndl->base.is_client = 1;

	if (out_if_addr) {
		union xio_sockaddr	if_sa;
		int			sa_len;

		sa_len = xio_host_port_to_ss(out_if_addr, &if_sa.sa_stor);
		if (sa_len == -1) {
			xio_set_error(XIO_E_ADDR_ERROR);
			ERROR_LOG("outgoing interface [%s] resolving failed\n",
				  out_if_addr);
			goto exit;
		}
		retval = bind(ucx_hndl->sock_fd,
			      (struct sockaddr *)&if_sa.sa_stor,
			      sa_len);
		if (retval) {
			xio_set_error(errno);
			ERROR_LOG("ucx bind failed. (errno=%d %m)\n",
				  errno);
			goto exit;
		}
	}

	/* add to epoll */
	retval = xio_context_add_ev_handler(
			ucx_hndl->base.ctx,
			ucx_hndl->sock_fd,
			XIO_POLLOUT,
			xio_ucx_conn_established_ev_handler,
			ucx_hndl);
	if (retval) {
		ERROR_LOG("setting connection handler failed. (errno=%d %m)\n",
			  errno);
		goto exit;
	}

	/* connect ucx_hndl->sock_fd */
	retval = connect(ucx_hndl->sock_fd,
			 (struct sockaddr *)&ucx_hndl->sa.sa_stor,
			 ss_len);
	if (retval) {
		if (errno == EINPROGRESS) {
			/*set iomux for write event*/
		} else {
			xio_set_error(errno);
			ERROR_LOG("ucx connect failed. (errno=%d %m)\n", errno);
			goto exit;
		}
	} else {
		/*handle in ev_handler*/
	}

	ss_len = sizeof(ucx_hndl->base.local_addr);
	retval = getsockname(ucx_hndl->sock_fd,
			     (struct sockaddr *)&ucx_hndl->base.local_addr,
			     &ss_len);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("ucx getsockname failed. (errno=%d %m)\n", errno);
		return retval;
	}

	return 0;

exit:
	ufree(ucx_hndl->base.portal_uri);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_open								     */
/*---------------------------------------------------------------------------*/
static struct xio_transport_base *xio_ucx_open(
		struct xio_transport	*transport,
		struct xio_context	*ctx,
		struct xio_observer	*observer)
{
	struct xio_ucx_transport	*ucx_hndl;

	ucx_hndl = xio_ucx_tcp_create(transport, ctx, observer, 1);
	if (!ucx_hndl) {
		ERROR_LOG("failed. to create ucx transport%m\n");
		return NULL;
	}
	return (struct xio_transport_base *)ucx_hndl;
}

/*
 * To dynamically control C-states, open the file /dev/cpu_dma_latency and
 * write the maximum allowable latency to it. This will prevent C-states with
 * transition latencies higher than the specified value from being used, as
 * long as the file /dev/cpu_dma_latency is kept open.
 * Writing a maximum allowable latency of 0 will keep the processors in C0
 * (like using kernel parameter \u2015idle=poll), and writing 1 should force
 * the processors to C1 when idle. Higher values could also be written to
 * restrict the use of C-states with latency greater than the value written.
 *
 * http://en.community.dell.com/techcenter/extras/m/white_papers/20227764/download.aspx
 */

/*---------------------------------------------------------------------------*/
/* xio_set_cpu_latency							     */
/*---------------------------------------------------------------------------*/
static int xio_set_cpu_latency(int *fd)
{
	int32_t latency = 0;

	if (!ucx_options.enable_dma_latency)
		return 0;

	DEBUG_LOG("setting latency to %d us\n", latency);
	*fd = open("/dev/cpu_dma_latency", O_WRONLY);
	if (*fd < 0) {
		ERROR_LOG(
		 "open /dev/cpu_dma_latency %m - need root permissions\n");
		return -1;
	}
	if (write(*fd, &latency, sizeof(latency)) != sizeof(latency)) {
		ERROR_LOG(
		 "write to /dev/cpu_dma_latency %m - need root permissions\n");
		close(*fd);
		*fd = -1;
		return -1;
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_init							     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_init(void)
{
	/* set cpu latency until process is down */
	xio_set_cpu_latency(&cdl_fd);

	xio_transport_mempool_array_init(&mempool_array, &mempool_array_len);
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_transport_init						     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_transport_init(struct xio_transport *transport)
{
	pthread_once(&ctor_key_once, xio_ucx_init);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_release							     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_release(void)
{
	if (cdl_fd >= 0)
		close(cdl_fd);

	xio_transport_mempool_array_release(mempool_array, mempool_array_len);
	/*ORK todo close everything? see xio_cq_release*/
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_transport_constructor					     */
/*---------------------------------------------------------------------------*/
void xio_ucx_transport_constructor(void)
{
	spin_lock_init(&mngmt_lock);
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_transport_destructor					     */
/*---------------------------------------------------------------------------*/
void xio_ucx_transport_destructor(void)
{
	ctor_key_once = PTHREAD_ONCE_INIT;
	dtor_key_once = PTHREAD_ONCE_INIT;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_release		                                     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_transport_release(struct xio_transport *transport)
{
	if (ctor_key_once == PTHREAD_ONCE_INIT)
		return;

	pthread_once(&dtor_key_once, xio_ucx_release);
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_rxd_init							     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_rxd_init(struct xio_ucx_work_req *rxd,
			     void *buf, unsigned size)
{
	rxd->msg_iov[0].iov_base = buf;
	rxd->msg_iov[0].iov_len	= sizeof(struct xio_tlv);
	rxd->msg_iov[1].iov_base = rxd->msg_iov[0].iov_base +
				   rxd->msg_iov[0].iov_len;
	rxd->msg_iov[1].iov_len	= size - sizeof(struct xio_tlv);
	rxd->msg_len = 2;

	rxd->tot_iov_byte_len = 0;

	rxd->stage = XIO_UCX_RX_START;
	rxd->msg.msg_control = NULL;
	rxd->msg.msg_controllen = 0;
	rxd->msg.msg_flags = 0;
	rxd->msg.msg_name = NULL;
	rxd->msg.msg_namelen = 0;
	rxd->msg.msg_iov = NULL;
	rxd->msg.msg_iovlen = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_txd_init							     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_txd_init(struct xio_ucx_work_req *txd,
			     void *buf, unsigned size)
{
	txd->msg_iov[0].iov_base = buf;
	txd->msg_iov[0].iov_len	= size;
	txd->msg_len = 1;
	txd->tot_iov_byte_len = 0;

	txd->stage = XIO_UCX_TX_BEFORE;
	txd->msg.msg_control = NULL;
	txd->msg.msg_controllen = 0;
	txd->msg.msg_flags = 0;
	txd->msg.msg_name = NULL;
	txd->msg.msg_namelen = 0;
	txd->msg.msg_iov = NULL;
	txd->msg.msg_iovlen = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_task_init							     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_task_init(struct xio_task *task,
			      struct xio_ucx_transport *ucx_hndl,
			      void *buf,
			      unsigned long size)
{
	XIO_TO_UCX_TASK(task, ucx_task);

	ucx_task->ucx_hndl = ucx_hndl;

	xio_ucx_rxd_init(&ucx_task->rxd, buf, size);
	xio_ucx_txd_init(&ucx_task->txd, buf, size);

	/* initialize the mbuf */
	xio_mbuf_init(&task->mbuf, buf, size, 0);
}

/* task pools management */

/*---------------------------------------------------------------------------*/
/* xio_ucx_calc_pool_size						     */
/*---------------------------------------------------------------------------*/
void xio_ucx_calc_pool_size(struct xio_ucx_transport *ucx_hndl)
{
	ucx_hndl->num_tasks = NUM_TASKS;

	ucx_hndl->alloc_sz  = ucx_hndl->num_tasks*ucx_hndl->membuf_sz;

	TRACE_LOG("pool size:  alloc_sz:%zd, num_tasks:%d, buf_sz:%zd\n",
		  ucx_hndl->alloc_sz,
		  ucx_hndl->num_tasks,
		  ucx_hndl->membuf_sz);
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_initial_pool_slab_pre_create				     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_initial_pool_slab_pre_create(
		struct xio_transport_base *transport_hndl,
		int alloc_nr,
		void *pool_dd_data, void *slab_dd_data)
{
	struct xio_ucx_tasks_slab *ucx_slab =
		(struct xio_ucx_tasks_slab *)slab_dd_data;
	uint32_t pool_size;

	ucx_slab->buf_size = CONN_SETUP_BUF_SIZE;
	pool_size = ucx_slab->buf_size * alloc_nr;

	ucx_slab->data_pool = ucalloc(pool_size * alloc_nr, sizeof(uint8_t));
	if (ucx_slab->data_pool == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc conn_setup_data_pool sz: %u failed\n",
			  pool_size);
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_initial_task_alloc						     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_ucx_initial_task_alloc(
					struct xio_ucx_transport *ucx_hndl)
{
	if (ucx_hndl->initial_pool_cls.task_get) {
		return ucx_hndl->initial_pool_cls.task_get(
					ucx_hndl->initial_pool_cls.pool);
	}
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_primary_task_alloc						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_ucx_primary_task_alloc(
					struct xio_ucx_transport *ucx_hndl)
{
	if (ucx_hndl->primary_pool_cls.task_get)
		return ucx_hndl->primary_pool_cls.task_get(
					ucx_hndl->primary_pool_cls.pool);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_task_lookup						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_ucx_primary_task_lookup(
					struct xio_ucx_transport *ucx_hndl,
					int tid)
{
	if (ucx_hndl->primary_pool_cls.task_lookup)
		return ucx_hndl->primary_pool_cls.task_lookup(
					ucx_hndl->primary_pool_cls.pool, tid);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_task_free							     */
/*---------------------------------------------------------------------------*/
inline void xio_ucx_task_free(struct xio_ucx_transport *ucx_hndl,
			       struct xio_task *task)
{
	if (ucx_hndl->primary_pool_cls.task_put)
		return ucx_hndl->primary_pool_cls.task_put(task);
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_initial_pool_post_create					     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_initial_pool_post_create(
		struct xio_transport_base *transport_hndl,
		void *pool, void *pool_dd_data)
{
	struct xio_task *task;
	struct xio_ucx_task *ucx_task;
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)transport_hndl;

	ucx_hndl->initial_pool_cls.pool = pool;

	task = xio_ucx_initial_task_alloc(ucx_hndl);
	if (task == NULL) {
		ERROR_LOG("failed to get task\n");
	} else {
		list_add_tail(&task->tasks_list_entry, &ucx_hndl->rx_list);
		ucx_task = (struct xio_ucx_task *)task->dd_data;
		ucx_task->ucx_op = XIO_UCX_RECV;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_initial_pool_slab_destroy					     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_initial_pool_slab_destroy(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, void *slab_dd_data)
{
	struct xio_ucx_tasks_slab *ucx_slab =
		(struct xio_ucx_tasks_slab *)slab_dd_data;

	ufree(ucx_slab->data_pool);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_initial_pool_slab_init_task					     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_initial_pool_slab_init_task(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, void *slab_dd_data,
		int tid, struct xio_task *task)
{
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)transport_hndl;
	struct xio_ucx_tasks_slab *ucx_slab =
		(struct xio_ucx_tasks_slab *)slab_dd_data;
	void *buf = ucx_slab->data_pool + tid*ucx_slab->buf_size;
	char *ptr;

	XIO_TO_UCX_TASK(task, ucx_task);

	/* fill xio_ucx_task */
	ptr = (char *)ucx_task;
	ptr += sizeof(struct xio_ucx_task);

	/* fill xio_ucx_work_req */
	ucx_task->txd.msg_iov = (void *)ptr;
	ptr += sizeof(struct iovec);

	ucx_task->rxd.msg_iov = (void *)ptr;
	ptr += 2 * sizeof(struct iovec);
	/*****************************************/

	xio_ucx_task_init(
			task,
			ucx_hndl,
			buf,
			ucx_slab->buf_size);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_initial_pool_get_params					     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_initial_pool_get_params(
		struct xio_transport_base *transport_hndl,
		int *start_nr, int *max_nr, int *alloc_nr,
		int *pool_dd_sz, int *slab_dd_sz, int *task_dd_sz)
{
	*start_nr = NUM_CONN_SETUP_TASKS;
	*alloc_nr = 0;
	*max_nr = NUM_CONN_SETUP_TASKS;
	*pool_dd_sz = 0;
	*slab_dd_sz = sizeof(struct xio_ucx_tasks_slab);
	*task_dd_sz = sizeof(struct xio_ucx_task) +
			      3*sizeof(struct iovec);
}

static struct xio_tasks_pool_ops initial_tasks_pool_ops = {
	.pool_get_params	= xio_ucx_initial_pool_get_params,
	.slab_pre_create	= xio_ucx_initial_pool_slab_pre_create,
	.slab_destroy		= xio_ucx_initial_pool_slab_destroy,
	.slab_init_task		= xio_ucx_initial_pool_slab_init_task,
	.pool_post_create	= xio_ucx_initial_pool_post_create
};


/*---------------------------------------------------------------------------*/
/* xio_ucx_primary_pool_slab_pre_create				     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_primary_pool_slab_pre_create(
		struct xio_transport_base *transport_hndl,
		int alloc_nr, void *pool_dd_data, void *slab_dd_data)
{
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)transport_hndl;
	struct xio_ucx_tasks_slab *ucx_slab =
		(struct xio_ucx_tasks_slab *)slab_dd_data;

	ucx_slab->buf_size = ucx_hndl->membuf_sz;

	if (disable_huge_pages) {
		ucx_slab->io_buf = xio_alloc(ucx_hndl->alloc_sz);
		if (!ucx_slab->io_buf) {
			xio_set_error(ENOMEM);
			ERROR_LOG("xio_alloc ucx pool sz:%zu failed\n",
				  ucx_hndl->alloc_sz);
			return -1;
		}
		ucx_slab->data_pool = ucx_slab->io_buf->addr;
	} else {
		/* maybe allocation of with unuma_alloc can provide better
		 * performance?
		 */
		ucx_slab->data_pool = umalloc_huge_pages(ucx_hndl->alloc_sz);
		if (!ucx_slab->data_pool) {
			xio_set_error(ENOMEM);
			ERROR_LOG("malloc ucx pool sz:%zu failed\n",
				  ucx_hndl->alloc_sz);
			return -1;
		}
	}

	DEBUG_LOG("pool buf:%p\n", ucx_slab->data_pool);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_primary_pool_post_create					     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_primary_pool_post_create(
		struct xio_transport_base *transport_hndl,
		void *pool, void *pool_dd_data)
{
	struct xio_task		*task = NULL;
	struct xio_ucx_task	*ucx_task = NULL;
	int			i;
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)transport_hndl;

	ucx_hndl->primary_pool_cls.pool = pool;

	for (i = 0; i < RX_LIST_POST_NR; i++) {
		/* get ready to receive message */
		task = xio_ucx_primary_task_alloc(ucx_hndl);
		if (task == 0) {
			ERROR_LOG("primary task pool is empty\n");
			return -1;
		}
		ucx_task = task->dd_data;
		ucx_task->ucx_op = XIO_UCX_RECV;
		list_add_tail(&task->tasks_list_entry, &ucx_hndl->rx_list);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_primary_pool_slab_destroy					     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_primary_pool_slab_destroy(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, void *slab_dd_data)
{
	struct xio_ucx_tasks_slab *ucx_slab =
		(struct xio_ucx_tasks_slab *)slab_dd_data;

	if (ucx_slab->io_buf)
		xio_free(&ucx_slab->io_buf);
	else
		ufree_huge_pages(ucx_slab->data_pool);


	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_primary_pool_slab_init_task					     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_primary_pool_slab_init_task(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data,
		void *slab_dd_data, int tid, struct xio_task *task)
{
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)transport_hndl;
	struct xio_ucx_tasks_slab *ucx_slab =
		(struct xio_ucx_tasks_slab *)slab_dd_data;
	void *buf = ucx_slab->data_pool + tid*ucx_slab->buf_size;
	int  max_iovsz = max(ucx_options.max_out_iovsz,
				     ucx_options.max_in_iovsz) + 1;
	char *ptr;

	XIO_TO_UCX_TASK(task, ucx_task);

	/* fill xio_tco_task */
	ptr = (char *)ucx_task;
	ptr += sizeof(struct xio_ucx_task);

	/* fill xio_ucx_work_req */
	ucx_task->txd.msg_iov = (void *)ptr;
	ptr += (max_iovsz + 1)*sizeof(struct iovec);
	ucx_task->rxd.msg_iov = (void *)ptr;
	ptr += (max_iovsz + 1)*sizeof(struct iovec);

	ucx_task->read_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_mempool_obj);
	ucx_task->write_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_mempool_obj);

	ucx_task->req_read_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_sge);
	ucx_task->req_write_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_sge);
	ucx_task->req_recv_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_sge);
	ucx_task->rsp_write_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_sge);
	/*****************************************/

	ucx_task->ucx_op = 0x200;
	xio_ucx_task_init(
			task,
			ucx_hndl,
			buf,
			ucx_slab->buf_size);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_task_pre_put						     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_task_pre_put(
		struct xio_transport_base *trans_hndl,
		struct xio_task *task)
{
	int	i;
	XIO_TO_UCX_TASK(task, ucx_task);

	/* recycle UCX  buffers back to pool */

	/* put buffers back to pool */

	for (i = 0; i < ucx_task->read_num_sge; i++) {
		if (ucx_task->read_sge[i].cache) {
			xio_mempool_free(&ucx_task->read_sge[i]);
			ucx_task->read_sge[i].cache = NULL;
		}
	}
	ucx_task->read_num_sge = 0;

	for (i = 0; i < ucx_task->write_num_sge; i++) {
		if (ucx_task->write_sge[i].cache) {
			xio_mempool_free(&ucx_task->write_sge[i]);
			ucx_task->write_sge[i].cache = NULL;
		}
	}
	ucx_task->write_num_sge		= 0;
	ucx_task->req_write_num_sge	= 0;
	ucx_task->rsp_write_num_sge	= 0;
	ucx_task->req_read_num_sge	= 0;
	ucx_task->req_recv_num_sge	= 0;
	ucx_task->sn			= 0;

	ucx_task->ucx_op		= XIO_UCX_NULL;

	xio_ucx_rxd_init(&ucx_task->rxd,
			 task->mbuf.buf.head,
			 task->mbuf.buf.buflen);
	xio_ucx_txd_init(&ucx_task->txd,
			 task->mbuf.buf.head,
			 task->mbuf.buf.buflen);

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_ucx_primary_pool_get_params					     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_primary_pool_get_params(
		struct xio_transport_base *transport_hndl,
		int *start_nr, int *max_nr, int *alloc_nr,
		int *pool_dd_sz, int *slab_dd_sz, int *task_dd_sz)
{
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)transport_hndl;
	int  max_iovsz = max(ucx_options.max_out_iovsz,
				    ucx_options.max_in_iovsz) + 1;

	*start_nr = NUM_START_PRIMARY_POOL_TASKS;
	*alloc_nr = NUM_ALLOC_PRIMARY_POOL_TASKS;
	*max_nr = ucx_hndl->num_tasks;
	*pool_dd_sz = 0;
	*slab_dd_sz = sizeof(struct xio_ucx_tasks_slab);
	*task_dd_sz = sizeof(struct xio_ucx_task) +
			(2 * (max_iovsz + 1))*sizeof(struct iovec) +
			 2 * max_iovsz * sizeof(struct xio_mempool_obj) +
			 4 * max_iovsz * sizeof(struct xio_sge);
}

static struct xio_tasks_pool_ops   primary_tasks_pool_ops = {
	.pool_get_params	= xio_ucx_primary_pool_get_params,
	.slab_pre_create	= xio_ucx_primary_pool_slab_pre_create,
	.slab_destroy		= xio_ucx_primary_pool_slab_destroy,
	.slab_init_task		= xio_ucx_primary_pool_slab_init_task,
	.pool_post_create	= xio_ucx_primary_pool_post_create,
	.task_pre_put		= xio_ucx_task_pre_put,
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_get_pools_ops						     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_get_pools_ops(struct xio_transport_base *trans_hndl,
				  struct xio_tasks_pool_ops **initial_pool_ops,
				  struct xio_tasks_pool_ops **primary_pool_ops)
{
	*initial_pool_ops = &initial_tasks_pool_ops;
	*primary_pool_ops = &primary_tasks_pool_ops;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_set_pools_cls						     */
/*---------------------------------------------------------------------------*/
static void xio_ucx_set_pools_cls(struct xio_transport_base *trans_hndl,
				  struct xio_tasks_pool_cls *initial_pool_cls,
				  struct xio_tasks_pool_cls *primary_pool_cls)
{
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)trans_hndl;

	if (initial_pool_cls)
		ucx_hndl->initial_pool_cls = *initial_pool_cls;
	if (primary_pool_cls)
		ucx_hndl->primary_pool_cls = *primary_pool_cls;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_set_opt                                                          */
/*---------------------------------------------------------------------------*/
static int xio_ucx_set_opt(void *xio_obj,
			   int optname, const void *optval, int optlen)
{
	switch (optname) {
	case XIO_OPTNAME_ENABLE_MEM_POOL:
		VALIDATE_SZ(sizeof(int));
		ucx_options.enable_mem_pool = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_ENABLE_DMA_LATENCY:
		VALIDATE_SZ(sizeof(int));
		ucx_options.enable_dma_latency = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_TRANS_BUF_THRESHOLD:
		VALIDATE_SZ(sizeof(int));

		/* changing the parameter is not allowed */
		if (ucx_options.ucx_buf_attr_rdonly) {
			xio_set_error(EPERM);
			return -1;
		}
		if (*(int *)optval < 0 ||
		    *(int *)optval > XIO_OPTVAL_MAX_UCX_BUF_THRESHOLD) {
			xio_set_error(EINVAL);
			return -1;
		}
		ucx_options.ucx_buf_threshold = *((int *)optval) +
					XIO_OPTVAL_MIN_UCX_BUF_THRESHOLD;
		ucx_options.ucx_buf_threshold =
			ALIGN(ucx_options.ucx_buf_threshold, 64);
		return 0;
		break;
	case XIO_OPTNAME_MAX_IN_IOVLEN:
		VALIDATE_SZ(sizeof(int));
		ucx_options.max_in_iovsz = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_MAX_OUT_IOVLEN:
		VALIDATE_SZ(sizeof(int));
		ucx_options.max_out_iovsz = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_UCX_ENABLE_MR_CHECK:
		VALIDATE_SZ(sizeof(int));
		ucx_options.enable_mr_check = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_UCX_NO_DELAY:
		VALIDATE_SZ(sizeof(int));
		ucx_options.ucx_no_delay = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_UCX_SO_SNDBUF:
		VALIDATE_SZ(sizeof(int));
		ucx_options.ucx_so_sndbuf = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_UCX_SO_RCVBUF:
		VALIDATE_SZ(sizeof(int));
		ucx_options.ucx_so_rcvbuf = *((int *)optval);
		return 0;
		break;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_get_opt                                                          */
/*---------------------------------------------------------------------------*/
static int xio_ucx_get_opt(void  *xio_obj,
			   int optname, void *optval, int *optlen)
{
	switch (optname) {

	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_is_valid_in_req							     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_is_valid_in_req(struct xio_msg *msg)
{
	int		i;
	int		mr_found = 0;
	struct xio_vmsg *vmsg = &msg->in;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sge;
	unsigned long		nents, max_nents;

	sgtbl		= xio_sg_table_get(&msg->in);
	sgtbl_ops	= xio_sg_table_ops_get(msg->in.sgl_type);
	nents		= tbl_nents(sgtbl_ops, sgtbl);
	max_nents	= tbl_max_nents(sgtbl_ops, sgtbl);

	if ((nents > ucx_options.max_in_iovsz) ||
	    (nents > max_nents) ||
	    (max_nents > ucx_options.max_in_iovsz)) {
		return 0;
	}

	if (vmsg->sgl_type == XIO_SGL_TYPE_IOV && nents > XIO_IOVLEN)
		return 0;

	if ((vmsg->header.iov_base != NULL)  &&
	    (vmsg->header.iov_len == 0))
		return 0;

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		if (sge_mr(sgtbl_ops, sge))
			mr_found++;
		if (sge_addr(sgtbl_ops, sge) == NULL) {
			if (sge_mr(sgtbl_ops, sge))
				return 0;
		} else {
			if (sge_length(sgtbl_ops, sge)  == 0)
				return 0;
		}
	}
	if (ucx_options.enable_mr_check &&
	    (mr_found != nents) && mr_found)
		return 0;

	return 1;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_is_valid_out_msg						     */
/*---------------------------------------------------------------------------*/
static int xio_ucx_is_valid_out_msg(struct xio_msg *msg)
{
	int			i;
	int			mr_found = 0;
	struct xio_vmsg		*vmsg = &msg->out;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sge;
	unsigned long		nents, max_nents;

	sgtbl		= xio_sg_table_get(&msg->out);
	sgtbl_ops	= xio_sg_table_ops_get(msg->out.sgl_type);
	nents		= tbl_nents(sgtbl_ops, sgtbl);
	max_nents	= tbl_max_nents(sgtbl_ops, sgtbl);

	if ((nents > ucx_options.max_out_iovsz) ||
	    (nents > max_nents) ||
	    (max_nents > ucx_options.max_out_iovsz))
		return 0;

	if (vmsg->sgl_type == XIO_SGL_TYPE_IOV && nents > XIO_IOVLEN)
		return 0;

	if (((vmsg->header.iov_base != NULL)  &&
	     (vmsg->header.iov_len == 0)) ||
	    ((vmsg->header.iov_base == NULL)  &&
	     (vmsg->header.iov_len != 0)))
			return 0;

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		if (sge_mr(sgtbl_ops, sge))
			mr_found++;
		if ((sge_addr(sgtbl_ops, sge) == NULL) ||
		    (sge_length(sgtbl_ops, sge)  == 0))
			return 0;
	}

	if (ucx_options.enable_mr_check &&
	    (mr_found != nents) && mr_found)
		return 0;

	return 1;
}

/*---------------------------------------------------------------------------*/
/* xio_ucx_dup2			                                             */
/* makes new_trans_hndl be the copy of old_trans_hndl, closes new_trans_hndl */
/* Note old and new are in dup2 terminology opposite to reconnect terms	     */
/* --------------------------------------------------------------------------*/
static int xio_ucx_dup2(struct xio_transport_base *old_trans_hndl,
			struct xio_transport_base **new_trans_hndl)
{
	xio_ucx_close(*new_trans_hndl);

	/* conn layer will call close which will only decrement */
	atomic_inc(&old_trans_hndl->kref);
	*new_trans_hndl = old_trans_hndl;

	return 0;
}

struct xio_transport xio_ucx_transport = {
	.name			= "ucx",
	.ctor			= xio_ucx_transport_constructor,
	.dtor			= xio_ucx_transport_destructor,
	.init			= xio_ucx_transport_init,
	.release		= xio_ucx_transport_release,
	.context_shutdown	= xio_ucx_context_shutdown,
	.open			= xio_ucx_open,
	.connect		= xio_ucx_connect,
	.listen			= xio_ucx_listen,
	.accept			= xio_ucx_accept,
	.reject			= xio_ucx_reject,
	.close			= xio_ucx_close,
	.dup2			= xio_ucx_dup2,
/*	.update_task		= xio_ucx_update_task,*/
	.send			= xio_ucx_send,
	.poll			= xio_ucx_poll,
	.set_opt		= xio_ucx_set_opt,
	.get_opt		= xio_ucx_get_opt,
	.cancel_req		= xio_ucx_cancel_req,
	.cancel_rsp		= xio_ucx_cancel_rsp,
	.get_pools_setup_ops	= xio_ucx_get_pools_ops,
	.set_pools_cls		= xio_ucx_set_pools_cls,

	.validators_cls.is_valid_in_req  = xio_ucx_is_valid_in_req,
	.validators_cls.is_valid_out_msg = xio_ucx_is_valid_out_msg,
};
