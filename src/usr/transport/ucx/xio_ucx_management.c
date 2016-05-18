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

struct xio_ucp_addrs		local_addr;

int xio_ucx_init(struct xio_transport *self)
{
	return 0;
}

void xio_ucx_request_init(struct void * ucx_handle)
{
	return;
}

void xio_ucx_request_cleanup(struct void * ucx_handle)
{
	return;
}

static int xio_init_ucp(struct xio_ucx_transport * ucx_handle)
{
	/* UCP temporary vars */
	ucp_params_t ucp_params;
	ucp_config_t *config;
	ucs_status_t status;

	/* UCP handler objects */
	ucp_context_h ucp_context;
	ucp_worker_h ucp_worker;
	ucs_status_t status;
	/* UCP initialization */
	status = ucp_config_read(NULL, NULL, &config);
	if (status != UCS_OK)
		return 1;
	ucp_params.features		= UCP_FEATURE_TAG;
	ucp_params.request_size = sizeof(struct xio_ucx_transport);
	ucp_params.request_init = xio_ucx_request_init;
	ucp_params.request_cleanup = xio_ucx_request_cleanup;

	status = ucp_init(&ucp_params, config, &ucp_context);

	ucp_config_print(config, stdout, NULL, UCS_CONFIG_PRINT_CONFIG);

	ucp_config_release(config);
	if (status != UCS_OK) {
		goto err;
	}

	status = ucp_worker_create(ucp_context, UCS_THREAD_MODE_SINGLE,
				   &ucp_worker);
	if (status != UCS_OK) {
		goto err_cleanup;
	}

	status = ucp_worker_get_address(ucp_worker, &local_addr.addr,
					&local_addr.addr_len);
	if (status != UCS_OK) {
		goto err_worker;
	}
	return 0;

	err_worker:
		ucp_worker_destroy(ucx_handle->ucp_context);
	err_cleanup:
		ucp_cleanup(ucx_handle->ucp_context);
	err:
		return 1;

}

static struct xio_transport_base *xio_ucx_open(
		struct xio_transport	*transport,
		struct xio_context	*ctx,
		struct xio_observer	*observer,
		uint32_t		trans_attr_mask,
		struct xio_transport_init_attr *attr)
{
	struct xio_ucx_transport	*ucx_hndl;
	int status = 0;
	/*allocate tcp handl */
	ucx_hndl = (struct xio_ucx_transport *)
			ucalloc(1, sizeof(struct xio_ucx_transport));
	if (!ucx_hndl) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc failed. %m\n");
		return NULL;
	}

	struct xio_ucx_transport	*ucx_hndl;

	ucx_hndl = xio_ucx_transport_create(transport, ctx, observer, 1);
	if (!ucx_hndl) {
		ERROR_LOG("failed. to create tcp transport%m\n");
		return NULL;
	}
	if (attr && trans_attr_mask) {
		memcpy(&ucx_hndl->trans_attr, attr, sizeof(*attr));
		ucx_hndl->trans_attr_mask = trans_attr_mask;
	}
	if (xio_init_ucp(ucx_hndl)) {
		ERROR_LOG("failed. to create ucp transport%m\n");
		return NULL;
	}
	return (struct xio_transport_base *)ucx_hndl;
}


void xio_ucx_flush_tx_handler(void *xio_ucx_hndl)
{
	struct xio_ucx_transport *ucx_hndl = (struct xio_ucx_transport *)
						xio_ucx_hndl;
	/*xio_tcp_xmit(tcp_hndl);*/
}

void xio_ucx_consume_ctl_rx(void *xio_ucx_hndl)
{
	struct xio_ucx_transport *ucx_hndl = (struct xio_ucx_transport *)
						xio_ucx_hndl;
	int retval = 0, count = 0;

	xio_context_disable_event(&ucx_hndl->ctl_rx_event);

/*	do {
		retval = ucx_hndl->sock.ops->rx_ctl_handler(tcp_hndl);
		++count;
	} while (retval > 0 && count <  RX_POLL_NR_MAX);

	if (retval > 0 &&  tcp_hndl->tmp_rx_buf_len &&
	    tcp_hndl->state == XIO_TRANSPORT_STATE_CONNECTED) {
		xio_context_add_event(tcp_hndl->base.ctx,
				      &tcp_hndl->ctl_rx_event);
	}*/
}
struct xio_ucx_transport *xio_ucx_transport_create(
		struct xio_transport	*transport,
		struct xio_context	*ctx,
		struct xio_observer	*observer,
		int			create_socket)
{
	struct xio_ucx_transport	*ucx_hndl;

	/*allocate tcp handl */
	struct xio_ucx_transport *ucx_hndl =
		(struct xio_ucx_transport *)transport;

	XIO_OBSERVABLE_INIT(&ucx_hndl->base.observable, ucx_hndl);

	ucx_hndl->base.portal_uri	= NULL;
	ucx_hndl->base.proto		= XIO_PROTO_UCX;
	kref_init(&ucx_hndl->base.kref);
	ucx_hndl->transport		= transport;
	ucx_hndl->base.ctx		= ctx;
	ucx_hndl->is_listen		= 0;

	ucx_hndl->tmp_rx_buf		= NULL;
	ucx_hndl->tmp_rx_buf_cur	= NULL;
	ucx_hndl->tmp_rx_buf_len	= 0;

	ucx_hndl->tx_ready_tasks_num = 0;
	ucx_hndl->tx_comp_cnt = 0;

	memset(&ucx_hndl->tmp_work, 0, sizeof(struct xio_tcp_work_req));
	ucx_hndl->tmp_work.msg_iov = ucx_hndl->tmp_iovec;

	/* from now on don't allow changes */
	ucx_hndl->max_inline_buf_sz	= xio_tcp_get_inline_buffer_size();
	ucx_hndl->membuf_sz		= ucx_hndl->max_inline_buf_sz;

	if (observer)
		xio_observable_reg_observer(&ucx_hndl->base.observable,
					    observer);

	INIT_LIST_HEAD(&ucx_hndl->in_flight_list);
	INIT_LIST_HEAD(&ucx_hndl->tx_ready_list);
	INIT_LIST_HEAD(&ucx_hndl->tx_comp_list);
	INIT_LIST_HEAD(&ucx_hndl->rx_list);
	INIT_LIST_HEAD(&ucx_hndl->io_list);

	INIT_LIST_HEAD(&ucx_hndl->pending_conns);

	memset(&ucx_hndl->flush_tx_event, 0, sizeof(struct xio_ev_data));
	ucx_hndl->flush_tx_event.handler	= xio_tcp_flush_tx_handler;
	ucx_hndl->flush_tx_event.data		= ucx_hndl;

	memset(&ucx_hndl->ctl_rx_event, 0, sizeof(struct xio_ev_data));
	ucx_hndl->ctl_rx_event.handler		= xio_tcp_consume_ctl_rx;
	ucx_hndl->ctl_rx_event.data		= ucx_hndl;

	memset(&ucx_hndl->disconnect_event, 0, sizeof(struct xio_ev_data));
	ucx_hndl->disconnect_event.handler	= xio_ucx_flush_tx_handler;
	ucx_hndl->disconnect_event.data		= ucx_hndl;

	TRACE_LOG("xio_tcp_open: [new] handle:%p\n", ucx_hndl);

	return ucx_hndl;

cleanup:
	ufree(ucx_hndl);

	return NULL;
}


void xio_ucx_conn_established_helper(int fd,
				     struct xio_ucx_transport *ucx_hndl,
				     struct xio_ucx_setup_msg	*msg,
				     int error)
{
	int				retval = 0;
	int				so_error = 0;
	socklen_t			len = sizeof(so_error);

	/* remove from epoll */
	retval = xio_context_del_ev_handler(ucx_hndl->base.ctx,
					ucx_hndl->fd_sock);
	if (retval) {
		ERROR_LOG("removing connection handler failed.(errno=%d %m)\n",
			  xio_get_last_socket_error());
		goto cleanup;
	}

	retval = getsockopt(ucx_hndl->fd_sock,
			    SOL_SOCKET,
			    SO_ERROR,
			    (char *)&so_error,
			    &len);
	if (retval) {
		ERROR_LOG("getsockopt failed. (errno=%d %m)\n",
			  xio_get_last_socket_error());
		so_error = xio_get_last_socket_error();
	}
	if (so_error || error) {
		DEBUG_LOG("fd=%d connection establishment failed\n",
				ucx_hndl->fd_sock);
		DEBUG_LOG("so_error=%d, epoll_error=%d\n", so_error, error);
		/*tcp_hndl->sock.ops->del_ev_handlers = NULL;*/
		goto cleanup;
	}

	/* add to epoll */
	retval = ucx_hndl->sock.ops->add_ev_handlers(tcp_hndl);
	if (retval) {
		ERROR_LOG("setting connection handler failed. (errno=%d %m)\n",
			  xio_get_last_socket_error());
		goto cleanup;
	}

	len = sizeof(tcp_hndl->base.peer_addr);
	retval = getpeername(tcp_hndl->sock.cfd,
			     (struct sockaddr *)&tcp_hndl->base.peer_addr,
			     &len);
	if (retval) {
		xio_set_error(xio_get_last_socket_error());
		ERROR_LOG("tcp getpeername failed. (errno=%d %m)\n",
			  xio_get_last_socket_error());
		so_error = xio_get_last_socket_error();
		goto cleanup;
	}
	tcp_hndl->state = XIO_TRANSPORT_STATE_CONNECTING;

	retval = xio_tcp_send_connect_msg(tcp_hndl->sock.cfd, msg);
	if (retval)
		goto cleanup;

	xio_transport_notify_observer(&tcp_hndl->base,
				      XIO_TRANSPORT_EVENT_ESTABLISHED,
				      NULL);

	return;

cleanup:
	if  (so_error == XIO_ECONNREFUSED)
		xio_transport_notify_observer(&tcp_hndl->base,
					      XIO_TRANSPORT_EVENT_REFUSED,
					      NULL);
	else
		xio_transport_notify_observer_error(&tcp_hndl->base,
						    so_error ? so_error :
						    XIO_E_CONNECT_ERROR);
}


void xio_ucx_conn_established_ev_handler(int fd, int events, void *user_context)
{
	struct xio_ucx_transport	*ucx_hndl = (struct xio_ucx_transport *)
							user_context;
	struct xio_ucx_setup_msg	msg;

	xio_ucx_conn_established_helper(
				fd, ucx_hndl, &msg,
				events &
				(XIO_POLLERR | XIO_POLLHUP | XIO_POLLRDHUP));
}

void xio_ucx_new_connection(struct xio_ucx_transport *parent_hndl)
{
	int retval;
	socklen_t len = sizeof(struct sockaddr_storage);
	struct xio_ucx_pending_conn *pending_conn;

	/*allocate pending fd struct */
	pending_conn = (struct xio_tcp_pending_conn *)
				ucalloc(1, sizeof(struct xio_tcp_pending_conn));
	if (!pending_conn) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc failed. %m\n");
		xio_transport_notify_observer_error(&parent_hndl->base,
						    xio_errno());
		return;
	}

	pending_conn->waiting_for_bytes = sizeof(struct xio_tcp_connect_msg);

	/* "accept" the connection */
	retval = xio_accept_non_blocking(
			parent_hndl->fd_sock,
			(struct sockaddr *)&pending_conn->sa.sa_stor,
			&len);
	if (retval < 0) {
		xio_set_error(xio_get_last_socket_error());
		ERROR_LOG("tcp accept failed. (errno=%d %m)\n",
			  xio_get_last_socket_error());
		ufree(pending_conn);
		return;
	}
	pending_conn->fd = retval;

	list_add_tail(&pending_conn->conns_list_entry,
		      &parent_hndl->pending_conns);

	/* add to epoll */
	retval = xio_context_add_ev_handler(
			parent_hndl->base.ctx,
			pending_conn->fd,
			XIO_POLLIN | XIO_POLLRDHUP,
			xio_tcp_pending_conn_ev_handler,
			parent_hndl);
	if (retval)
		ERROR_LOG("adding pending_conn_ev_handler failed\n");
}

void xio_ucx_disconnect_helper(void *xio_tcp_hndl) {
	struct xio_ucx_transport *ucx_hndl =
			(struct xio_ucx_transport *) xio_tcp_hndl;

	if (ucx_hndl->state >= XIO_TRANSPORT_STATE_DISCONNECTED)
		return;

	ucx_hndl->state = XIO_TRANSPORT_STATE_DISCONNECTED;

/*	 flush all tasks in completion
	if (!list_empty(&ucx_hndl->in_flight_list)) {
		struct xio_task *task = NULL;

		task = list_last_entry(&ucx_hndl->in_flight_list,
				struct xio_task, tasks_list_entry);
		if (task) {
			XIO_TO_TCP_TASK(task, tcp_task);

			xio_ctx_add_work(tcp_hndl->base.ctx, task,
					xio_tcp_tx_completion_handler,
					&tcp_task->comp_work);
		}
	} else {
		 call disconnect if no message to flush other wise defer
		xio_context_add_event(tcp_hndl->base.ctx,
				&tcp_hndl->disconnect_event);
	}*/
}

void xio_ucx_listener_ev_handler(int fd, int events, void *user_context)
{
	struct xio_ucx_transport *tcp_hndl = (struct xio_ucx_transport *)
						user_context;

	if (events & XIO_POLLIN)
		xio_ucx_new_connection(tcp_hndl);

	if ((events & (XIO_POLLHUP | XIO_POLLERR))) {
		DEBUG_LOG("epoll returned with error events=%d for fd=%d\n",
			  events, fd);
		xio_ucx_disconnect_helper(tcp_hndl);
	}
}

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
		goto exit1;
	}
	ucx_hndl->base.is_client = 0;

	/* bind */
	retval = bind(ucx_hndl->fd_sock, (struct sockaddr *)&sa.sa_stor, sa_len);
	if (retval) {
		xio_set_error(xio_get_last_socket_error());
		ERROR_LOG("tcp bind failed. (errno=%d %m)\n",
			  xio_get_last_socket_error());
		goto exit1;
	}

	ucx_hndl->is_listen = 1;

	retval  = listen(ucx_hndl->fd_sock, backlog > 0 ? backlog : MAX_BACKLOG);
	if (retval) {
		xio_set_error(xio_get_last_socket_error());
		ERROR_LOG("tcp listen failed. (errno=%d %m)\n",
			  xio_get_last_socket_error());
		goto exit1;
	}

	/* add to epoll */
	retval = xio_context_add_ev_handler(
			ucx_hndl->base.ctx,
			ucx_hndl->fd_sock,
			XIO_POLLIN,
			xio_ucx_listener_ev_handler,
			ucx_hndl);
	if (retval) {
		ERROR_LOG("xio_context_add_ev_handler failed.\n");
		goto exit1;
	}
	ucx_hndl->in_epoll[0] = 1;

	retval  = getsockname(ucx_hndl->fd_sock,
			      (struct sockaddr *)&sa.sa_stor,
			      (socklen_t *)&sa_len);
	if (retval) {
		xio_set_error(xio_get_last_socket_error());
		ERROR_LOG("getsockname failed. (errno=%d %m)\n",
			  xio_get_last_socket_error());
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

	exit1:
		/*ucx_hndl->sock.ops->del_ev_handlers = NULL;*/
	exit:
		return -1;
}

int xio_ucx_connect(struct xio_transport_base *transport,
		   const char *portal_uri, const char *out_if_addr)
{
	int retval;
	struct xio_ucx_transport	*ucx_hndl =
					(struct xio_ucx_transport *)transport;
	union xio_sockaddr		rsa;
	socklen_t			rsa_len = 0;
	int				retval = 0;

	/* resolve the portal_uri */
	rsa_len = xio_uri_to_ss(portal_uri, &rsa.sa_stor);
	if (rsa_len == (socklen_t)-1) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("address [%s] resolving failed\n", portal_uri);
		goto exit1;
	}
	/* allocate memory for portal_uri */
	ucx_hndl->base.portal_uri = strdup(portal_uri);
	if (!ucx_hndl->base.portal_uri) {
		xio_set_error(ENOMEM);
		ERROR_LOG("strdup failed. %m\n");
		goto exit1;
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
		retval = bind(ucx_hndl->fd_sock,
			      (struct sockaddr *)&if_sa.sa_stor,
			      sa_len);
		if (retval) {
			xio_set_error(xio_get_last_socket_error());
			ERROR_LOG("tcp bind failed. (errno=%d %m)\n",
				  xio_get_last_socket_error());
			goto exit;
		}
	}
	retval = xio_tcp_connect_helper(ucx_hndl->fd_sock,
					(struct sockaddr *)rsa.sa_stor, rsa_len,
					&ucx_hndl->port,
					&ucx_hndl->base.local_addr);
	if (retval)
		return retval;

	/* add to epoll */
	retval = xio_context_add_ev_handler(
			ucx_hndl->base.ctx,
			ucx_hndl->fd_sock,
			XIO_POLLOUT | XIO_POLLRDHUP,
			xio_ucx_conn_established_ev_handler,
			ucx_hndl);
	if (retval) {
		ERROR_LOG("setting connection handler failed. (errno=%d %m)\n",
			  xio_get_last_socket_error());
		return retval;
	}

	return 0;
	exit:
		ufree(ucx_hndl->base.portal_uri);
	exit1:
		/*ucx_hndl->sock.ops->del_ev_handlers = NULL;*/
		return -1;
}
struct xio_transport xio_ucx_transport = {
	.name			= "ucx",
	.ctor			= NULL,
	.dtor			= NULL,
	.init			= xio_ucx_init,
	.release		= NULL,
	.context_shutdown	= NULL,
	.open			= xio_ucx_open,
	.connect		= xio_ucx_connect,
	.listen			= xio_ucx_listen,
	.accept			= NULL,
	.reject			= NULL,
	.close			= NULL,
	.dup2			= NULL,
	.update_task		= NULL,
	.update_rkey		= NULL,
	.send			= NULL,xio_tcp_transport
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
