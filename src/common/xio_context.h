/*
 * Copyright (c) 2013 Mellanox Technologies��. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies�� BSD license
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
 *      - Neither the name of the Mellanox Technologies�� nor the names of its
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
#ifndef XIO_CONTEXT_H
#define XIO_CONTEXT_H

#include "xio_workqueue.h"

#define xio_ctx_work_t  xio_work_handle_t
#define xio_ctx_delayed_work_t  xio_delayed_work_handle_t

/*---------------------------------------------------------------------------*/
/* enum									     */
/*---------------------------------------------------------------------------*/
enum xio_context_event {
	XIO_CONTEXT_EVENT_CLOSE
};

enum xio_counters {
	XIO_STAT_TX_MSG,
	XIO_STAT_RX_MSG,
	XIO_STAT_TX_BYTES,
	XIO_STAT_RX_BYTES,
	XIO_STAT_DELAY,
	XIO_STAT_APPDELAY,
	/* user can register 10 more messages */
	XIO_STAT_USER_FIRST,
	XIO_STAT_LAST = 16
};

/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct xio_statistics {
	uint64_t	hertz;
	uint64_t	counter[XIO_STAT_LAST];
	char		*name[XIO_STAT_LAST];
};

struct xio_context {
	void				*ev_loop;
	int				cpuid;
	int				nodeid;
	int				polling_timeout;
	unsigned int			flags;
	uint64_t			worker;
	struct xio_statistics		stats;
	struct xio_context_params	params;
	struct xio_workqueue		*workqueue;
	struct list_head		ctx_list;  /* per context storage */

	/* list of sessions using this connection */
	struct xio_observable		observable;
	void				*netlink_sock;
};

/*---------------------------------------------------------------------------*/
/* xio_context_reg_observer						     */
/*---------------------------------------------------------------------------*/
int xio_context_reg_observer(struct xio_context *context,
			     struct xio_observer *observer);

/*---------------------------------------------------------------------------*/
/* xio_context_unreg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_context_unreg_observer(struct xio_context *conn,
				struct xio_observer *observer);


int xio_add_counter(struct xio_context *ctx, char *name);

int xio_del_counter(struct xio_context *ctx, int counter);

static inline void xio_ctx_stat_add(struct xio_context *ctx, int counter, uint64_t val)
{
	ctx->stats.counter[counter] += val;
}

static inline void xio_ctx_stat_inc(struct xio_context *ctx, int counter)
{
	ctx->stats.counter[counter]++;
}

static inline void xio_stat_add(struct xio_statistics *stats, int counter, uint64_t val)
{
	stats->counter[counter] += val;
}

static inline void xio_stat_inc(struct xio_statistics *stats, int counter)
{
	stats->counter[counter]++;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_add_delayed_work						     */
/*---------------------------------------------------------------------------*/
int xio_ctx_add_delayed_work(struct xio_context *ctx,
			     int msec_duration, void *data,
			     void (*timer_fn)(void *data),
			     xio_ctx_delayed_work_t *work);

/*---------------------------------------------------------------------------*/
/* xio_ctx_del_delayed_work					             */
/*---------------------------------------------------------------------------*/
int xio_ctx_del_delayed_work(struct xio_context *ctx,
			     xio_ctx_delayed_work_t *work);

/*---------------------------------------------------------------------------*/
/* xio_ctx_add_work							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_add_work(struct xio_context *ctx,
			     void *data,
			     void (*function)(void *data),
			     xio_ctx_work_t *work);

/*---------------------------------------------------------------------------*/
/* xio_ctx_del_delayed_work					             */
/*---------------------------------------------------------------------------*/
int xio_ctx_del_work(struct xio_context *ctx,
		     xio_ctx_work_t *work);


#endif /*XIO_CONTEXT_H */

