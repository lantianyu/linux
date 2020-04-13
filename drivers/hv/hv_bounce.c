/*
 * Copyright (c) 2021, Microsoft Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "hyperv_vmbus.h"

int hv_init_channel_ivm(struct vmbus_channel *channel)
{
	if (!hv_partition_is_isolated())
		return 0;

	INIT_LIST_HEAD(&channel->bounce_page_free_head);
	INIT_LIST_HEAD(&channel->bounce_pkt_free_list_head);

	/*
	 * This can be optimized to be only done when bounce pages are used for
	 * this channel.
	 */
	channel->bounce_pkt_cache = KMEM_CACHE(hv_bounce_pkt, 0);
	if (unlikely(!channel->bounce_pkt_cache))
		return -ENOMEM;
	channel->bounce_page_cache = KMEM_CACHE(hv_bounce_page_list, 0);
	if (unlikely(!channel->bounce_page_cache))
		return -ENOMEM;
	/* By default, no bounce resources are allocated */
	BUILD_BUG_ON(HV_DEFAULT_BOUNCE_BUFFER_PAGES);
	return 0;
}

void hv_free_channel_ivm(struct vmbus_channel *channel)
{
	if (!hv_partition_is_isolated())
		return;
	
	hv_bounce_pkt_list_free(channel, &channel->bounce_pkt_free_list_head);
	kmem_cache_destroy(channel->bounce_pkt_cache);
	cancel_delayed_work_sync(&channel->bounce_page_list_maintain);
	hv_bounce_page_list_free(channel, &channel->bounce_page_free_head);
	kmem_cache_destroy(channel->bounce_page_cache);
}
