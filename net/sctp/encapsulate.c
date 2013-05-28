/* SCTP kernel implementation
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001-2003 International Business Machines, Corp.
 * Copyright (c) 2001 Intel Corp.
 * Copyright (c) 2001 Nokia, Inc.
 * Copyright (c) 2001 La Monte H.P. Yarroll
 *
 * This file is part of the SCTP kernel implementation
 *
 * These functions handle all input from the IP layer into SCTP.
 *
 * This SCTP implementation is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This SCTP implementation is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ************************
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <lksctp-developers@lists.sourceforge.net>
 *
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Written or modified by:
 *    La Monte H.P. Yarroll <piggy@acm.org>
 *    Karl Knutson <karl@athena.chicago.il.us>
 *    Xingang Guo <xingang.guo@intel.com>
 *    Jon Grimm <jgrimm@us.ibm.com>
 *    Hui Huang <hui.huang@nokia.com>
 *    Daisy Chang <daisyc@us.ibm.com>
 *    Sridhar Samudrala <sri@us.ibm.com>
 *    Ardelle Fan <ardelle.fan@intel.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#include <linux/udp.h>
#include <linux/types.h>
#include <linux/list.h> /* For struct list_head */
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/time.h> /* For struct timeval */
#include <linux/slab.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/snmp.h>
#include <net/sock.h>
#include <net/xfrm.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <net/sctp/checksum.h>
#include <net/net_namespace.h>

/* Forward declarations for internal helpers. */
static int sctp_tunnel_sock_create(struct sctp_association *asoc,
                                   const union sctp_addr *addr,
				   enum sctp_encap_type encap,
				   struct socket **sockp);
static inline struct sctp_tunnel *sctp_sock_to_tunnel(struct sock *sk);
static inline void sctp_skb_set_owner_w(struct sk_buff *skb, struct sock *sk);

static int sctp_tunnel_sock_create(struct sctp_association *asoc,
                                   const union sctp_addr *addr,
				   enum sctp_encap_type encap,
				   struct socket **sockp)
{
	int err;
	struct socket *sock;
	struct sockaddr_in udp_addr;
        struct inet_sock *sk = inet_sk(asoc->base.sk);

	switch(encap) {
	case SCTP_ENCAPTYPE_UDP:
		err = sock_create(AF_INET, SOCK_DGRAM, 0, &sock);
		if (err < 0)
			goto out;

		memset(&udp_addr, 0, sizeof(udp_addr));
		udp_addr.sin_family = AF_INET;
		udp_addr.sin_addr.s_addr = sk->inet_saddr;
		udp_addr.sin_port = sk->inet_sport;

                SCTP_DEBUG_PRINTK_IPADDR("sctp_tunnel_sock_create: association %p addr:  ",
                                         " port: %d\n",
                                         addr,
                                         addr,
                                         udp_addr.sin_port);

		err = kernel_bind(sock, (struct sockaddr *) &udp_addr,
		                  sizeof(udp_addr));
		if (err < 0)
			goto out;

		udp_addr.sin_family = AF_INET;
                udp_addr.sin_addr.s_addr = sk->inet_saddr;
		udp_addr.sin_port = sk->inet_sport;

		err = kernel_connect(sock, (struct sockaddr *) &udp_addr,
		                     sizeof(udp_addr), 0);
		if (err < 0)
			goto out;
		udp_sk(sock->sk)->encap_type = UDP_ENCAP_SCTPINUDP;
		udp_sk(sock->sk)->encap_rcv = sctp_udp_encap_recv;

		udp_encap_enable();
                break;
	default:
		goto out;
	}

out:
        *sockp = sock;
	if ((err < 0) && sock) {
		sock_release(sock);
                *sockp = NULL;
	}
	return err;
}

int sctp_tunnel_create(struct sctp_association *asoc,
                       const union sctp_addr *addr,
                       struct sctp_tunnel **tunnelp)
{
	int err;

	struct sock *sk;
	struct socket *sock;
	struct sctp_tunnel *tunnel = NULL;
        struct net *net = sock_net(asoc->base.sk);
	enum sctp_encap_type encap = SCTP_ENCAPTYPE_UDP;

	SCTP_DEBUG_PRINTK("SCTP: Variable initialization done.");

	err = sctp_tunnel_sock_create(asoc, addr, encap, &sock);
	if (err < 0)
		goto err;

	SCTP_DEBUG_PRINTK("SCTP: Tunnel sock created");

	sk = sock->sk;

	/* Check if this socket has already been prepped */
	tunnel = (struct sctp_tunnel *)sk->sk_user_data;
	if (tunnel != NULL) {
		err = -EBUSY;
		SCTP_DEBUG_PRINTK("SCTP: Already prepped.");
		goto err;
	}

	SCTP_DEBUG_PRINTK("SCTP: Not already prepped");

	tunnel = kzalloc(sizeof(struct sctp_tunnel), GFP_KERNEL);
	if (tunnel == NULL) {
		err = -ENOMEM;
		SCTP_DEBUG_PRINTK("SCTP: No memory");
		goto err;
	}

	SCTP_DEBUG_PRINTK("SCTP: Allocated memory");
	tunnel->sctp_net = net;
	tunnel->encap = encap;
	tunnel->sk = sk;

	sk->sk_user_data = tunnel;
	//sk->sk_destruct = &sctp_tunnel_destruct;
	err = 0;

err:
	return err;
}

static inline struct sctp_tunnel *sctp_sock_to_tunnel(struct sock *sk)
{
	struct sctp_tunnel *tunnel;

	if (sk == NULL)
		return NULL;

	sock_hold(sk);
	tunnel = (struct sctp_tunnel *)(sk->sk_user_data);
	if (tunnel == NULL) {
		sock_put(sk);
		goto out;
	}

out:
	return tunnel;
}

int sctp_udp_encap_recv(struct sock *udp_sk, struct sk_buff *skb)
{
	struct sock * sk;
	struct sctp_tunnel *tunnel;

	tunnel = sctp_sock_to_tunnel(udp_sk);

	if (tunnel == NULL)
		goto drop;

	sk = tunnel->sk;
	if (sk == NULL)
		goto drop;

	if(!sctp_udp_decapsulate(skb))
		goto drop;

	sctp_rcv_core(tunnel->sctp_net, skb);

drop:
	return 0;
}

inline int sctp_udp_decapsulate(struct sk_buff *skb)
{
	struct udphdr *uh;

	uh = udp_hdr(skb);
	if (skb->len < sizeof(struct udphdr))
		return -1;

	skb_pull(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);
	return 1;
}


void sctp_udp_encapsulate(struct sk_buff *skb, struct sctp_packet *packet)
{
        struct udphdr *uh;
	struct sock *sk = skb->sk;
        struct inet_sock *inet = inet_sk(sk);
	int len;
	int offset;
	unsigned int csum;

	/* Build the encapsulating UDP header.
	 */

	uh = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);
	offset = skb_transport_offset(skb);
	len = skb->len - offset;
	uh->source = htons(packet->source_port);
	uh->dest   = htons(packet->destination_port);
	uh->len    = htons(len);
	uh->check  = 0;

	/* Calculate checksum
	 */

	csum = skb_checksum(skb, 0, len, 0);
	uh->check = csum_tcpudp_magic(inet->inet_saddr
                                      , inet->inet_daddr
                                      , len, IPPROTO_UDP, csum);

	sctp_skb_set_owner_w(skb, sk);
}

static void sctp_sock_wfree(struct sk_buff *skb) {
	sock_put(skb->sk);
}

static inline void sctp_skb_set_owner_w(struct sk_buff *skb, struct sock *sk) {
	sock_hold(sk);
	skb->sk = sk;
	skb->destructor = sctp_sock_wfree;
}
