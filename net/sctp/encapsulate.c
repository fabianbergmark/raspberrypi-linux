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
static void sctp_tunnel_sock_destroy(struct sock *sk);
static int sctp_tunnel_sock_create(struct sctp_tunnel *tunnel);
static inline int sctp_udp_nat(struct sk_buff *skb, struct udphdr *uh);
static inline struct sctp_tunnel *sctp_sock_to_tunnel(struct sock *sk);
static inline void sctp_skb_set_owner_w(struct sk_buff *skb, struct sock *sk);

static int sctp_tunnel_sock_create(struct sctp_tunnel *tunnel)
{
        int err;
        struct sock *sk;
        struct socket *sock = NULL;
        struct sctp_tunnel *prepped;

        switch (tunnel->encap) {
        case SCTP_ENCAPTYPE_UDP:
                err = sock_create(AF_INET, SOCK_DGRAM, 0, &sock);
                if (err < 0)
                        goto out;

                udp_sk(sock->sk)->encap_type = UDP_ENCAP_SCTPINUDP;
                udp_sk(sock->sk)->encap_rcv = sctp_udp_encap_recv;
                udp_encap_enable();

                pr_debug("sctp_tunnel_sock_create: UDP socket created\n");
                break;
        default:
                err = -EINVAL;
                goto out;
        }

        sk = sock->sk;

        /* Check if this socket has already been prepped */
        prepped = (struct sctp_tunnel *)sk->sk_user_data;
        if (prepped != NULL) {
                err = -EBUSY;
                pr_debug("sctp_tunnel_create: The socket already has a tunnel\n");
                goto out;
        }

        tunnel->sock = sock;
        sk->sk_user_data = tunnel;
        sk->sk_destruct = &sctp_tunnel_sock_destroy;
out:
        if ((err < 0) && sock) {
                kernel_sock_shutdown(sock, SHUT_RDWR);
                sock_release(sock);
                tunnel->sock = NULL;
        }
        return err;
}

static void sctp_tunnel_sock_destroy(struct sock *sk)
{
        struct sctp_tunnel *tunnel;

        tunnel = sk->sk_user_data;
        if (tunnel == NULL)
                goto end;

        pr_debug("sctp_tunnel_sock_destroy: Destroying tunnel sock.\n");

        switch (tunnel->encap) {
        case SCTP_ENCAPTYPE_UDP:
                (udp_sk(sk))->encap_type = 0;
                (udp_sk(sk))->encap_rcv = NULL;
                (udp_sk(sk))->encap_destroy = NULL;
                break;
        }

        sk->sk_destruct = NULL;
        sk->sk_destruct = tunnel->old_sk_destruct;
        sk->sk_user_data = NULL;
        tunnel->sock = NULL;

        if (sk->sk_destruct)
                (*sk->sk_destruct)(sk);
end:
        return;
}

struct sctp_tunnel* sctp_tunnel_create(struct sock *sk)
{
        int err;
        struct sctp_tunnel *tunnel;
        enum sctp_encap_type encap = SCTP_ENCAPTYPE_UDP;

        tunnel = kzalloc(sizeof(struct sctp_tunnel), GFP_KERNEL);
        if (tunnel == NULL) {
                goto err;
        }

        tunnel->encap = encap;
	tunnel->sk = sk;
        err = sctp_tunnel_sock_create(tunnel);

        if (err < 0)
        {
                pr_debug("sctp_tunnel_create: Unable to create socket.\n");
                goto err;
        }

        return tunnel;
err:
        return NULL;
}

int sctp_tunnel_destroy(struct sctp_tunnel *tunnel)
{
        struct sock *sk;
        pr_debug("sctp_tunnel_destroy: Destroying tunnel.\n");
	tunnel->sk = NULL;
	
	if (tunnel->sock) {
	  sk = tunnel->sock->sk;
	  kernel_sock_shutdown(tunnel->sock, SHUT_RDWR);
	  sock_release(tunnel->sock);
	}
        return 0;
}

int sctp_tunnel_bind(struct sctp_tunnel *tunnel,
                     const union sctp_addr *addr)
{
        int err;
        struct sockaddr_in udp_addr;
        struct socket *sock = tunnel->sock;

        switch(tunnel->encap) {
        case SCTP_ENCAPTYPE_UDP:
                memset(&udp_addr, 0, sizeof(udp_addr));
                udp_addr.sin_family = AF_INET;
                udp_addr.sin_addr = addr->v4.sin_addr;
                udp_addr.sin_port = addr->v4.sin_port;

                err = kernel_bind(sock, (struct sockaddr *) &udp_addr,
                                  sizeof(udp_addr));

                /*SCTP_DEBUG_PRINTK_IPADDR("sctp_tunnel_bind: association %p addr:  ",
                                         " port: %d\n",
                                         addr,
                                         addr,
                                         ntohs(addr->v4.sin_port));*/
                if (err < 0)
                {
                        pr_debug("sctp_tunnel_bind: Unable to bind socket.\n");
                        goto out;
                }

                break;
        default:
                pr_debug("sctp_tunnel_bind: Encapsulation type not implemented.\n");
                err = -EINVAL;
                goto out;

        }
out:
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

/*static inline u32 sctp_udp_tunnel_hash_key(const void *data, u32 len, u32 seed)
{
	const struct sctp_udp_tunnel_hash_cmp_arg *x = data;
	const union sctp_addr *paddr = x->paddr;
	const struct net *net = x->net;
	u16 lport;
	u32 addr;

	lport = x->ep ? htons(x->ep->base.bind_addr.port) :
			x->laddr->v4.sin_port;
	if (paddr->sa.sa_family == AF_INET6)
		addr = jhash(&paddr->v6.sin6_addr, 16, seed);
	else
		addr = paddr->v4.sin_addr.s_addr;

	return  jhash_3words(addr, ((__u32)paddr->v4.sin_port) << 16 |
			     (__force __u32)lport, net_hash_mix(net), seed);
}

static inline u32 sctp_udp_tunnel_hash_obj(const void *data, u32 len, u32 seed)
{
	const struct sctp_tunnel *t = data;
	const union sctp_addr *paddr = &t->ipaddr;
	const struct net *net = sock_net(t->asoc->base.sk);
	u16 lport = htons(t->asoc->base.bind_addr.port);
	u32 addr;

	if (paddr->sa.sa_family == AF_INET6)
		addr = jhash(&paddr->v6.sin6_addr, 16, seed);
	else
		addr = paddr->v4.sin_addr.s_addr;

	return  jhash_3words(addr, ((__u32)paddr->v4.sin_port) << 16 |
			     (__force __u32)lport, net_hash_mix(net), seed);
}


static inline int sctp_udp_tunnel_hash_cmp(struct rhashtable_compare_arg *arg,
				const void *ptr)
{
	const struct sctp_hash_cmp_arg *x = arg->key;
	const struct sctp_transport *t = ptr;
	struct sctp_association *asoc = t->asoc;
	const struct net *net = x->net;

	if (!sctp_cmp_addr_exact(&t->ipaddr, x->paddr))
		return 1;
	if (!net_eq(sock_net(asoc->base.sk), net))
		return 1;
	if (x->ep) {
		if (x->ep != asoc->ep)
			return 1;
	} else {
		if (x->laddr->v4.sin_port != htons(asoc->base.bind_addr.port))
			return 1;
		if (!sctp_bind_addr_match(&asoc->base.bind_addr,
					  x->laddr, sctp_sk(asoc->base.sk)))
			return 1;
	}

	return 0;
	}

static const struct rhashtable_params sctp_udp_tunnel_hash_params = {
        .head_offset            = offsetof(struct sctp_tunnel, node),
        .hashfn                 = sctp_udp_tunnel_hash_key,
        .obj_hashfn             = sctp_udp_tunnel_hash_obj,
        .obj_cmpfn              = sctp_udp_tunnel_hash_cmp,
        .automatic_shrinking    = true,
};

struct sctp_udp_tunnel_hash_cmp_arg {
        const union sctp_addr           *laddr;
        const union sctp_addr           *paddr;
        const struct net                *net;
};

int sctp_udp_tunnel_hashtable_init(void)
{
         return rhashtable_init(&sctp_udp_tunnel_hashtable, &sctp_udp_tunnel_hash_params);
}

void sctp_udp_tunnel_hashtable_destroy(void)
{
	rhashtable_destroy(&sctp_udp_tunnel_hashtable);
}

void sctp_hash_udp_tunnel(struct sctp_transport *t)
{
        struct sctp_udp_tunnel_hash_cmp_arg arg;

        arg.paddr = &t->ipaddr;
        arg.net   = sock_net(t->asoc->base.sk);

reinsert:
        if (rhashtable_lookup_insert_key(&sctp_udp_tunnel_hashtable, &arg,
                                         &t->tunnel->node, sctp_udp_tunnel_hash_params) == -EBUSY)
                goto reinsert;
}
*/
int sctp_udp_encap_recv(struct sock *udp_sk, struct sk_buff *skb)
{
        struct udphdr *uh;
	struct net *net;
        struct sctp_tunnel *tunnel;
	struct sctp_transport *transport;
	union sctp_addr src;
	union sctp_addr dst;
	uh = NULL;
	net = dev_net(skb->dev);
	
	/*	struct sctp_udp_hash_cmp_arg arg = {
	  .laddr = laddr,
	  .paddr = paddr,
	  .net   = net,
	};
	
        tunnel = rhashtable_lookup_fast(&sctp_udp_tunnel_hashtable, &arg,
	sctp_udp_tunnel_hash_params);*/
	 
	  
        if (!sctp_udp_decapsulate(skb, udp_sk, &uh))
        {
                pr_debug("sctp_udp_encap_recv: Can't decapsulate package, aborting.\n");
                goto drop_put;
        }

	src.v4.sin_port = uh->source;
	memcpy(&src.v4.sin_addr.s_addr, &ip_hdr(skb)->saddr, sizeof(struct in_addr));
	dst.v4.sin_port = uh->dest;
	memcpy(&dst.v4.sin_addr.s_addr, &ip_hdr(skb)->daddr, sizeof(struct in_addr));
	
	transport = sctp_addrs_lookup_transport(net, &src, &dst);
	
	if (transport == NULL) {
	        pr_debug("sctp_udp_encap_recv: using the endpoint tunnel.\n");
	        tunnel = sctp_sock_to_tunnel(udp_sk);
	} else {
                pr_debug("sctp_udp_encap_recv: using the transport tunnel.\n");
	        tunnel = transport->tunnel;
	}
	
        if (tunnel == NULL)
        {
                pr_debug("sctp_udp_encap_recv: Can't find tunnel, aborting.\n");
                goto drop;
        }

	if (tunnel->sk == NULL)
	{
	        pr_debug("sctp_udp_encap_recv: Dangling tunnel.\n");
		goto drop_put;
	}

	sock_put(udp_sk);
        return sctp_rcv_core(net, skb);
drop_put:
	sock_put(udp_sk);
drop:
        return -1;
}

void sctp_udp_encapsulate(struct sk_buff *skb, struct sctp_packet *packet)
{

        struct sctp_transport *tp = packet->transport;

        struct sctp_tunnel *tunnel = tp->tunnel;
        struct sock *sk = tunnel->sock->sk;
        int len;
        int offset;
        struct udphdr *uh;
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
        uh->check = csum_tcpudp_magic(tp->saddr.v4.sin_addr.s_addr
                                      , tp->ipaddr.v4.sin_addr.s_addr
                                      , len, IPPROTO_UDP, csum);

	pr_debug("sctp_udp_encapsulate: packet %p src addr: %pI4 port: %d\n",
		 packet,
		 &tp->saddr.v4.sin_addr.s_addr,
		 ntohs(uh->source));

	pr_debug("sctp_udp_encapsulate: packet %p dst addr: %pI4 port: %d\n",
		 packet,
		 &tp->ipaddr.v4.sin_addr.s_addr,
		 ntohs(uh->dest));

	sctp_skb_set_owner_w(skb, sk);
	
}

inline int sctp_udp_decapsulate(struct sk_buff *skb, struct sock *sk, struct udphdr **puh)
{
        struct udphdr *uh;

        uh = udp_hdr(skb);
        if (skb->len < sizeof(struct udphdr))
                return -1;

	pr_debug("sctp_udp_decapsulate: Recieved a package on port %pI4:%d from port %pI4:%d\n",
		 &ip_hdr(skb)->daddr,
		 ntohs(uh->dest),
		 &ip_hdr(skb)->saddr,
		 ntohs(uh->source));

        skb_pull(skb, sizeof(struct udphdr));
        skb_reset_transport_header(skb);

        if (!sctp_udp_nat(skb, uh))
                return -1;

	*puh = uh;
        return 1;
}

static inline int sctp_udp_nat(struct sk_buff *skb, struct udphdr *uh)
{
        struct sctphdr *sh;

        sh = sctp_hdr(skb);
        sh->source = uh->source;
        sh->dest = uh->dest;

        sh->checksum = sctp_compute_cksum(skb, 0);

        return 1;
}

static void sctp_sock_wfree(struct sk_buff *skb) {
        sock_put(skb->sk);
}

static inline void sctp_skb_set_owner_w(struct sk_buff *skb, struct sock *sk) {
        skb_orphan(skb);
        sock_hold(sk);
        skb->sk = sk;
        skb->destructor = sctp_sock_wfree;
}
