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
static int sctp_tunnel_sock_create(struct sctp_tunnel *tunnel);
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

                SCTP_DEBUG_PRINTK("sctp_tunnel_sock_create: UDP socket created\n");
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
                SCTP_DEBUG_PRINTK("sctp_tunnel_create: The socket already has a tunnel\n");
                goto out;
        }

        tunnel->sock = sock;
        sk->sk_user_data = tunnel;
out:
        if ((err < 0) && sock) {
                sock_release(sock);
                tunnel->sock = NULL;
        }
        return err;
}

int sctp_tunnel_create(struct sock *enc,
                       struct sctp_tunnel **tunnelp)
{
        int err;
        struct sctp_tunnel *tunnel;
        enum sctp_encap_type encap = SCTP_ENCAPTYPE_UDP;

        tunnel = kzalloc(sizeof(struct sctp_tunnel), GFP_KERNEL);
        if (tunnel == NULL) {
                err = -ENOMEM;
                SCTP_DEBUG_PRINTK("sctp_tunnel_create: Out of memory");
                goto err;
        }

        tunnel->encap = encap;
        tunnel->sctp_net = sock_net(enc);
        err = sctp_tunnel_sock_create(tunnel);

        if (err < 0)
        {
                SCTP_DEBUG_PRINTK("sctp_tunnel_bind: Unable to create socket.\n");
                goto err;
        }


        err = 0;
err:
        *tunnelp = tunnel;
        if (err < 0)
                *tunnelp = NULL;
        return err;
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

                SCTP_DEBUG_PRINTK_IPADDR("sctp_tunnel_bind: association %p addr:  ",
                                         " port: %d\n",
                                         addr,
                                         addr,
                                         ntohs(addr->v4.sin_port));
                if (err < 0)
                {
                        SCTP_DEBUG_PRINTK("sctp_tunnel_bind: Unable to bind socket.\n");
                        goto out;
                }

                break;
        default:
                SCTP_DEBUG_PRINTK("sctp_tunnel_bind: Encapsulation type not implemented.\n");
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

int sctp_udp_encap_recv(struct sock *udp_sk, struct sk_buff *skb)
{
        struct sctp_tunnel *tunnel;
        struct inet_sock *inet = inet_sk(udp_sk);

        tunnel = sctp_sock_to_tunnel(udp_sk);

        if (tunnel == NULL)
        {
                SCTP_DEBUG_PRINTK("sctp_encap_recv: Can't find tunnel, aborting.\n");
                goto drop;
        }

        if (!sctp_udp_decapsulate(skb, udp_sk))
        {
                SCTP_DEBUG_PRINTK("sctp_encap_recv: Can't decapsulate package, aborting.\n");
                goto drop;
        }

        SCTP_DEBUG_PRINTK("sctp_encap_recv: Recieved a package on port %d from port %d.\n",
                          ntohs(inet->inet_sport),
                          ntohs(inet->inet_dport));


        return sctp_rcv_core(tunnel->sctp_net, skb);

drop:
        return 0;
}

void sctp_udp_encapsulate(struct sk_buff *skb, struct sctp_packet *packet)
{

        struct sctp_transport *tp = packet->transport;
        struct sctp_tunnel *tunnel = tp->asoc->ep->base.tunnel;
        struct sock *sk = tunnel->sock->sk;
        union sctp_addr *sctp_src = &tp->saddr;
        union sctp_addr *sctp_dst = &tp->ipaddr;
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
        uh->check = csum_tcpudp_magic(sctp_src->v4.sin_addr.s_addr
                                      , sctp_dst->v4.sin_addr.s_addr
                                      , len, IPPROTO_UDP, csum);

        SCTP_DEBUG_PRINTK_IPADDR("sctp_udp_encapsulate: association %p src addr:  ",
                                 " port: %d\n",
                                 sctp_src,
                                 sctp_src,
                                 ntohs(uh->source));

        SCTP_DEBUG_PRINTK_IPADDR("sctp_udp_encapsulate: association %p dst addr:  ",
                                 " port: %d\n",
                                 sctp_dst,
                                 sctp_dst,
                                 ntohs(uh->dest));

        sctp_skb_set_owner_w(skb, sk);
}

inline int sctp_udp_decapsulate(struct sk_buff *skb, struct sock *sk)
{
        struct udphdr *uh;

        uh = udp_hdr(skb);
        if (skb->len < sizeof(struct udphdr))
                return -1;

        skb_pull(skb, sizeof(struct udphdr));
        skb_reset_transport_header(skb);

        return 1;
}

static void sctp_sock_wfree(struct sk_buff *skb) {
        sock_put(skb->sk);
}

static inline void sctp_skb_set_owner_w(struct sk_buff *skb, struct sock *sk) {
        sock_hold(sk);
        skb->sk = sk;
        skb->destructor = sctp_sock_wfree;
}
