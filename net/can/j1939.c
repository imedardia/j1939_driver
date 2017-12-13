/*
 * J1939 Simple Transport Protocol Driver
 * All PGN Filtering and SPN-Data processing
 * should be handled in User-space
 * For the moment DM1/DM2/DM13 Multipacket frames
 * processing is done also at user-space Level
 * 
 * This module is highly inspired for CAN-RAW
 * Linux Module source code
 */ 
#include <linux/module.h>
#include <linux/init.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/can.h>
#include <linux/can/core.h>
#include <linux/can/skb.h>
#include <linux/can/raw.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/version.h>

#define CAN_J1939_VERSION "20171203"
/*
 * Let's use for the moment the PROTO-5 (CAN_MCNET) as
 * it will avoid for us to recompile all Linux Kernel
 * built-in module like Core, BCM, GW, ISOTP ...
 */ 
#define CAN_J1939 5

#define SOL_CAN_J1939 (SOL_CAN_BASE + CAN_J1939)

/*
 * Define IOCTLs for J1939 Protocol Module
 */
 
 enum {
	CAN_J1939_FILTER = 1,	/* set 0 .. n can_filter(s)          */
	CAN_J1939_MAX_IOCTLS
};
 
 /*
  * 512 is the Max number of CAN Filters supported
  * within J1939 Proto
  */
 #define CAN_J1939_FILTER_MAX 512

MODULE_DESCRIPTION("PF_CAN J1939 protocol");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("imed benromdhane <benromdhane.imed@gmail.com>");
MODULE_ALIAS("can-proto-5");


struct j1939_sock {
	struct sock sk;
	int bound;
	int ifindex;
	struct notifier_block notifier;
	int count;                 /* number of active filters */
	struct can_filter dfilter; /* default/single filter */
	struct can_filter *filter; /* pointer to filter(s) */
};

static inline struct j1939_sock *j1939_sk(const struct sock *sk)
{
	return (struct j1939_sock *)sk;
}

static void j1939_rcv(struct sk_buff *oskb, void * data)
{
	struct sock *sk = (struct sock *)data;
	struct sockaddr_can *addr;
	struct sk_buff *skb; 

	skb = skb_clone(oskb, GFP_ATOMIC);
	if (!skb)
		return;

	skb->tstamp = oskb->tstamp;
	skb->dev = oskb->dev;
	BUILD_BUG_ON(sizeof(skb->cb) < sizeof(struct sockaddr_can));
	addr = (struct sockaddr_can *)skb->cb;
	memset(addr, 0, sizeof(*addr));
	addr->can_family  = AF_CAN;
	addr->can_ifindex = skb->dev->ifindex;

	if (sock_queue_rcv_skb(sk, skb) < 0)
		kfree_skb(skb);

}

//Enable CAN Filters passed and configured by userland
//using setsockopt

static int j1939_enable_filters(struct net_device *dev, struct sock *sk,
			      struct can_filter *filter, int count)
{
	int err = 0;
	int i;

	for (i = 0; i < count; i++) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,10,17)
		err = can_rx_register(dev, filter[i].can_id,
				      filter[i].can_mask,
				      j1939_rcv, sk, "j1939", sk);
#else
		err = can_rx_register(&init_net, dev, filter[i].can_id,
				      filter[i].can_mask,
				      j1939_rcv, sk, "j1939", sk);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,17) */
		if (err) {
			/* clean up successfully registered filters */
			while (--i >= 0)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,10,17)
				can_rx_unregister(dev, filter[i].can_id,
						  filter[i].can_mask,
						  j1939_rcv, sk);
#else
				can_rx_unregister(&init_net, dev, filter[i].can_id,
						  filter[i].can_mask,
						  j1939_rcv, sk);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,17) */
			break;
		}
	}

	return err;
}

static void j1939_disable_filters(struct net_device *dev, struct sock *sk,
			      struct can_filter *filter, int count)
{
	int i;

	for (i = 0; i < count; i++)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,10,17)
				can_rx_unregister(dev, filter[i].can_id,
						  filter[i].can_mask,
						  j1939_rcv, sk);
#else
				can_rx_unregister(&init_net, dev, filter[i].can_id,
						  filter[i].can_mask,
						  j1939_rcv, sk);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,17) */
}

static inline void j1939_disable_allfilters(struct net_device *dev,
					  struct sock *sk)
{
	struct j1939_sock *ro = j1939_sk(sk);

	j1939_disable_filters(dev, sk, ro->filter, ro->count);
}

static int j1939_enable_allfilters(struct net_device *dev, struct sock *sk)
{
	struct j1939_sock *ro = j1939_sk(sk);
	int err;

	err = j1939_enable_filters(dev, sk, ro->filter, ro->count);

	return err;
}

static int j1939_notifier(struct notifier_block *nb,
			unsigned long msg, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct j1939_sock *ro = container_of(nb, struct j1939_sock, notifier);
	struct sock *sk = &ro->sk;

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	if (dev->type != ARPHRD_CAN)
		return NOTIFY_DONE;

	if (ro->ifindex != dev->ifindex)
		return NOTIFY_DONE;

	switch (msg) {

	case NETDEV_UNREGISTER:
		lock_sock(sk);
		/* remove current filters & unregister */
		if (ro->bound)
			j1939_disable_allfilters(dev, sk);

		if (ro->count > 1)
			kfree(ro->filter);

		ro->ifindex = 0;
		ro->bound   = 0;
		ro->count   = 0;
		release_sock(sk);

		sk->sk_err = ENODEV;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;

	case NETDEV_DOWN:
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;
	}

	return NOTIFY_DONE;
}

static int j1939_init(struct sock *sk)
{
	struct j1939_sock *ro = j1939_sk(sk);

	ro->bound            = 0;
	ro->ifindex          = 0;

	/* set default filter to single entry dfilter */
	ro->dfilter.can_id   = 0x80000000; //Accepts only CAN Extended IDs
	ro->dfilter.can_mask = 0x80000000; //Accepts only CAN Extended IDs
	ro->filter           = &ro->dfilter;
	ro->count            = 1;

	/* set notifier */
	ro->notifier.notifier_call = j1939_notifier;

	register_netdevice_notifier(&ro->notifier);

	return 0;
}

static int j1939_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct j1939_sock *ro;

	if (!sk)
		return 0;

	ro = j1939_sk(sk);

	unregister_netdevice_notifier(&ro->notifier);

	lock_sock(sk);

	/* remove current filters & unregister */
	if (ro->bound) {
		if (ro->ifindex) {
			struct net_device *dev;

			dev = dev_get_by_index(&init_net, ro->ifindex);
			if (dev) {
				j1939_disable_allfilters(dev, sk);
				dev_put(dev);
			}
		} else
			j1939_disable_allfilters(NULL, sk);
	}

	if (ro->count >= 1)
		kfree(ro->filter);

	ro->ifindex = 0;
	ro->bound   = 0;
	ro->count   = 0;

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}

static int j1939_bind(struct socket *sock, struct sockaddr *uaddr, int len)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct j1939_sock *ro = j1939_sk(sk);
	int ifindex;
	int err = 0;
	int notify_enetdown = 0;

	if (len < sizeof(*addr))
		return -EINVAL;

	lock_sock(sk);

	if (ro->bound && addr->can_ifindex == ro->ifindex)
		goto out;

	if (addr->can_ifindex) {
		struct net_device *dev;

		dev = dev_get_by_index(&init_net, addr->can_ifindex);
		if (!dev) {
			err = -ENODEV;
			goto out;
		}
		if (dev->type != ARPHRD_CAN) {
			dev_put(dev);
			err = -ENODEV;
			goto out;
		}
		if (!(dev->flags & IFF_UP))
			notify_enetdown = 1;

		ifindex = dev->ifindex;

		/* filters set by default/setsockopt */
		err = j1939_enable_allfilters(dev, sk);
		dev_put(dev);
	} else {
		ifindex = 0;

		/* filters set by default/setsockopt */
		err = j1939_enable_allfilters(NULL, sk);
	}

	if (!err) {
		if (ro->bound) {
			/* unregister old filters */
			if (ro->ifindex) {
				struct net_device *dev;

				dev = dev_get_by_index(&init_net, ro->ifindex);
				if (dev) {
					j1939_disable_allfilters(dev, sk);
					dev_put(dev);
				}
			} else
				j1939_disable_allfilters(NULL, sk);
		}
		ro->ifindex = ifindex;
		ro->bound = 1;
	}

 out:
	release_sock(sk);

	if (notify_enetdown) {
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
	}

	return err;
}

static int j1939_getname(struct socket *sock, struct sockaddr *uaddr,
		       int *len, int peer)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct j1939_sock *ro = j1939_sk(sk);

	if (peer)
		return -EOPNOTSUPP;

	memset(addr, 0, sizeof(*addr));
	addr->can_family  = AF_CAN;
	addr->can_ifindex = ro->ifindex;

	*len = sizeof(*addr);

	return 0;
}

static int j1939_setsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct j1939_sock *ro = j1939_sk(sk);
	struct can_filter *filter = NULL;  /* dyn. alloc'ed filters */
	struct can_filter sfilter;         /* single filter */
	struct net_device *dev = NULL;
	int count = 0;
	int err = 0;
	
	if (level != SOL_CAN_J1939)
		return -EINVAL;

	switch (optname) {

	case CAN_J1939_FILTER:
		if (optlen % sizeof(struct can_filter) != 0)
			return -EINVAL;

		if (optlen > CAN_J1939_FILTER_MAX * sizeof(struct can_filter))
			return -EINVAL;

		count = optlen / sizeof(struct can_filter);

		if (count > 1) {
			/* filter does not fit into dfilter => alloc space */
			filter = memdup_user(optval, optlen);
			if (IS_ERR(filter))
				return PTR_ERR(filter);
		} else if (count == 1) {
			if (copy_from_user(&sfilter, optval, sizeof(sfilter)))
				return -EFAULT;
		}

		lock_sock(sk);

		if (ro->bound && ro->ifindex)
			dev = dev_get_by_index(&init_net, ro->ifindex);

		if (ro->bound) {
			/* (try to) register the new filters */
			if (count == 1)
				err = j1939_enable_filters(dev, sk, &sfilter, 1);
			else
				err = j1939_enable_filters(dev, sk, filter, count);
			if (err) {
				if (count > 1)
					kfree(filter);
				goto out_fil;
			}

			/* remove old filter registrations */
			j1939_disable_filters(dev, sk, ro->filter, ro->count);
		}

		/* remove old filter space */
		if (ro->count > 1)
			kfree(ro->filter);

		/* link new filters to the socket */
		if (count == 1) {
			/* copy filter data for single filter */
			ro->dfilter = sfilter;
			filter = &ro->dfilter;
		}
		ro->filter = filter;
		ro->count  = count;

 out_fil:
		if (dev)
			dev_put(dev);

		release_sock(sk);

		break;

	default:
		return -ENOPROTOOPT;
	}
	return err;
}

static int j1939_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct j1939_sock *ro = j1939_sk(sk);
	int len;
	void *val;
	int err = 0;

	if (level != SOL_CAN_J1939)
		return -EINVAL;

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	switch (optname) {

	case CAN_J1939_FILTER:
		lock_sock(sk);
		if (ro->count > 0) {
			int fsize = ro->count * sizeof(struct can_filter);
			if (len > fsize)
				len = fsize;
			if (copy_to_user(optval, ro->filter, len))
				err = -EFAULT;
		} else
			len = 0;
		release_sock(sk);

		if (!err)
			err = put_user(len, optlen);
		return err;

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, val, len))
		return -EFAULT;
	return 0;
}

static int j1939_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct j1939_sock *ro = j1939_sk(sk);
	struct sk_buff *skb;
	struct net_device *dev;
	int err;
	
	if (!ro->bound) //Socket not yet bound
		return -EADDRNOTAVAIL;

	if (size != CAN_MTU) //Wrong size passed
		return -EINVAL;

	dev = dev_get_by_index(sock_net(sk), ro->ifindex);
	if (!dev)
		return -ENXIO;

	skb = sock_alloc_send_skb(sk, size,
				  msg->msg_flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto put_dev;

	can_skb_prv(skb)->ifindex = dev->ifindex;
	can_skb_prv(skb)->skbcnt = 0;

	err = memcpy_from_msg(skb_put(skb, size), msg, size);
	if (err < 0)
		goto free_skb;

	sock_tx_timestamp(sk, sk->sk_tsflags, &skb_shinfo(skb)->tx_flags);

	skb->dev = dev;
	skb->sk  = sk;

	err = can_send(skb, 1);

	dev_put(dev);

	if (err)
		goto send_failed;

	return size;

free_skb:
	kfree_skb(skb);
put_dev:
	dev_put(dev);
send_failed:
	return err;
}

static int j1939_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
		                 int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int err = 0;
	int noblock;

	noblock =  flags & MSG_DONTWAIT;
	flags   &= ~MSG_DONTWAIT;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		return err;

	if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	else
		size = skb->len;

	err = memcpy_to_msg(msg, skb->data, size);
	if (err < 0) {
		skb_free_datagram(sk, skb);
		return err;
	}

	sock_recv_timestamp(msg, sk, skb);

	if (msg->msg_name) {
		__sockaddr_check_size(sizeof(struct sockaddr_can));
		msg->msg_namelen = sizeof(struct sockaddr_can);
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	skb_free_datagram(sk, skb);
	
	return size;
}

static const struct proto_ops j1939_ops = {
	.family        = PF_CAN,
	.release       = j1939_release,
	.bind          = j1939_bind,
	.connect       = sock_no_connect,
	.socketpair    = sock_no_socketpair,
	.accept        = sock_no_accept,
	.getname       = j1939_getname,
	.poll          = sock_no_poll,
	.ioctl         = can_ioctl,	/* use can_ioctl() from af_can.c */
	.listen        = sock_no_listen,
	.shutdown      = sock_no_shutdown,
	.setsockopt    = j1939_setsockopt,
	.getsockopt    = j1939_getsockopt,
	.sendmsg       = j1939_sendmsg,
	.recvmsg       = j1939_recvmsg,
	.mmap          = sock_no_mmap,
	.sendpage      = sock_no_sendpage,
};

static struct proto j1939_proto __read_mostly = {
	.name       = "CAN_J1939",
	.owner      = THIS_MODULE,
	.obj_size   = sizeof(struct j1939_sock),
	.init       = j1939_init,
};

static const struct can_proto j1939_can_proto = {
	.type       = SOCK_DGRAM,
	.protocol   = CAN_J1939,
	.ops        = &j1939_ops,
	.prot       = &j1939_proto,
};

static __init int j1939_module_init(void)
{
	int err;

	pr_info("can: j1939 protocol (rev " CAN_J1939_VERSION ")\n");

	err = can_proto_register(&j1939_can_proto);
	if (err < 0)
		printk(KERN_ERR "can: registration of J1939 protocol failed\n");

	return err;
}

static __exit void j1939_module_exit(void)
{
	can_proto_unregister(&j1939_can_proto);
}

module_init(j1939_module_init);
module_exit(j1939_module_exit);
