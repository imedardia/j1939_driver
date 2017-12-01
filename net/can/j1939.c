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
#include <linux/can/raw.h>
#include <net/sock.h>
#include <net/net_namespace.h>

//For the moment let's use same value as CAN_MCNET
//This will avoid us to modify inside Linux kernel tree
//And recompile base modules (can, can_raw, slcan, can_bcm, vcan,  ...)
#define CAN_J1939 5

#define SOL_CAN_J1939 (SOL_CAN_BASE + CAN_J1939)
#define CAN_J1939_VERSION "20170212"

MODULE_DESCRIPTION("Simple SAE-J1939 protocol");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Imed BEN ROMDHANE <benromdhane.imed@gmail.com");

#define DBG(fmt, args...) (printk( KERN_DEBUG "can-isotp: %s: " fmt, \
				   __func__, ##args))
#undef DBG
#define DBG(fmt, args...)

#define SINGLE_MASK(id) ((id & CAN_EFF_FLAG) ? \
			 (CAN_EFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG) : \
			 (CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG))


struct j1939_sock {
	struct sock sk;
	int bound;
	int ifindex;
	struct notifier_block notifier;
};

static inline struct j1939_sock *j1939_sk(const struct sock *sk)
{
	return (struct j1939_sock *)sk;
}

static void j1939_skb_destructor(struct sk_buff *skb)
{
	sock_put(skb->sk);
}

static inline void j1939_skb_set_owner(struct sk_buff *skb, struct sock *sk)
{
	if (sk) {
		sock_hold(sk);
		skb->destructor = j1939_skb_destructor;
		skb->sk = sk;
	}
}

static int j1939_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct j1939_sock *ro = j1939_sk(sk);
	struct sk_buff *skb;
	struct net_device *dev;
	int ifindex;
	int err;

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_can *, addr, msg->msg_name);

		if (msg->msg_namelen < sizeof(*addr))
			return -EINVAL;

		if (addr->can_family != AF_CAN)
			return -EINVAL;

		ifindex = addr->can_ifindex;
	} else
		ifindex = ro->ifindex;

	if (unlikely(size != CAN_MTU))
		return -EINVAL;

	dev = dev_get_by_index(&init_net, ifindex);
	if (!dev)
		return -ENXIO;

	skb = sock_alloc_send_skb(sk, CAN_MTU,
				  msg->msg_flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto put_dev;

	err = memcpy_from_msg(skb_put(skb, size), msg, size);
	if (err < 0)
		goto free_skb;

//	sock_tx_timestamp(sk, &skb_shinfo(skb)->tx_flags);

	skb->dev = dev;
	skb->sk  = sk;
	skb->priority = sk->sk_priority;

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
	printk("New J1939 Message received");

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
		msg->msg_namelen = sizeof(struct sockaddr_can);
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	skb_free_datagram(sk, skb);

	return size;
}


static int j1939_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct j1939_sock *so;
	struct net *net;

	if (!sk)
		return 0;

	so = j1939_sk(sk);
	net = sock_net(sk);


	unregister_netdevice_notifier(&so->notifier);

	lock_sock(sk);

	so->ifindex = 0;
	so->bound   = 0;

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}


static int j1939_notifier(struct notifier_block *nb,
			unsigned long msg, void *data)
{
	struct net_device *dev = (struct net_device *)data;
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

		ro->ifindex = 0;
		ro->bound   = 0;
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
	struct j1939_sock *so = j1939_sk(sk);

	so->ifindex = 0;
	so->bound   = 0;

	so->notifier.notifier_call = j1939_notifier;
	register_netdevice_notifier(&so->notifier);

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

		dev_put(dev);
	} else {
		ifindex = 0;
	}

	if (!err) {
		if (ro->bound) {
			/* unregister old filters */
			if (ro->ifindex) {
				struct net_device *dev;

				dev = dev_get_by_index(&init_net, ro->ifindex);
				if (dev) {
					dev_put(dev);
				}
			}
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



static const struct proto_ops j1939_ops = {
	.family        = PF_CAN,
	.release       = j1939_release,
	.bind          = j1939_bind,
	.connect       = sock_no_connect,
	.socketpair    = sock_no_socketpair,
	.accept        = sock_no_accept,
	.getname       = j1939_getname,
	.poll          = datagram_poll,
	.ioctl         = can_ioctl,	/* use can_ioctl() from af_can.c */
	.listen        = sock_no_listen,
	.shutdown      = sock_no_shutdown,
	.setsockopt    = sock_no_setsockopt,
	.getsockopt    = sock_no_getsockopt,
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
