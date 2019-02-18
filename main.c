#include <stdio.h>
#include <stdint.h>
#include <assert_test.h>
#include <uk/netdev.h>
#include <uk/netdev_core.h>
#include <uk/alloc.h>
#include <uk/semaphore.h>
#include <uk/arch/types.h>

#define NET_DEVICE_COUNT   2
#define EXPECTED_PKT       (0x50)
#define NET_DATA_SIZE      (1530)
#define DESC_COUNT         (0x100)

static struct uk_alloc *a = NULL;
static struct uk_sched *s = NULL;
static struct uk_netdev *netdevice[NET_DEVICE_COUNT] = {0};
static __u16  desc_cnt[NET_DEVICE_COUNT] = {0};
static struct uk_netbuf *spare_buf[NET_DEVICE_COUNT];
static __atomic pkt_cnt[NET_DEVICE_COUNT];
static  struct uk_semaphore sem_flag;
static struct uk_netdev_info dev_info[NET_DEVICE_COUNT] = {0};

static uint16_t alloc_rxpkts(void *argp, struct uk_netbuf *nb[], uint16_t count);

static void netdev_test_callback(struct uk_netdev *dev,
					uint16_t queue_id, void *cookie);

#include "xbpf.h"

static void netdev_arp_response_frame(struct uk_netbuf *buf)
{
	uint16_t swap;
	int i = 0;
	/* swap source and destination MAC */
	for (i = 0; i < 3; i++) {
		swap = *(((uint16_t *)buf->data) + i);
	//	*(((uint16_t *)buf->data) + i) =
	//		*(((uint16_t *)buf->data) + 3 + i);
	//	*(((uint16_t *)buf->data) + 3 + i) = swap;
		uk_pr_err("%04x, %04x\n", swap,
			*(((uint16_t *)buf->data) + i + 3));
	}
}

static void netdev_form_reply(struct uk_netbuf *buf)
{
	__u16 ethertype = *(__u16 *)(buf->data + 12);
	uk_pr_err("Ethertype %04x\n", ethertype);
	netdev_arp_response_frame(buf);
}

static void netdev_test_data_tx(uint16_t queue_id,
				struct uk_netbuf *buf, int instance)
{
	struct uk_netbuf *sendbuf = NULL;
	int rc = 0;
	uk_pr_err("Allocating send buffer\n");
	sendbuf = uk_netbuf_alloc_buf(uk_alloc_get_default(),
			NET_DATA_SIZE, dev_info[instance].nb_encap_tx, 0, NULL);
	TEST_NOT_NULL(sendbuf);
	uk_pr_err("Copying data of length %d\n", buf->len);
	memcpy(sendbuf->data, buf->data, buf->len);
	sendbuf->len = buf->len;
	UK_ASSERT(!sendbuf->prev);
	netdev_form_reply(sendbuf);
	uk_pr_err("Sending(%d) data of length %d\n",
			instance, sendbuf->len);
	rc = uk_netdev_tx_one(netdevice[instance], queue_id, sendbuf);
	TEST_EXPR(rc == 2);
}

static void netdev_test_callback(struct uk_netdev *dev, uint16_t queue_id,
					void *cookie)
{
	struct uk_netbuf *buf = NULL, *fill_buf = NULL;
	struct uk_netbuf *sendbuf = NULL;
	__u16 count = 0;
	int rc = 0;
	static int rcv_stat = 0;
	int instance = (int) cookie;
	uk_pr_err("Recv Identifier %d\n", instance);

	do {
		/* buffer alloc via callback now
		if (spare_buf[instance]) {
			fill_buf = spare_buf[instance];
			spare_buf[instance] = NULL;
			count  = 1;
		}
		UK_ASSERT(fill_buf);
		*/
		//rc = uk_netdev_rx_one(dev, queue_id, &buf, &fill_buf, &count);
		rc = uk_netdev_rx_one(dev, queue_id, &buf);
		if (rc < 0) {
			uk_pr_err("Error receiving packet\n");
			TEST_ZERO_CHK(rc);
		}

		uk_pr_err("Receive return code %d\n", rc);

		if (uk_netdev_status_notready(rc)) {
			/* No (more) packets received */
			break;
		}


		if (rc < 0) {
			uk_pr_err("instance %d\n", instance);
			break;
		}
		/*
		if (rc > 0) {
			TEST_NOT_NULL(buf);
			TEST_ZERO_CHK(count);
		} else {
			TEST_EXPR(!buf);
			TEST_EXPR(count == 1);
			spare_buf[instance] = fill_buf;
			break;
		}
		*/
		// mangle pkt
		do_exec_ebpf(ebpf_vm, buf->data, buf->len);
		netdev_test_data_tx(queue_id, buf,  1 - instance);
		/*
		uk_netbuf_free(buf);
		buf = uk_netbuf_alloc_buf(uk_alloc_get_default(),
					NET_DATA_SIZE, dev_info[instance].nb_encap_rx, 0, NULL);
		TEST_NOT_NULL(buf);
		buf->len = NET_DATA_SIZE - dev_info[instance].nb_encap_rx;
		count = 1;
		spare_buf[instance] = buf;

		uk_pr_err("packet processed %d reset length:%d\n"
				,++rcv_stat, spare_buf[instance]->len);
		if (rc == 1) {
			uk_pr_err("Enabling interrupt returned %d\n",
					rc);
			rc = uk_netdev_rxq_intr_enable(dev, queue_id);
		}
		uk_pr_err("Interrupt enable: %d\n", rc);
		*/
	} while (uk_netdev_status_more(rc));
	//} while (rc > 0 && rcv_stat < EXPECTED_PKT);
	//} while (rc == 1 && rcv_stat < EXPECTED_PKT);

	uk_pr_err("out of loop %d\n", rcv_stat);
	ukarch_inc(&pkt_cnt[instance].counter);
	if (pkt_cnt[instance].counter == EXPECTED_PKT) {
		uk_pr_err("uping the sem\n");
		uk_semaphore_up(&sem_flag);
	}
}

void netdev_init(uint32_t *count)
{
	*count  = uk_netdev_count();
}

void netdev_test_init()
{
	int count = 0;
	netdev_init(&count);
	TEST_NOT_ZERO_CHK(count);
}

void netdev_test_fetch(int count)
{
	int i = 0;
	struct uk_netdev *dev;
	for (i = 0; i < count; i++) {
		uk_pr_err("Fetching index %d\n", i);
		dev = uk_netdev_get(i);
		TEST_NOT_NULL(dev);
		netdevice[i] = dev;
	}
}

void netdev_test_invalid_configure(int instance)
{
	struct uk_netdev_conf conf = {0};
	int rc = 0;
	conf.nb_rx_queues = 5;
	conf.nb_tx_queues = 5;
	rc = uk_netdev_configure(netdevice[instance], &conf);
	TEST_NOT_ZERO_CHK(rc);
}


void netdev_test_configure(int instance)
{
	struct uk_netdev_info *info = &dev_info[instance];
	int rc = 0;
	struct uk_netdev_conf conf;

	uk_netdev_info_get(netdevice[instance], info);
	TEST_NOT_ZERO_CHK(info->nb_encap_rx);
	TEST_NOT_ZERO_CHK(info->nb_encap_tx);
	uk_pr_err("RX Encap %d: TX Encap %d\n", info->nb_encap_rx, info->nb_encap_tx);

	conf.nb_rx_queues = info->max_rx_queues;
	conf.nb_tx_queues = info->max_tx_queues;
	
	rc = uk_netdev_configure(netdevice[instance], &conf);
	TEST_ZERO_CHK(rc);
}

static uint16_t alloc_rxpkts(void *argp, struct uk_netbuf *nb[], uint16_t count)
{
	struct uk_alloc *a;
	uint16_t i;
	int instance;

	//UK_ASSERT(argp);

	// the the instance
	instance =  (int) argp;

	for (i = 0; i < count; ++i) {

		struct uk_netbuf *buf = NULL;
		buf = uk_netbuf_alloc_buf(uk_alloc_get_default(),
					NET_DATA_SIZE, dev_info[instance].nb_encap_rx, 0, NULL);
		TEST_NOT_NULL(buf);
		buf->len = NET_DATA_SIZE - dev_info[instance].nb_encap_rx;

		nb[i] = buf;
		if (!nb[i]) {
			/* we run out of memory */
			break;
		}
	}

	return i;
}

void netdev_test_rx_queue_configure(int instance)
{
	struct uk_netdev_rxqueue_conf conf = {0};
	int rc = 0;
	struct uk_alloc *a = uk_alloc_get_default();

	conf.a = a;
	conf.alloc_rxpkts = alloc_rxpkts;
	conf.alloc_rxpkts_argp = (void *) instance;

	conf.s = uk_sched_get_default();
	conf.a = uk_alloc_get_default();
	conf.callback = netdev_test_callback;
	conf.callback_cookie = (void *) instance;
	rc = uk_netdev_rxq_configure(netdevice[instance], 0, DESC_COUNT,
			&conf);
	TEST_ZERO_CHK(rc);
}

void netdev_test_tx_queue_configure(int instance)
{
	struct uk_netdev_txqueue_conf conf = {0};
	int rc = 0;
	conf.a = uk_alloc_get_default();
	rc = uk_netdev_txq_configure(netdevice[instance], 0, DESC_COUNT,
			&conf);
	TEST_ZERO_CHK(rc);
}

void netdev_test_start(int instance)
{
	int rc = 0;
	uk_pr_err("Starting the netdevice\n");
	rc = uk_netdev_start(netdevice[instance]);
	TEST_ZERO_CHK(rc);
}

void netdev_test_rxq_intr_enable(int instance)
{
	struct uk_netdev_rxqueue_conf conf = {0};
	int rc = 0;
	conf.s = uk_sched_get_default();
	conf.a = uk_alloc_get_default();
	rc = uk_netdev_rxq_intr_enable(netdevice[instance], 0);
	TEST_ZERO_CHK(rc);
}

void netdev_test_add_recv_desc_append(int instance)
{
	__u16 count = 1;
	int rc = 0, i = 0;
	struct uk_netbuf *buf = NULL;
	struct uk_netdev_info *conf = &dev_info[instance];
	uk_pr_info("RX queue hdr %d\n", conf->nb_encap_rx);

	/**
	 * Test a single buffer allocation.
	 */
	for (i = 0; i < DESC_COUNT; i++) {
		buf = uk_netbuf_alloc_buf(uk_alloc_get_default(),
					NET_DATA_SIZE, conf->nb_encap_rx, 0, NULL);
		TEST_NOT_NULL(buf);
		buf->len = NET_DATA_SIZE - conf->nb_encap_rx;
		count = 1;
		//rc = uk_netdev_rx_one(netdevice[instance], 0, NULL, &buf, &count);
		rc = uk_netdev_rx_one(netdevice[instance], 0, NULL);
		TEST_ZERO_CHK(rc);
		if (count == 0) {
			desc_cnt[instance]++;
		} else {
			uk_pr_err("The virtqueue is full %d\n",
					desc_cnt[instance]);
			spare_buf[instance] = buf;
			break;
		}
	}
}

static void netdev_receive_prepare(int instance __unused)
{
	uk_pr_err("Sleeping %ld\n", sem_flag.count);
	uk_semaphore_down(&sem_flag);
	uk_pr_err("Waking up %ld\n", sem_flag.count);
}

int main()
{
	uk_pr_err("START\n");
	/* Hold the main thread */
	// this is currently a dummy call to test ebpf
	// here we need the loader and
	// in netdev_test_callback the exec
	ebpf_vm = do_prepare_ebpf();
	uk_semaphore_init(&sem_flag, 0);
	uk_pr_err("Semaphore %ld\n", sem_flag.count);
	pkt_cnt[0].counter = 0;
	pkt_cnt[1].counter = 0;
#ifdef CONFIG_UKNETDEVTEST_INIT
	netdev_test_init();
	uk_pr_err("Semaphore after init %ld\n", sem_flag.count);
#endif /* CONFIG_UKNETDEVTEST_INIT */

#ifdef CONFIG_UKNETDEVTEST_FETCH
	uint32_t count = 0;
	netdev_init(&count);
	uk_pr_err("Device Count %d\n", count);
	netdev_test_fetch(count);
#endif /* CONFIG_UKNETDEVTEST_FETCH */

#ifdef CONFIG_UKNETDEVTEST_CONFIGURE
	netdev_test_configure(0);
	netdev_test_configure(1);
	uk_pr_err("Semaphore after configure %ld\n", sem_flag.count);
	netdev_test_invalid_configure(0);
#endif /* CONFIG_UKNETDEVTEST_CONFIGURE */

#ifdef CONFIG_UKNETDEVTEST_CONFIGURE_RX
	netdev_test_rx_queue_configure(0);
	netdev_test_rx_queue_configure(1);
	uk_pr_err("Semaphore after rx configure %ld\n", sem_flag.count);
#endif /* CONFIG_UKNETDEVTEST_CONFIGURE_RX */
#ifdef CONFIG_UKNETDEVTEST_CONFIGURE_TX
	netdev_test_tx_queue_configure(0);
	netdev_test_tx_queue_configure(1);
	uk_pr_err("Semaphore after tx configure %ld\n", sem_flag.count);
#endif /* CONFIG_UKNETDEVTEST_CONFIGURE_TX */

#ifdef CONFIG_UKNETDEVTEST_START
	netdev_test_start(0);
	uk_pr_err("Semaphore after start %ld\n", sem_flag.count);
	netdev_test_start(1);
	uk_pr_err("Semaphore after start %ld\n", sem_flag.count);
#endif /* CONFIG_UKNETDEVTEST_START */

#ifdef CONFIG_UKNETDEVTEST_RX_INTR
	netdev_test_rxq_intr_enable(0);
	uk_pr_err("Semaphore after intr enable %ld\n", sem_flag.count);
	netdev_test_rxq_intr_enable(1);
	uk_pr_err("Semaphore after intr enable %ld\n", sem_flag.count);
	uk_pr_info("Enabling interrupt\n");
#endif /* CONFIG_UKNETDEVTEST_RX_INTR */

#ifdef CONFIG_UKNETDEVTEST_DESCADD
	netdev_test_add_recv_desc_append(0);
	uk_pr_err("Semaphore after desc 1 %ld\n", sem_flag.count);
	netdev_test_add_recv_desc_append(1);
	uk_pr_err("Semaphore after desc 1 %ld\n", sem_flag.count);
#endif /* CONFIG_UKNETDEVTEST_DESCADD */

	netdev_receive_prepare(0);
	return 0;
}
