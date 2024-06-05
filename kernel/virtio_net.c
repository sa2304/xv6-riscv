#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "memlayout.h"
#include "spinlock.h"
#include "virtio.h"
//#include "string.h"

uint32 htonl(uint32 hostlong) {
  return
      (hostlong & 0xFF) << 24 |
          (hostlong & 0xFF00) << 8 |
          (hostlong & 0xFF0000) >> 8 |
          (hostlong & 0xFF000000) >> 24;
}

void test_htonl_1() {
  uint32 expected = 0x11223344, result = htonl(0x44332211);
  if (expected != result) {
    printf("test_htonl_1 failed: expected 0x%x, got 0x%x", expected, result);
    panic("assertion failed");
  }

  printf("test_htonl_1 passed!\n");
}

void test_htonl_2() {
  uint32 expected = 0xE95B0328, result = htonl(0x28035BE9);
  if (expected != result) {
    printf("test_htonl_2 failed: expected 0x%x, got 0x%x", expected, result);
    panic("assertion failed");
  }

  printf("test_htonl_2 passed!\n");
}

uint16 htons(uint16 hostshort) {
  return ((hostshort & 0xFF) << 8) | ((hostshort & 0xFF00) >> 8);
}

void test_htons_1() {
  uint16 expected = 0xABCD, result = htons(0xCDAB);
  if (expected != result) {
    printf("test_htons_1 failed: expected 0x%x, got 0x%x", expected, result);
    panic("assertion failed");
  }

  printf("test_htons_1 passed!\n");
}

void test_htons_2() {
  uint16 expected = 0x1324, result = htons(0x2413);
  if (expected != result) {
    printf("test_htons_2 failed: expected 0x%x, got 0x%x", expected, result);
    panic("assertion failed");
  }

  printf("test_htons_2 passed!\n");
}

//uint32_t ntohl(uint32_t netlong);
//uint16_t ntohs(uint16_t netshort);

#define R1(r) ((volatile uint32 *)(VIRTIO1 + (r)))
#define MacAddressLength 6

//static const uint32 VirtioNetReceiveQ = 0;
static const uint32 VirtioNetTransmitQ = 1;
static const uint8 macBroadcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

struct virtio_net_queue {
  struct virtq_desc *desc;
  struct virtq_avail *avail;
  struct virtq_used *used;
  char is_free[NUM];  // is a descriptor free?
};

void virtio_net_queue_init(uint8 i, struct virtio_net_queue *queue) {
  // initialize queue i.
  *R1(VIRTIO_MMIO_QUEUE_SEL) = i;

  // ensure queue i is not in use.
  if (*R1(VIRTIO_MMIO_QUEUE_READY))
    panic("virtio net should not be ready");

  // check maximum queue size.
  uint32 max = *R1(VIRTIO_MMIO_QUEUE_NUM_MAX);
  if (max == 0)
    panic("virtio net has no queue i");
  if (max < NUM)
    panic("virtio net max queue too short");

  // allocate and zero queue memory.
  queue->desc = kalloc();
  queue->avail = kalloc();
  queue->used = kalloc();
  if (!queue->desc || !queue->avail || !queue->used)
    panic("virtio net kalloc");
  memset(queue->desc, 0, PGSIZE);
  memset(queue->avail, 0, PGSIZE);
  memset(queue->used, 0, PGSIZE);

  // set queue size.
  *R1(VIRTIO_MMIO_QUEUE_NUM) = NUM;

  // write physical addresses.
  *R1(VIRTIO_MMIO_QUEUE_DESC_LOW) = (uint64) queue->desc;
  *R1(VIRTIO_MMIO_QUEUE_DESC_HIGH) = (uint64) queue->desc >> 32;
  *R1(VIRTIO_MMIO_DRIVER_DESC_LOW) = (uint64) queue->avail;
  *R1(VIRTIO_MMIO_DRIVER_DESC_HIGH) = (uint64) queue->avail >> 32;
  *R1(VIRTIO_MMIO_DEVICE_DESC_LOW) = (uint64) queue->used;
  *R1(VIRTIO_MMIO_DEVICE_DESC_HIGH) = (uint64) queue->used >> 32;

  // queue is ready.
  *R1(VIRTIO_MMIO_QUEUE_READY) = 0x1;

  // all NUM descriptors start out unused.
  for (int i = 0; i < NUM; i++)
    queue->is_free[i] = 1;
}

static struct network {
  struct virtio_net_queue transmit;
  struct virtio_net_queue receive;
  struct spinlock lock;
  uint8 mac[MacAddressLength];
  char is_transmit_done[NUM];
  uint16 used_idx;
} network;

struct virtio_net_config {
  uint8 mac[MacAddressLength];
};

//#define VIRTIO_PRINT_FEATURE(features, f) if ((features) & (f)) printf("%s\n", #f);

// find a free descriptor, mark it non-free, return its index.
static int
alloc_desc(struct virtio_net_queue *queue) {
  for (int i = 0; i < NUM; i++) {
    if (queue->is_free[i]) {
      queue->is_free[i] = 0;
      return i;
    }
  }
  return -1;
}

// mark a descriptor as free.
static void
free_desc(struct virtio_net_queue *queue, uint32 i) {
  if (NUM <= i)
    panic("free_desc: i too large");
  if (queue->is_free[i])
    panic("free_desc: desc already free");

  struct virtq_desc *desc = &queue->desc[i];
  desc->addr = 0;
  desc->len = 0;
  desc->flags = 0;
  desc->next = 0;
  queue->is_free[i] = 1;
  wakeup(&queue->is_free[0]);
}

void
virtio_net_init(void) {
  uint32 status = 0;

  initlock(&network.lock, "virtio_net");
  network.used_idx = 0;

  if (*R1(VIRTIO_MMIO_MAGIC_VALUE) != 0x74726976 ||
      *R1(VIRTIO_MMIO_VERSION) != 2 ||
      *R1(VIRTIO_MMIO_DEVICE_ID) != 1 ||
      *R1(VIRTIO_MMIO_VENDOR_ID) != 0x554d4551) {
    panic("could not find virtio net");
  }

  // reset device
  *R1(VIRTIO_MMIO_STATUS) = status;

  // guest OS saw the device
  status |= VIRTIO_CONFIG_S_ACKNOWLEDGE;
  *R1(VIRTIO_MMIO_STATUS) = status;
//  panic("virtio_net_init: after acknowledge");

  // tell device I can drive
  status |= VIRTIO_CONFIG_S_DRIVER;
  *R1(VIRTIO_MMIO_STATUS) = status;

  // enable features that I support
  //A truly minimal driver would only accept VIRTIO_NET_F_MAC and ignore everything else.
  *R1(VIRTIO_MMIO_DRIVER_FEATURES) = VIRTIO_NET_F_MAC | VIRTIO_NET_F_CSUM;

  // tell device that I'm done with features
  status |= VIRTIO_CONFIG_S_FEATURES_OK;
  *R1(VIRTIO_MMIO_STATUS) = status;

  // make sure that device accepted my features choice
  status = *R1(VIRTIO_MMIO_STATUS);
  if (!(status & VIRTIO_CONFIG_S_FEATURES_OK))
    panic("virtio net FEATURES_OK unset");

  // read device MAC address
  const struct virtio_net_config *config = (const struct virtio_net_config *) R1(VIRTIO_MMIO_CONFIG);
  printf("MAC = ");
  for (int i = 0; i < MacAddressLength; ++i) {
    network.mac[i] = config->mac[i];
    if (0 == i) printf("%x", config->mac[i]);
    else printf(":%x", config->mac[i]);
  }
  printf("\n");

  virtio_net_queue_init(0, &network.receive);
  virtio_net_queue_init(1, &network.transmit);
  memset(network.is_transmit_done, 0, NUM);

  // populate receive queue with buffers
  for (int i = 0; i < NUM; ++i) {
    struct virtq_desc *desc = &network.receive.desc[i];
    desc->addr = (uint64) kalloc();
    desc->len = PGSIZE;
    desc->flags = VRING_DESC_F_WRITE;
    desc->next = 0;

    network.receive.avail->ring[network.receive.avail->idx++ % NUM] = i;
  }
  //TODO Notify queue?

  // tell device that I've finished setup
  status |= VIRTIO_CONFIG_S_DRIVER_OK;
  *R1(VIRTIO_MMIO_STATUS) = status;
//  panic("DEBUG");
}

void
virtio_net_make_frame(void *buf, void *data, uint16 data_len, const uint8 *destination_mac, const uint8 *source_mac) {
  struct virtio_net_hdr *hdr = (struct virtio_net_hdr *) buf;
  memset(hdr, 0, sizeof(struct virtio_net_hdr));
  hdr->hdr_len = sizeof(struct virtio_net_hdr);

  char *p = (char *) buf + sizeof(struct virtio_net_hdr);
  const char *p_begin = p;

  // Preamble
  for (int i = 0; i < 7; ++i) {
    *p++ = 0xAA;
  }

  // SFD
  *p++ = 0xAB;

  // Destination MAC
  memmove(p, destination_mac, MacAddressLength);
  p += MacAddressLength;

  // Source MAC
  memmove(p, source_mac, MacAddressLength);
  p += MacAddressLength;

  // Len
  *(uint16 *) p = data_len;
  p += sizeof(data_len);

  // Data
  memmove(p, data, data_len);
  p += data_len;

  // Padding
  const uint16 minFrameSize = 64;
  // frame_size = sizes of DestinationAddress, SourceAddress, Len, Data, Pad, Checksum
  uint16 frame_size = data_len + 2 * MacAddressLength + 6;
  uint16 pad_size = (frame_size < minFrameSize) ? minFrameSize - frame_size : 0;
  memset(p, 0, pad_size);
  p += pad_size;

  // Checksum
  //TODO Now we rely on VIRTIO_NET_F_CSUM feature and expect device to calculate checksum
  hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
  hdr->csum_start = 8;
  hdr->csum_offset = p - p_begin;
}

void
virtio_net_send(void *data, uint16 data_len, const uint8 *destination_mac) {
  printf("virtio_net_send: begin\n");
  void *buf = kalloc();
  virtio_net_make_frame(buf, data, data_len, destination_mac, network.mac);
  printf("virtio_net_send: frame made\n");

  // Put buffer into transmit virtqueue
  acquire(&network.lock);
  int idx = alloc_desc(&network.transmit);
  while (-1 == idx) {
    sleep(&network.transmit.is_free[0], &network.lock);
    idx = alloc_desc(&network.transmit);
  }
  struct virtq_desc *desc = &network.transmit.desc[idx];
  desc->addr = (uint64) buf;
  desc->len = PGSIZE;
  desc->flags = 0;
  desc->next = 0;

  network.transmit.avail->ring[network.transmit.avail->idx % NUM] = idx;
  __sync_synchronize();
  network.transmit.avail->idx++;
  __sync_synchronize();
  *R1(VIRTIO_MMIO_QUEUE_NOTIFY) = VirtioNetTransmitQ; // value is queue number
  printf("virtio_net_send: frame put in transmitq\n");

  // Wait for virtio_net_intr() to say request has finished.
  while (0 == network.is_transmit_done[idx]) {
    sleep(&network.is_transmit_done[0], &network.lock);
  }

  printf("virtio_net_send transmit done\n");
  network.is_transmit_done[idx] = 0;
  free_desc(&network.transmit, idx);

  release(&network.lock);
}

void
virtio_net_intr(void) {
  acquire(&network.lock);
  printf("virtio_net_intr: begin\n");

  while (network.used_idx < network.transmit.used->idx) {
    const uint32 id = network.transmit.used->ring[network.used_idx].id;
    network.is_transmit_done[id] = 1;
    printf("virtio_net_intr: frame %d transmitted\n", id);
    ++network.used_idx;
  }
  wakeup(&network.is_transmit_done[0]);

  release(&network.lock);
}

static const uint8 op_size = 1;
static const uint8 htype_size = 1;
static const uint8 hlen_size = 1;
static const uint8 hops_size = 1;
static const uint8 xid_size = 4;
static const uint8 secs_size = 2;
static const uint8 flags_size = 2;
static const uint8 ciaddr_size = 4;
static const uint8 yiaddr_size = 4;
static const uint8 siaddr_size = 4;
static const uint8 giaddr_size = 4;
static const uint8 chaddr_size = 16;
static const uint8 sname_size = 64;
static const uint8 file_size = 128;
static const uint8 dhcpMessageSize = op_size + htype_size + hlen_size + hops_size + xid_size + secs_size + flags_size +
    ciaddr_size + yiaddr_size + siaddr_size + giaddr_size + chaddr_size + sname_size + file_size;
static const uint8 dhcpOpRequest = 1;
static const uint8 dhcpHtypeEthernet = 1;
void virtio_net_make_dhcp_message(uint8 *buf, uint8 op, uint8 htype, uint8 hlen, uint8 hops, uint32 xid, uint16 secs,
                                  uint16 flags, uint32 ciaddr, uint32 yiaddr, uint32 siaddr, uint32 giaddr,
                                  uint8 *chaddr, char *sname, char *boot_file_name) {
  //FIXME Add length parameters for chaddr, sname, boot_file_name
  memset(buf, 0, dhcpMessageSize);
  uint8 *p = buf;
  *p = op;
  p += op_size;

  *p = htype;
  p += htype_size;

  *p = hlen;
  p += hlen_size;

  *p = hops;
  p += hops_size;

  *(uint32 *) p = htonl(xid);
  p += xid_size;

  *(uint16 *) p = htons(secs);
  p += secs_size;

  *(uint16 *) p = htons(flags);
  p += flags_size;

  *(uint32 *) p = htonl(ciaddr);
  p += ciaddr_size;

  *(uint32 *) p = htonl(yiaddr);
  p += yiaddr_size;

  *(uint32 *) p = htonl(siaddr);
  p += siaddr_size;

  *(uint32 *) p = htonl(giaddr);
  p += giaddr_size;

  for (int i = 0; i < chaddr_size; ++i) {
    *p++ = chaddr[i];
  }

  if (sname) { strncpy((char *) p, sname, sname_size); }
  p += sname_size;

  if (boot_file_name) { strncpy((char *) p, boot_file_name, file_size); }
  p += file_size;
}

void assert_memory_equal(void *v1, void *v2, int n, const char *error_message_prefix) {
  uint8 *b1 = (uint8 *) v1;
  uint8 *b2 = (uint8 *) v2;
  for (int i = 0; i < n; ++i) {
    if (*b1 != *b2) {
      printf("%s: expected 0x%x, got 0x%x at i=%d\n", error_message_prefix, *b1, *b2, i);
      panic("assertion failed");
    }
    ++b1, ++b2;
  }
}

void test_virtio_net_make_dhcp_message() {
  uint8 mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint8 *buf = kalloc();
  virtio_net_make_dhcp_message(buf, dhcpOpRequest, dhcpHtypeEthernet, MacAddressLength, 0, 1, 2, 0xABCD, 0x1A2B3C4D,
                               0x11121314, 0x98765432, 0x00337722, mac, 0, 0);
  uint8 expected[] = {dhcpOpRequest, dhcpHtypeEthernet, MacAddressLength, 0x00,
                      0x00, 0x00, 0x00, 0x01, // xid
                      0x00, 0x02, // secs
                      0xAB, 0xCD, // flags
                      0x1A, 0x2B, 0x3C, 0x4D, // ciaddr
                      0x11, 0x12, 0x13, 0x14, // yiaddr
                      0x98, 0x76, 0x54, 0x32, // siaddr
                      0x00, 0x33, 0x77, 0x22, // giaddr

      // chaddr - 16 bytes
                      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

      // sname - 64 bytes
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

      // boot file name - 128 bytes
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  assert_memory_equal(expected, buf, dhcpMessageSize, "test_virtio_net_make_dhcp_message");
//  for (int i = 0; i < dhcpMessageSize; ++i) {
//    if (expected[i] != buf[i]) {
//      printf("test_virtio_net_make_dhcp_message: expected 0x%x, got 0x%x at i=%d\n", expected[i], buf[i], i);
//      panic("assertion failed");
//    }
//    printf("%x ", expected[i]);
//  }

  printf("test_virtio_net_make_dhcp_message: test passed!\n");
}

static const uint8 ipHeaderSize = 20;
uint8 virtio_net_make_ip_header(uint8 *buf, uint8 type_of_service, uint16 data_length, uint8 protocol,
                                uint32 source_address, uint32 destination_address) {
  const uint8 header_length = ipHeaderSize / sizeof(uint32);  // in 32-bit words

  uint8 *p = buf;

  // Version 4 and header length of 5 * 4 = 20 bytes
  *p = 0x40 | header_length;
  ++p;

  // Type of service
  *p++ = 0;

  // Total length
  uint16 total_length = data_length + header_length * sizeof(uint32);
  *(uint16 *) p = htons(total_length);
  p += sizeof(total_length);

  // Identification - aids in assembling the fragments of a datagram
  *(uint16 *) p = 0;
  p += sizeof(uint16);

  // Flags and Fragment offset
  *(uint16 *) p = 0;
  p += sizeof(uint16);

  // Time to live
  *p = 128;
  ++p;

  // Protocol
  *p = protocol;
  p += sizeof(protocol);

  // Checksum (disabled)
  *(uint16 *) p = 0;
  p += sizeof(uint16);

  *(uint32 *) p = htonl(source_address);
  p += sizeof(source_address);

  *(uint32 *) p = htonl(destination_address);
  p += sizeof(destination_address);

  return header_length * sizeof(uint32);
}

/** Returns IP address as uint32, little-endian */
uint32 virtio_net_make_ip_address(uint8 a, uint8 b, uint8 c, uint8 d) {
  return ((uint32) d << 24) | ((uint32) c << 16) | ((uint32) b << 8) | a;
}

void test_virtio_net_make_ip_address_1() {
  uint32 expected = 0x04030201, result = virtio_net_make_ip_address(1, 2, 3, 4);
  if (expected != result) {
    printf("expected 0x%x, got 0x%x\n", expected, result);
    panic("test_virtio_net_make_ip_address_1 failed");
  }
  printf("test_virtio_net_make_ip_address_1 passed!\n");
}

void test_virtio_net_make_ip_address_2() {
  uint32 expected = 0x3200A8C0, result = virtio_net_make_ip_address(192, 168, 0, 50);
  if (expected != result) {
    printf("expected 0x%x, got 0x%x\n", expected, result);
    panic("test_virtio_net_make_ip_address_2 failed");
  }
  printf("test_virtio_net_make_ip_address_2 passed!\n");
}

void test_virtio_net_make_ip_header() {
  uint8 *buf = (uint8 *) kalloc();
  uint8 expected[] = {
      0x45, // Version | IHL
      0x00, // Type of service
      0x78, 0x24,  // Total length
      0x00, 0x00, // Identification
      0x00, 0x00, // Flags | Fragment offset
      0x80, // TTL
      0x10, // Protocol
      0x00, 0x00, // Header checksum
      0xC0, 0xA8, 0x00, 0x3A, // Source address - 192.168.0.58
      0xC0, 0xA8, 0x00, 0x01, // Destination address - 192.168.0.1
  };

  virtio_net_make_ip_header(buf, 0xA1, 0x7810, 0x10, 0xC0A8003A, 0xC0A80001);
  assert_memory_equal(expected, buf, ipHeaderSize, "test_virtio_net_make_ip_header");

  printf("test_virtio_net_make_ip_header: test passed!\n");
}

static const uint8 udpHeaderSize = 4 * sizeof(uint16);
static const uint8 protocolUdp = 0x11;
void virtio_net_make_udp_header(uint8 *buf, uint16 source_port, uint16 destination_port, uint16 length,
                                uint16 checksum) {
  uint8 *p = buf;
  *(uint16 *) p = source_port;
  p += sizeof(source_port);

  *(uint16 *) p = destination_port;
  p += sizeof(destination_port);

  *(uint16 *) p = length;
  p += sizeof(length);

  *(uint16 *) p = checksum;
  p += sizeof(checksum);
}

void virtio_net_send_dhcp_request() {
  uint8 *dhcp_message = (uint8 *) kalloc();
  const uint8 transaction_id = 1;
  virtio_net_make_dhcp_message(dhcp_message, dhcpOpRequest, dhcpHtypeEthernet, MacAddressLength, 0, transaction_id,
                               0, 0, 0, 0, 0, 0, network.mac, 0, 0);

  uint8 *ip_message = (uint8 *) kalloc();
  virtio_net_make_udp_header(ip_message, 68, 67, dhcpMessageSize, 0);
  memmove(ip_message + udpHeaderSize, dhcp_message, dhcpMessageSize);

  uint8 *ethernet_data = (uint8 *) kalloc();
  uint8 ip_header_size = virtio_net_make_ip_header(ethernet_data, 0, dhcpMessageSize + udpHeaderSize, protocolUdp, 0,
                                                   0xFFFFFFFF);
  memmove(ethernet_data + ip_header_size, ip_message, udpHeaderSize + dhcpMessageSize);

  virtio_net_send(ethernet_data, ip_header_size + udpHeaderSize + dhcpMessageSize, macBroadcast);
//  uint8* ethernet_frame = (uint8 *) kalloc();
//  virtio_net_make_frame(ethernet_frame, ethernet_data, ip_header_size + udpHeaderSize + dhcpMessageSize, macBroadcast,
//                        network.mac);
}

uint64
sys_test_virtio_net_send(void) {
  test_htonl_1();
  test_htonl_2();

  test_htons_1();
  test_htons_2();

  test_virtio_net_make_ip_address_1();
  test_virtio_net_make_ip_address_2();

  test_virtio_net_make_dhcp_message();
  test_virtio_net_make_ip_header();

//  virtio_net_send_dhcp_request();
//  virtio_net_send(0, 0, macBroadcast);

  return 0;
}
