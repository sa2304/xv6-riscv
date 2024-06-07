#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "memlayout.h"
#include "spinlock.h"
#include "virtio.h"
//#include "string.h"

static const uint8 ETHERNET_HEADER_OFFSET_DEST_ADDR = 0;
static const uint8 ETHERNET_HEADER_OFFSET_SRC_ADDR = 6;
static const uint8 ETHERNET_HEADER_OFFSET_LEN_TYPE = 12;
static const uint8 ETHERNET_HEADER_SIZE = 14;
static const uint16 ETHERNET_TYPE_IPV4 = 0x0800;

static const uint8 IP_HEADER_OFFSET_VERSION_IHL = 0;
static const uint8 IP_HEADER_OFFSET_TYPE_OF_SERVICE = 1;
static const uint8 IP_HEADER_OFFSET_TOTAL_LENGTH = 2;
static const uint8 IP_HEADER_OFFSET_IDENTIFICATION = 4;
static const uint8 IP_HEADER_OFFSET_FLAGS = 6;
static const uint8 IP_HEADER_OFFSET_TTL = 8;
static const uint8 IP_HEADER_OFFSET_PROTOCOL = 9;
static const uint8 IP_HEADER_OFFSET_HEADER_CSUM = 10;
static const uint8 IP_HEADER_OFFSET_SRC_ADDR = 12;
static const uint8 IP_HEADER_OFFSET_DEST_ADDR = 16;
//static const uint8 IP_HEADER_OFFSET_OPTIONS = 20;
static const uint8 IP_HEADER_SIZE = 20;

static const uint8 UDP_HEADER_OFFSET_SRC_PORT = 0;
static const uint8 UDP_HEADER_OFFSET_DEST_PORT = 2;
static const uint8 UDP_HEADER_OFFSET_LENGTH = 4;
static const uint8 UDP_HEADER_OFFSET_CSUM = 6;
static const uint8 UDP_HEADER_SIZE = 8;

static const uint8 DHCP_MESSAGE_CHADDR_SIZE_MAX = 16;
static const uint8 DHCP_MESSAGE_BOOT_FILE_NAME_SIZE_MAX = 128;
static const uint8 DHCP_MESSAGE_SNAME_SIZE_MAX = 64;

static const uint8 DHCP_MESSAGE_OFFSET_OP = 0;
static const uint8 DHCP_MESSAGE_OFFSET_HTYPE = 1;
static const uint8 DHCP_MESSAGE_OFFSET_HLEN = 2;
static const uint8 DHCP_MESSAGE_OFFSET_HOPS = 3;
static const uint8 DHCP_MESSAGE_OFFSET_XID = 4;
static const uint8 DHCP_MESSAGE_OFFSET_SECS = 8;
static const uint8 DHCP_MESSAGE_OFFSET_FLAGS = 10;
static const uint8 DHCP_MESSAGE_OFFSET_CIADDR = 12;
static const uint8 DHCP_MESSAGE_OFFSET_YIADDR = 16;
static const uint8 DHCP_MESSAGE_OFFSET_SIADDR = 20;
static const uint8 DHCP_MESSAGE_OFFSET_GIADDR = 24;
static const uint8 DHCP_MESSAGE_OFFSET_CHADDR = 28;
static const uint8 DHCP_MESSAGE_OFFSET_SNAME = 44;
static const uint8 DHCP_MESSAGE_OFFSET_BOOT_FILE_NAME = 108;
//static const uint8 DHCP_MESSAGE_OFFSET_OPTIONS = 236;
static const uint8 DHCP_MESSAGE_SIZE = 236; // does not include required DHCP options

// DHCP client must handle Options field with length at least 321 octets.
// This requirement implies that a DHCP client must be prepared to receive a message of up to 576 octets,
// the minimum IP datagram size an IP host must be prepared to accept.
// DHCP clients may negotiate the use of larger DHCP messages through the ’maximum DHCP message size’ option.

static const uint8 PROTOCOL_UDP = 0x11;

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
#define MAC_ADDRESS_LENGTH 6

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
  uint8 mac[MAC_ADDRESS_LENGTH];
  char is_transmit_done[NUM];
  uint16 used_idx;
} network;

struct virtio_net_config {
  uint8 mac[MAC_ADDRESS_LENGTH];
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
  *R1(VIRTIO_MMIO_DRIVER_FEATURES) = VIRTIO_NET_F_MAC /*| VIRTIO_NET_F_CSUM*/;

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
  for (int i = 0; i < MAC_ADDRESS_LENGTH; ++i) {
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

void virtio_net_ethernet_header_write(void *buf, const uint8 *destination_mac, const uint8 *source_mac, uint16 type) {
  uint8 *hdr = (uint8 *) buf;
  memmove(&hdr[ETHERNET_HEADER_OFFSET_DEST_ADDR], destination_mac, MAC_ADDRESS_LENGTH);
  memmove(&hdr[ETHERNET_HEADER_OFFSET_SRC_ADDR], source_mac, MAC_ADDRESS_LENGTH);
  *((uint16 *) &hdr[ETHERNET_HEADER_OFFSET_LEN_TYPE]) = htons(type);
}

void test_virtio_net_ethernet_header_write_1() {
  uint8 expected[] = {0x54, 0xf7, 0x26, 0x6d, 0x5c, 0xc8, // destination address
                      0x7a, 0x8b, 0x7c, 0x92, 0x08, 0x01, // source address
                      0x80, 0x35, // len/type
  };
  void *buf = kalloc();
  const uint8 destination_address[6] = {0x54, 0xf7, 0x26, 0x6d, 0x5c, 0xc8};
  const uint8 source_address[6] = {0x7a, 0x8b, 0x7c, 0x92, 0x08, 0x01};
  virtio_net_ethernet_header_write(buf, destination_address, source_address, 0x8035);
  assert_memory_equal(expected, buf, ETHERNET_HEADER_SIZE, "test_virtio_net_ethernet_header_write_1");

  printf("test_virtio_net_ethernet_header_write_1 passed!\n");
}

void test_virtio_net_ethernet_header_write_2() {
  uint8 expected[] = {0x1a, 0xee, 0x1c, 0x98, 0x03, 0xc9, // destination address
                      0x76, 0x84, 0x62, 0xcf, 0x3f, 0xa4, // source address
                      0x60, 0x02, // len/type
  };
  void *buf = kalloc();
  const uint8 destination_address[6] = {0x1a, 0xee, 0x1c, 0x98, 0x03, 0xc9};
  const uint8 source_address[6] = {0x76, 0x84, 0x62, 0xcf, 0x3f, 0xa4};
  virtio_net_ethernet_header_write(buf, destination_address, source_address, 0x6002);
  assert_memory_equal(expected, buf, ETHERNET_HEADER_SIZE, "test_virtio_net_ethernet_header_write_2");

  printf("test_virtio_net_ethernet_header_write_2 passed!\n");
}

void virtio_net_ethernet_frame_write(void *buf, void *data, uint16 data_len, const uint8 *destination_mac,
                                     const uint8 *source_mac, uint16 type) {
  const uint16 hdr_len = sizeof(struct virtio_net_hdr);
  printf("virtio_net_hdr length = %d\n", hdr_len);
  struct virtio_net_hdr *hdr = (struct virtio_net_hdr *) buf;
  memset(hdr, 0, hdr_len);
  hdr->hdr_len = hdr_len;

  virtio_net_ethernet_header_write(buf + hdr_len, destination_mac, source_mac, type);

  uint8 *frame = (uint8 *) buf + hdr_len;
  // Data
  memmove(&frame[ETHERNET_HEADER_SIZE], data, data_len);

  // Padding
  const uint16 minFrameSize = 64;
  // frame_size = sizes of DestinationAddress, SourceAddress, Len, Data, Pad, Checksum
  uint16 frame_size = data_len + 2 * MAC_ADDRESS_LENGTH + 6;
  uint16 pad_size = (frame_size < minFrameSize) ? minFrameSize - frame_size : 0;
  memset(&frame[ETHERNET_HEADER_SIZE + data_len], 0, pad_size);

  //FIXME Checksum
  *((uint32 *) &frame[ETHERNET_HEADER_SIZE + data_len + pad_size]) = 0;
  //TODO Now we rely on VIRTIO_NET_F_CSUM feature and expect device to calculate checksum
  hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
  hdr->csum_start = 14 + 20;
  hdr->csum_offset = 6;

//  printf("{ ");
//  for (int i = 0; i < hdr->csum_offset; ++i) {
//    printf("0x%x, ", *((uint8*)buf + i));
//  }
//  printf("}\n");
}

void test_virtio_net_ethernet_frame_write_1() {
  // Ethernet frame of minimum size - 64 octets
  uint8 expecred[64] = {
      // Ethernet header - 14 octects
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // destination address
      0x6c, 0x48, 0x67, 0x94, 0x52, 0x0e, // source address
      0x12, 0x34,  // len/type

      // Data + padding
      0x08, 0xC0, 0x0A, 0x8C,
      0x19, 0x95, 0x43, 0x6B, 0x73, 0x71, 0x34, 0xBB,
      0x56, 0xE8, 0x17, 0x76, 0x08, 0xDC, 0x48, 0x36,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00,

      // Checksum
      0x00, 0x00, 0x00, 0x00};

  uint8 destination_address[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8 source_address[] = {0x6c, 0x48, 0x67, 0x94, 0x52, 0x0e};
  uint8 data[] = {0x08, 0xC0, 0x0A, 0x8C,
                  0x19, 0x95, 0x43, 0x6B, 0x73, 0x71, 0x34, 0xBB,
                  0x56, 0xE8, 0x17, 0x76, 0x08, 0xDC, 0x48, 0x36}; // 20 octets
  uint8 *buf = (uint8 *) kalloc();
  memset(buf, 0, PGSIZE);

  virtio_net_ethernet_frame_write(buf, data, 20, destination_address, source_address, 0x1234);

  assert_memory_equal(expecred, buf, 64, "test_virtio_net_ethernet_frame_write_1");
  // make sure other memory is untouched
  for (int i = 64; i < PGSIZE; ++i) {
    if (buf[i] != 0) {
      printf("test_virtio_net_ethernet_frame_write_1 memory after packet is corrupted: byte 0x%x at %d\n", buf[i], i);
      panic("assert failed");
    }
  }

  printf("test_virtio_net_ethernet_frame_write_1 passed!\n");
}

void test_virtio_net_ethernet_frame_write_2() {
  uint8 expected[] = {
      // Ethernet header - 14 octets
      0xeb, 0xab, 0x84, 0x1c, 0x93, 0xa2, // destination address
      0x26, 0xd9, 0x5a, 0x74, 0x10, 0xf7, // source address
      0x22, 0x88, // len/type

      // Data
      0xa0, 0x49, 0xb9, 0x0c, 0x94, 0xf8, 0x6f, 0x4a,
      0x33, 0x79, 0x12, 0xb5, 0x6d, 0xb9, 0xa4, 0x77,
      0x78, 0xe0, 0xf8, 0x93, 0x63, 0x7f, 0xef, 0x42,
      0x87, 0x96, 0xae, 0xcd, 0x7f, 0x9e, 0x2d, 0xee,
      0xda, 0xff, 0x85, 0xae, 0xe1, 0x49, 0x0d, 0x44,
      0x11, 0xca, 0xc7, 0x6a, 0xd7, 0x1c,

      // Checksum
      0x00, 0x00, 0x00, 0x00};

  uint8 destination_address[] = {0xeb, 0xab, 0x84, 0x1c, 0x93, 0xa2};
  uint8 source_address[] = {0x26, 0xd9, 0x5a, 0x74, 0x10, 0xf7};
  // data fits in minFrameSize = 64, no padding
  uint8 data[] = {0xa0, 0x49, 0xb9, 0x0c, 0x94, 0xf8, 0x6f, 0x4a,
                  0x33, 0x79, 0x12, 0xb5, 0x6d, 0xb9, 0xa4, 0x77,
                  0x78, 0xe0, 0xf8, 0x93, 0x63, 0x7f, 0xef, 0x42,
                  0x87, 0x96, 0xae, 0xcd, 0x7f, 0x9e, 0x2d, 0xee,
                  0xda, 0xff, 0x85, 0xae, 0xe1, 0x49, 0x0d, 0x44,
                  0x11, 0xca, 0xc7, 0x6a, 0xd7, 0x1c};  // 46 octets
  uint8 *buf = (uint8 *) kalloc();
  memset(buf, 0, PGSIZE);

  virtio_net_ethernet_frame_write(buf, data, 64, destination_address, source_address, 0x2288);

  assert_memory_equal(expected, buf, 64, "test_virtio_net_ethernet_frame_write_2");
  // make sure other memory is untouched
  for (int i = 64; i < PGSIZE; ++i) {
    if (buf[i] != 0) {
      printf("test_virtio_net_ethernet_frame_write_2 memory after packet is corrupted: byte 0x%x at %d\n", buf[i], i);
      panic("assert failed");
    }
  }

  printf("test_virtio_net_ethernet_frame_write_2 passed!\n");
}

void test_virtio_net_ethernet_frame_write_3() {
  //FIXME large data, frame exceeds midFrameSize
  uint8 expected[] = {
      // Ethernet header - 14 octets
      0xcd, 0x6f, 0x4a, 0x5e, 0x62, 0x1a, // destination address
      0x8f, 0x45, 0x1c, 0x2b, 0xab, 0x63, // source address
      0x60, 0x04, // len/type

      // Data - 72 octets
      0x97, 0x7e, 0xbc, 0xb2, 0x5c, 0x98, 0x6e, 0xb2,
      0xac, 0x9b, 0x9a, 0x20, 0x80, 0x26, 0x04, 0xf5,
      0x93, 0xd9, 0xb5, 0xf2, 0x2d, 0x5a, 0x07, 0xf9,
      0x44, 0x4b, 0x59, 0x9b, 0x9a, 0x55, 0x4c, 0xd7,
      0x8e, 0xf7, 0xc0, 0x17, 0x66, 0x3a, 0x59, 0x42,
      0xcf, 0xb8, 0x23, 0xea, 0x42, 0x62, 0x50, 0x2b,
      0x03, 0x92, 0x2d, 0x9b, 0xe4, 0x9c, 0xb6, 0x02,
      0x7c, 0xaa, 0x36, 0x2b, 0x67, 0x4d, 0xf0, 0x45,
      0x3a, 0x2f, 0x87, 0xf5, 0xa7, 0x8f, 0x7c, 0x76,

      // Checksum
      0x00, 0x00, 0x00, 0x00};

  uint8 destination_address[] = {0xcd, 0x6f, 0x4a, 0x5e, 0x62, 0x1a};
  uint8 source_address[] = {0x8f, 0x45, 0x1c, 0x2b, 0xab, 0x63};
  uint8 data[72] = {0x97, 0x7e, 0xbc, 0xb2, 0x5c, 0x98, 0x6e, 0xb2,
                    0xac, 0x9b, 0x9a, 0x20, 0x80, 0x26, 0x04, 0xf5,
                    0x93, 0xd9, 0xb5, 0xf2, 0x2d, 0x5a, 0x07, 0xf9,
                    0x44, 0x4b, 0x59, 0x9b, 0x9a, 0x55, 0x4c, 0xd7,
                    0x8e, 0xf7, 0xc0, 0x17, 0x66, 0x3a, 0x59, 0x42,
                    0xcf, 0xb8, 0x23, 0xea, 0x42, 0x62, 0x50, 0x2b,
                    0x03, 0x92, 0x2d, 0x9b, 0xe4, 0x9c, 0xb6, 0x02,
                    0x7c, 0xaa, 0x36, 0x2b, 0x67, 0x4d, 0xf0, 0x45,
                    0x3a, 0x2f, 0x87, 0xf5, 0xa7, 0x8f, 0x7c, 0x76};
  uint8 *buf = (uint8 *) kalloc();
  memset(buf, 0, PGSIZE);

  virtio_net_ethernet_frame_write(buf, data, 72, destination_address, source_address, 0x6004);

  assert_memory_equal(expected, buf, ETHERNET_HEADER_SIZE + 72 + 4, "test_virtio_net_ethernet_frame_write_3");
  // make sure other memory is untouched
  for (int i = ETHERNET_HEADER_SIZE + 72 + 4; i < PGSIZE; ++i) {
    if (buf[i] != 0) {
      printf("test_virtio_net_ethernet_frame_write_3 memory after packet is corrupted: byte 0x%x at %d\n", buf[i], i);
      panic("assert failed");
    }
  }

  printf("test_virtio_net_ethernet_frame_write_3 passed!\n");
}

void
virtio_net_send(void *data, uint16 data_len, const uint8 *destination_mac) {
  printf("virtio_net_send: begin\n");
  void *buf = kalloc();
  virtio_net_ethernet_frame_write(buf, data, data_len, destination_mac, network.mac, ETHERNET_TYPE_IPV4);
  printf("virtio_net_send: frame made\n");

  // Put buffer into transmit virtqueue
  acquire(&network.lock);
  //TODO Extract virtio_net_queue_push function
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

#define MIN(a, b) ((a) < (b)) ? (a) : (b)

//static const uint8 op_size = 1;
//static const uint8 htype_size = 1;
//static const uint8 hlen_size = 1;
//static const uint8 hops_size = 1;
//static const uint8 xid_size = 4;
//static const uint8 secs_size = 2;
//static const uint8 flags_size = 2;
//static const uint8 ciaddr_size = 4;
//static const uint8 yiaddr_size = 4;
//static const uint8 siaddr_size = 4;
//static const uint8 giaddr_size = 4;
//static const uint8 chaddr_size = 16;
//static const uint8 sname_size = 64;
//static const uint8 file_size = 128;
//static const uint8 DHCP_MESSAGE_SIZE = op_size + htype_size + hlen_size + hops_size + xid_size + secs_size + flags_size +
//    ciaddr_size + yiaddr_size + siaddr_size + giaddr_size + chaddr_size + sname_size + file_size;
static const uint8 DHCP_OP_REQUEST = 1;
static const uint8 DHCP_HTYPE_ETHERNET = 1;
/** Fills DHCP message fields */
void virtio_net_dhcp_message_write(void *buf, uint8 op, uint8 htype, uint8 hlen, uint8 hops, uint32 xid, uint16 secs,
                                   uint16 flags, uint32 ciaddr, uint32 yiaddr, uint32 siaddr, uint32 giaddr,
                                   uint8 *chaddr, uint8 chaddr_size, char *sname, char *boot_file_name) {
  //FIXME Add length parameters for chaddr, sname, boot_file_name
  memset(buf, 0, DHCP_MESSAGE_SIZE);

  uint8 *msg = (uint8 *) buf;
  msg[DHCP_MESSAGE_OFFSET_OP] = op;
  msg[DHCP_MESSAGE_OFFSET_HTYPE] = htype;
  msg[DHCP_MESSAGE_OFFSET_HLEN] = hlen;
  msg[DHCP_MESSAGE_OFFSET_HOPS] = hops;
  *((uint32 *) &msg[DHCP_MESSAGE_OFFSET_XID]) = htonl(xid);
  *((uint16 *) &msg[DHCP_MESSAGE_OFFSET_SECS]) = htons(secs);
  *((uint16 *) &msg[DHCP_MESSAGE_OFFSET_FLAGS]) = htons(flags);
  *((uint32 *) &msg[DHCP_MESSAGE_OFFSET_CIADDR]) = htonl(ciaddr);
  *((uint32 *) &msg[DHCP_MESSAGE_OFFSET_YIADDR]) = htonl(yiaddr);
  *((uint32 *) &msg[DHCP_MESSAGE_OFFSET_SIADDR]) = htonl(siaddr);
  *((uint32 *) &msg[DHCP_MESSAGE_OFFSET_GIADDR]) = htonl(giaddr);

  if (DHCP_MESSAGE_CHADDR_SIZE_MAX < chaddr_size) { chaddr_size = DHCP_MESSAGE_CHADDR_SIZE_MAX; }
  for (int i = 0; i < chaddr_size; ++i) {
    msg[DHCP_MESSAGE_OFFSET_CHADDR + i] = chaddr[i];
  }

  if (sname) {
    uint8 sname_size = MIN(strlen(sname), DHCP_MESSAGE_SNAME_SIZE_MAX);
    strncpy((char *) &msg[DHCP_MESSAGE_OFFSET_SNAME], sname, sname_size);
  }

  if (boot_file_name) {
    uint8 boot_file_name_size = MIN(strlen(boot_file_name), DHCP_MESSAGE_BOOT_FILE_NAME_SIZE_MAX);
    strncpy((char *) &msg[DHCP_MESSAGE_OFFSET_BOOT_FILE_NAME], boot_file_name, boot_file_name_size);
  }

  //FIXME Implement other DHCP-message constructors which write required options
}

void test_virtio_net_dhcp_message_write_1() {
  uint8 mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  void *buf = kalloc();
  virtio_net_dhcp_message_write(buf, DHCP_OP_REQUEST, DHCP_HTYPE_ETHERNET, MAC_ADDRESS_LENGTH, 0, 1, 2, 0xABCD,
                                0x1A2B3C4D, 0x11121314, 0x98765432, 0x00337722, mac, 6, 0, 0);
  uint8 expected[] = {DHCP_OP_REQUEST, DHCP_HTYPE_ETHERNET, MAC_ADDRESS_LENGTH, 0x00,
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

  assert_memory_equal(expected, buf, DHCP_MESSAGE_SIZE, "test_virtio_net_dhcp_message_write");
//  for (int i = 0; i < DHCP_MESSAGE_SIZE; ++i) {
//    if (expected[i] != buf[i]) {
//      printf("test_virtio_net_dhcp_message_write: expected 0x%x, got 0x%x at i=%d\n", expected[i], buf[i], i);
//      panic("assertion failed");
//    }
//    printf("%x ", expected[i]);
//  }

  printf("test_virtio_net_dhcp_message_write: test passed!\n");
}

void test_virtio_net_dhcp_message_write_2() {
  //FIXME
  panic("test_virtio_net_dhcp_message_write_2");
}

void virtio_net_ip_header_write(void *buf, uint8 type_of_service, uint16 data_length, uint8 protocol,
                                uint32 source_address, uint32 destination_address) {
  const uint8 header_length = IP_HEADER_SIZE / sizeof(uint32);  // in 32-bit words

  uint8* hdr = (uint8*) buf; 
  // Version 4 and header length of 5 * 4 = 20 bytes
  hdr[IP_HEADER_OFFSET_VERSION_IHL] = 0x40 | header_length;

  // Type of service
  hdr[IP_HEADER_OFFSET_TYPE_OF_SERVICE] = 0;

  // Total length
  uint16 total_length = data_length + header_length * sizeof(uint32);
  *((uint16 *) &hdr[IP_HEADER_OFFSET_TOTAL_LENGTH]) = htons(total_length);

  // Identification - aids in assembling the fragments of a datagram
  *((uint16 *) &hdr[IP_HEADER_OFFSET_IDENTIFICATION]) = 0;

  // Flags and Fragment offset
  *((uint16 *) &hdr[IP_HEADER_OFFSET_FLAGS]) = 0;

  // Time to live
  hdr[IP_HEADER_OFFSET_TTL] = 128;

  // Protocol
  hdr[IP_HEADER_OFFSET_PROTOCOL] = protocol;

  // Checksum (disabled)
  *((uint16 *) &hdr[IP_HEADER_OFFSET_HEADER_CSUM]) = 0;

  // Source address
  *((uint32 *) &hdr[IP_HEADER_OFFSET_SRC_ADDR]) = htonl(source_address);

  // Destination address
  *((uint32 *) &hdr[IP_HEADER_OFFSET_DEST_ADDR]) = htonl(destination_address);
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

void test_virtio_net_ip_header_write_1() {
  void *buf = (uint8 *) kalloc();
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

  virtio_net_ip_header_write(buf, 0xA1, 0x7810, 0x10, 0xC0A8003A, 0xC0A80001);
  assert_memory_equal(expected, buf, IP_HEADER_SIZE, "test_virtio_net_ip_header_write");

  printf("test_virtio_net_ip_header_write: test passed!\n");
}

void test_virtio_net_ip_header_write_2() {
  //FIXME
  panic("void test_virtio_net_ip_header_write_2");
}

void virtio_net_udp_header_write(void *buf, uint16 source_port, uint16 destination_port, uint16 length,
                                 uint16 checksum) {
  uint8 *p = (uint8 *) buf;
  *((uint16 *) &p[UDP_HEADER_OFFSET_SRC_PORT]) = htons(source_port);
  *((uint16 *) &p[UDP_HEADER_OFFSET_DEST_PORT]) = htons(destination_port);
  *((uint16 *) &p[UDP_HEADER_OFFSET_LENGTH]) = htons(length);
  *((uint16 *) &p[UDP_HEADER_OFFSET_CSUM]) = htons(checksum);
}

void test_virtio_net_udp_header_write_1() {
  void *buf = kalloc();
  uint8 expected[] = {0x00, 0x44, // source port
                    0x00, 0x43, // destination port
                    0xEE, 0xFF, // length
                    0xAB, 0xCD  // checksum
  };
  virtio_net_udp_header_write(buf, 0x0044, 0x0043, 0xEEFF, 0xABCD);
  assert_memory_equal(expected, buf, UDP_HEADER_SIZE, "test_virtio_net_udp_header_write_1");

  printf("test_virtio_net_udp_header_write_1 passed!\n");
}

void test_virtio_net_udp_header_write_2() {
  void *buf = kalloc();
  uint8 expected[] = {0xAA, 0xBB, // source port
                    0x12, 0x34, // destination port
                    0x11, 0x22, // length
                    0xCD, 0xDD  // checksum
  };
  virtio_net_udp_header_write(buf, 0xAABB, 0x1234, 0x1122, 0xCDDD);
  assert_memory_equal(expected, buf, UDP_HEADER_SIZE, "test_virtio_net_udp_header_write_2");

  printf("test_virtio_net_udp_header_write_2 passed!\n");
}

void virtio_net_send_dhcp_request() {
  uint8 *dhcp_message = (uint8 *) kalloc();
  const uint8 transaction_id = 1;
  virtio_net_dhcp_message_write(dhcp_message, DHCP_OP_REQUEST, DHCP_HTYPE_ETHERNET, MAC_ADDRESS_LENGTH, 0,
                                transaction_id, 0, 0, 0, 0, 0, 0, network.mac, 6, 0, 0);

  uint8 *ip_message = (uint8 *) kalloc();
  virtio_net_udp_header_write(ip_message, 68, 67, DHCP_MESSAGE_SIZE, 0);
  memmove(ip_message + UDP_HEADER_SIZE, dhcp_message, DHCP_MESSAGE_SIZE);

  uint8 *ethernet_data = (uint8 *) kalloc();
  virtio_net_ip_header_write(ethernet_data, 0, DHCP_MESSAGE_SIZE + UDP_HEADER_SIZE, PROTOCOL_UDP, 0, 0xFFFFFFFF);
  memmove(ethernet_data + IP_HEADER_SIZE, ip_message, UDP_HEADER_SIZE + DHCP_MESSAGE_SIZE);

  virtio_net_send(ethernet_data, IP_HEADER_SIZE + UDP_HEADER_SIZE + DHCP_MESSAGE_SIZE, macBroadcast);
//  uint8* ethernet_frame = (uint8 *) kalloc();
//  virtio_net_make_frame(ethernet_frame, ethernet_data, ip_header_size + UDP_HEADER_SIZE + DHCP_MESSAGE_SIZE, macBroadcast,
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

  test_virtio_net_dhcp_message_write_1();
  test_virtio_net_dhcp_message_write_2();

  test_virtio_net_udp_header_write_1();
  test_virtio_net_udp_header_write_2();

  test_virtio_net_ip_header_write_1();
  test_virtio_net_ip_header_write_2();

  test_virtio_net_ethernet_header_write_1();
  test_virtio_net_ethernet_header_write_2();

  test_virtio_net_ethernet_frame_write_1();
  test_virtio_net_ethernet_frame_write_2();
  test_virtio_net_ethernet_frame_write_3();

  virtio_net_send_dhcp_request();
//  virtio_net_send(0, 0, macBroadcast);

  return 0;
}
