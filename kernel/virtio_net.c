#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "memlayout.h"
#include "spinlock.h"
#include "virtio.h"

#define R1(r) ((volatile uint32 *)(VIRTIO1 + (r)))
//static const uint32 VirtioNetReceiveQ = 0;
static const uint32 VirtioNetTransmitQ = 1;

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
  uint8 mac[6];
  char is_transmit_done[NUM];
  uint16 used_idx;
} network;

struct virtio_net_config {
  uint8 mac[6];
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
  for (int i = 0; i < 6; ++i) {
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
virtio_net_make_frame(void *buf, void *data, uint16 data_len, uint8 *destination_mac, uint8 *source_mac) {
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

  const uint8 addressSize = 6;
  // Destination MAC
  memmove(p, destination_mac, addressSize);
  p += addressSize;

  // Source MAC
  memmove(p, source_mac, addressSize);
  p += addressSize;

  // Len
  *(uint16 *) p = data_len;
  p += sizeof(data_len);

  // Data
  memmove(p, data, data_len);
  p += data_len;

  // Padding
  const uint16 minFrameSize = 64;
  // frame_size = sizes of DestinationAddress, SourceAddress, Len, Data, Pad, Checksum
  uint16 frame_size = data_len + 2 * addressSize + 6;
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
virtio_net_send(void *data, uint16 data_len, uint8 *destination_mac) {
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

void virtio_net_make_dhcp_message(uint8 *buf, uint8 op, uint8 htype, uint8 hlen, uint8 hops, uint32 xid, uint16 secs,
                                  uint16 flags, uint32 ciaddr, uint32 yiaddr, uint32 siaddr, uint32 giaddr,
                                  uint8 *chaddr, char *sname, char *boot_file_name) {
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

  uint8 *p = buf;
  *p = op;
  p += op_size;

  *p = htype;
  p += htype_size;

  *p = hlen;
  p += hlen_size;

  *p = hops;
  p += hops_size;

  *(uint32) p = xid;
  p += xid_size;

  *(uint16) p = secs;
  p += secs_size;

  *(uint16) p = flags;
  p += flags_size;

  *(uint32) p = ciaddr;
  p += ciaddr_size;

  *(uint32) p = yiaddr;
  p += yiaddr_size;

  *(uint32) p = siaddr;
  p += siaddr_size;

  *(uint32) p = giaddr;
  p += giaddr_size;

  for (int i = 0; i < chaddr_size; ++i) {
    *p++ = chaddr[i];
  }

  strncpy((char *) p, sname, sname_size);
  p += sname_size;

  strncpy((char *) p, boot_file_name, file_size);
  p += file_size;
}

void virtio_net_make_ip_header(uint8 *buf, uint8 type_of_service, uint16 data_length, uint8 protocol,
                               uint32 source_address, uint32 destination_address) {
  const uint8 header_length = 5;  // in 32-bit words

  uint8 *p = buf;

  // Version 4 and header length of 5 * 4 = 20 bytes
  *p = 0x40 | header_length;
  ++p;

  // Type of service
  *p++ = 0;

  // Total length
  uint16 total_length = data_length + header_length * 4;
  *(uint16) p = total_length;
  p += sizeof(total_length);

  // Identification - aids in assembling the fragments of a datagram
  *(uint16) p = 0;
  p += sizeof(uint16);

  // Flags and Fragment offset
  *(uint16) p = 0;
  p += sizeof(uint16);

  // Time to live
  *p = 128;
  ++p;

  // Protocol
  *p = protocol;
  p += sizeof(protocol);

  // Checksum (disabled)
  *(uint16) p = 0;
  p += sizeof(uint16);

  *(uint32) p = source_address;
  p += sizeof(source_address);

  *(uint32) p = destination_address;
  p += sizeof(destination_address);
}

void virtio_net_make_udp_header(uint8 *buf, uint16 source_port, uint16 destination_port, uint16 length,
                                uint16 checksum) {
  uint8* p = buf;
  *(uint16) p = source_port;
  p += sizeof(source_port);

  *(uint16) p = destination_port;
  p += sizeof(destination_port);

  *(uint16) p = length;
  p += sizeof(length);

  *(uint16) p = checksum;
  p += sizeof(checksum);
}

uint64
sys_test_virtio_net_send(void) {
  uint8 mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  virtio_net_send(0, 0, mac);

  return 0;
}
