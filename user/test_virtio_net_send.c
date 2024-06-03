#include "kernel/types.h"
#include "user.h"

int main(int argc, char** argv) {
  test_virtio_net_send();
  printf("Done\n");

  return 0;
}