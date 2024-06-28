#include "kernel/types.h"
#include "user.h"

int main(int argc, char** argv) {
  dhcp_request();
  printf("Done\n");

  return 0;
}