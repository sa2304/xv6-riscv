#include "kernel/types.h"
#include "user.h"

static int isdigit(char c) {
  return ('0' == c)
      || ('1' == c)
      || ('2' == c)
      || ('3' == c)
      || ('4' == c)
      || ('5' == c)
      || ('6' == c)
      || ('7' == c)
      || ('8' == c)
      || ('9' == c);
}
// a.b.c.d
int parseIpAddress(const char *s) {
  int result = 0;
  for (int i = 0; i < 4; ++i) {
    if (0 < i) {
      if (*s != '.') return 0;
      ++s;
    }

    int octet = atoi(s);
    while (isdigit(*s)) { ++s; }
    result = (result << 8) | octet;
  }

  return result;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: ping <ip as uint32>\n");
    return -1;
  }
  int ip = parseIpAddress(argv[1]);
  printf("[user] ping %s\n", argv[1]);
  ping(ip);
  printf("Done\n");

  return 0;
}