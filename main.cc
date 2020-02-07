#include <poll.h>
#include <stdint.h>

#include <bpf/libbpf.h>

#include "server.h"
#include "client.h"
#include "bpf-loader.h"

static int add_ip(struct bpf_map *ip_map, struct bpf_map *sock_map, const client &from, int idx, const client &to) {
  uint64_t key = (static_cast<uint64_t>(htonl(from.ip())) << 32) | htonl(from.port());

  if (bpf_map_update_elem(bpf_map__fd(ip_map), &key, &idx, BPF_ANY) != 0) {
    fprintf(stderr, "%d: %s\n", errno, strerror(errno));
    return -1;
  }

  int fd = to.fd();
  if (bpf_map_update_elem(bpf_map__fd(sock_map), &idx, &fd, BPF_ANY) != 0) {
    fprintf(stderr, "%d: %s\n", errno, strerror(errno));
    return -1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  bpf_loader b;
  auto r3 = b.load(argv[1]);

  if (r3.is_err()) {
    fprintf(stderr, "%d: %s\n", r3.error().err(), r3.error().msg().c_str());
    return -1;
  }

  auto r4 = b.map("sock_map");
  if (r4.is_err()) {
    fprintf(stderr, "%d: %s\n", r4.error().err(), r4.error().msg().c_str());
    return -1;
  }

  struct bpf_map *sock_map = r4.value();

  r4 = b.map("ip_map");
  if (r4.is_err()) {
    fprintf(stderr, "%d: %s\n", r4.error().err(), r4.error().msg().c_str());
    return -1;
  }

  struct bpf_map *ip_map = r4.value();

  server s("localhost", 8080);
  auto r = s.init();

  if (r.is_err()) {
    fprintf(stderr, "%d: %s\n", r.error().err(), r.error().msg().c_str());
    return -1;
  }

  auto r2 = s.accept();
  if (r2.is_err()) {
    fprintf(stderr, "%d: %s\n", r2.error().err(), r2.error().msg().c_str());
    return -1;
  }

  client c1(r2.value().first, r2.value().second);
  fprintf(stdout, "%s connected on %d (%d)\n", c1.hostname().c_str(), c1.port(), c1.fd());

  r2 = s.accept();
  if (r2.is_err()) {
    fprintf(stderr, "%d: %s\n", r2.error().err(), r2.error().msg().c_str());
    return -1;
  }

  client c2(r2.value().first, r2.value().second);
  fprintf(stdout, "%s connected on %d (%d)\n", c2.hostname().c_str(), c2.port(), c2.fd());

  add_ip(ip_map, sock_map, c1, 0, c2);
  add_ip(ip_map, sock_map, c2, 1, c1);

  struct pollfd fds[2] =
    {
     { .fd = c1.fd(), .events = POLLRDHUP },
     { .fd = c2.fd(), .events = POLLRDHUP },
    };

  poll(fds, sizeof(fds) / sizeof(fds[0]), -1);

  fprintf(stdout, "we are done!\n");
  // wait for the magic!
  return 0;
}

