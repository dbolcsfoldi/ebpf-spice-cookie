#include <poll.h>
#include <stdint.h>

#include <bcc/BPF.h>

#include "server.h"
#include "client.h"

const std::string BPF_PROG = R"(
    #include <uapi/linux/bpf.h>
    #include <uapi/linux/if_ether.h>
    #include <uapi/linux/if_packet.h>
    #include <uapi/linux/ip.h>

    BPF_SOCKMAP(sock_map, 2);
    BPF_HASH(ip_map, u64, int, 64);

    int prog_parser(struct __sk_buff *skb)
    {
      return skb->len;
    }

    int prog_verdict(struct __sk_buff *skb) {
      __u64 ip = skb->remote_ip4;
      __u32 port = skb->remote_port;
      __u64 key = (ip << 32) | port;

      int *idx = ip_map.lookup(&key);
      if (!idx) {
        return SK_DROP;
      }

      return sock_map.sk_redirect_map(skb, *idx, 0);
    }
)";

static int add_ip(ebpf::BPFHashTable<uint64_t, int> &ip_map, ebpf::BPFSockmapTable &sock_map, const client &from, int idx, const client &to) {
  uint64_t key = (static_cast<uint64_t>(htonl(from.ip())) << 32) | htonl(from.port());

  ebpf::StatusTuple status = ip_map.update_value(key, idx);

  if (status.code() != 0) {
    fprintf(stderr, "%d: %s\n", status.code(), status.msg().c_str());
    return -1;
  }

  int fd = to.fd();
  status = sock_map.update_value(idx, fd);

  if (status.code() != 0) {
    fprintf(stderr, "%d: %s\n", status.code(), status.msg().c_str());
    return -1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  ebpf::BPF bpf;
  ebpf::StatusTuple status = bpf.init(BPF_PROG);

  if (status.code()) {
    fprintf(stderr, "%d: %s\n", status.code(), status.msg().c_str());
    return -1;
  }

  ebpf::BPFSockmapTable sock_map = bpf.get_sockmap_table("sock_map");
  ebpf::BPFHashTable<uint64_t, int> ip_map = bpf.get_hash_table<uint64_t, int>("ip_map");

  int parser_fd;
  status = bpf.attach_fd("prog_parser", BPF_PROG_TYPE_SK_SKB, parser_fd, BPF_SK_SKB_STREAM_PARSER, sock_map.get_fd());
  if (status.code() != 0) {
    fprintf(stderr, "%d: %s\n", status.code(), status.msg().c_str());
    return -1;
  }

  int verdict_fd;
  status = bpf.attach_fd("prog_verdict", BPF_PROG_TYPE_SK_SKB, verdict_fd, BPF_SK_SKB_STREAM_VERDICT, sock_map.get_fd());

  if (status.code() != 0) {
    fprintf(stderr, "%d: %s\n", status.code(), status.msg().c_str());
    return -1;
  }

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

