#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def SEC("maps") sock_map =
  {
   .type = BPF_MAP_TYPE_SOCKMAP,
   .key_size = sizeof(int),
   .value_size = sizeof(int),
   .max_entries = 2,
  };

struct bpf_map_def SEC("maps") ip_map =
  {
   .type = BPF_MAP_TYPE_HASH,
   .key_size = sizeof(__u64),
   .value_size = sizeof(int),
   .max_entries = 64,
  };

SEC("sk_skb/stream_parser")
int turn_parser(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int turn_verdict(struct __sk_buff *skb) {
  __u64 ip = skb->remote_ip4;
  __u32 port = skb->remote_port;
  __u64 key = (ip << 32) | port;

  int *idx = bpf_map_lookup_elem(&ip_map, &key);
  if (!idx) {
    return SK_DROP;
  }

  return bpf_sk_redirect_map(skb, &sock_map, *idx, 0);
}


