#include "bpf-loader.h"

#include <unistd.h>

#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/version.h>

#include <algorithm>

static char gpl[] = "GPL";

typedef std::map<std::string, int> fd_map;
static fd_map fd_maps;

// massive hack to relocate maps follows

static struct bpf_insn * find_call(struct bpf_insn *ni, int count) {
  for (int i = 0; i < count; ++i) {
    if ((ni[i].code & 0xf0) == 0x80) {
      return &ni[i];
    }
  }

  return nullptr;
}

static int sock_map_inserter(struct bpf_program *prog, int n,
                        struct bpf_insn *insns, int insns_cnt,
                        struct bpf_prog_prep_result *res) {
  struct bpf_insn *ni = static_cast<struct bpf_insn *>(calloc(sizeof(insns), insns_cnt));
  memcpy(ni, insns, sizeof(insns) * insns_cnt);

  for (int i = 0; i < insns_cnt; ++i) {
    if (ni[i].code == (BPF_LD | BPF_IMM | BPF_DW)) {
      struct bpf_insn *call_ni = find_call(&ni[i], insns_cnt - i);
      int fd = 0;

      if (call_ni->imm == BPF_FUNC_map_lookup_elem) {
        fd = fd_maps["ip_map"];
      } else if (call_ni->imm == BPF_FUNC_sk_redirect_map) {
        fd = fd_maps["sock_map"];
      } else {
        continue;
      }

      ni[i].src_reg = BPF_PSEUDO_MAP_FD;
      ni[i].imm = fd;
    }
  }

  res->new_insn_ptr = ni;
  res->new_insn_cnt = insns_cnt;
  res->pfd = nullptr;
  return 0;
}

// massive hack over

static const char *LEVEL[] =
  {
   "WARN",
   "INFO",
   "DEBUG"
  };

static int log(enum libbpf_print_level level, const char *fmt, va_list ap) {
  fprintf(stderr, "[libbpf %s]: ", LEVEL[level]);
  vfprintf(stderr, fmt, ap);
  return 0;
}

bpf_loader::bpf_loader() {
  libbpf_set_print(log);
}

bpf_loader::~bpf_loader() {
  result<void, error> result = unload();
  if (result.is_err()) {
    fprintf(stderr, "unloading error, %d: %s\n", result.error().err(), result.error().msg().c_str());
  }
}

result<void, error> bpf_loader::load(const std::string &obj_file) {
  obj_ = bpf_object__open(obj_file.c_str());

  if (!obj_) {
    return result<void, error>::err(error(-1, "no object"));
  }

  struct bpf_program *p;
  bpf_object__for_each_program(p, obj_) {
    programs_[bpf_program__title(p, false)] = p;
  }

  struct bpf_map *m = nullptr;
  bpf_object__for_each_map(m, obj_) {
    const struct bpf_map_def *map_def = bpf_map__def(m);
    std::string name(bpf_map__name(m));
    maps_[name] = m;

    int fd = bpf_create_map(static_cast<enum bpf_map_type>(map_def->type), map_def->key_size, map_def->value_size, map_def->max_entries, map_def->map_flags);
    if (fd < 0) {
      return result<void, error>::err(error::from_errno());
    }

    fd_maps[name] = fd;
    if (bpf_map__reuse_fd(m, fd) < 0) {
      return result<void, error>::err(error::from_errno());
    }
  }

  bpf_program__set_prep(programs_["sk_skb/stream_verdict"], 1, sock_map_inserter);

  for(auto it = programs_.begin(); it != programs_.end(); ++it) {
    struct bpf_program *p = it->second;
    int r = bpf_program__load(p, gpl, KERNEL_VERSION(4, 4, 0));
    if (r < 0) {
      return result<void, error>::err(error::from_errno());
    }

    fd_maps[it->first] = r;

    std::string title(bpf_program__title(p, false));

    enum bpf_attach_type t = (title == "sk_skb/stream_parser") ? BPF_SK_SKB_STREAM_PARSER : BPF_SK_SKB_STREAM_VERDICT;
    r = bpf_prog_attach(bpf_program__fd(p), fd_maps["sock_map"],
                       t, 0);

    if (r < 0) {
      return result<void, error>::err(error::from_errno());
    }
  }

  return result<void, error>::ok();
}

result<void, error> bpf_loader::unload() {
  bpf_prog_detach(bpf_map__fd(maps_["sock_map"]), BPF_SK_SKB_STREAM_PARSER);
  bpf_prog_detach(bpf_map__fd(maps_["sock_map"]), BPF_SK_SKB_STREAM_VERDICT);

  for (auto it = programs_.begin(); it != programs_.end(); it++) {
    close(bpf_program__fd(it->second));
  }

  for (auto it = maps_.begin(); it != maps_.end(); it++) {
    close(bpf_map__fd(it->second));
  }

  bpf_object__close(obj_);
  return result<void, error>::ok();
}

result<struct bpf_map *, error> bpf_loader::map(const std::string &name) {
  auto it = maps_.find(name);
  if (it == maps_.end()) {
    return result<struct bpf_map *, error>::err(error(-1, "map not found " + name));
  }

  return result<struct bpf_map *, error>::ok(it->second);
}

