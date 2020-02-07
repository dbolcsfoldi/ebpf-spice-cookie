#pragma once

#include <bpf/bpf.h>

#include <string>
#include <map>

#include "common.h"

class bpf_loader {
 public:
  bpf_loader();
  ~bpf_loader();

  result<void, error> load(const std::string &obj_file);
  result<void, error> unload();
  result<struct bpf_map *, error> map(const std::string &name);

private:
  struct bpf_object *obj_;
  std::map<std::string, struct bpf_map *> maps_;
  std::map<std::string, struct bpf_program *> programs_;
};

