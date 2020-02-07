#pragma once

#include <netinet/ip.h>

#include <string>
#include <utility>

#include "common.h"

class server {
 public:
  server(const std::string &hostname, int listen_port, int backlog = 10);
  ~server();

  result<void, error> init();
  result<std::pair<int, struct sockaddr_in>, error> accept();
  result<void, error> close();

 private:
  std::string hostname_;
  int backlog_;
  struct sockaddr_in addr_in_;
  int sock_;
};

