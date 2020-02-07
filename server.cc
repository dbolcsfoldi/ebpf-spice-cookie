#include "server.h"

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>

server::server(const std::string &hostname, int listen_port, int backlog) :
  hostname_(hostname), backlog_(backlog)
{
  addr_in_.sin_family = AF_INET;
  addr_in_.sin_port = htons(listen_port);
}

server::~server() {
  close();
}

result<void, error> server::init() {
  int r = inet_pton(AF_INET, hostname_.c_str(), &addr_in_.sin_addr.s_addr);

  if (r == 0) {
    addr_in_.sin_addr.s_addr = INADDR_ANY;
  } else if (r == -1) {
    return result<void, error>::err(error::from_errno());
  }

  sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sock_ < 0) {
    return result<void, error>::err(error::from_errno());
  }

  const int ONE = 1;
  if (setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE)) != 0) {
    return result<void, error>::err(error::from_errno());
  }

  if (bind(sock_, reinterpret_cast<struct sockaddr *>(&addr_in_), sizeof(addr_in_)) != 0) {
    return result<void, error>::err(error::from_errno());
  }

  if (listen(sock_, backlog_) != 0) {
    return result<void, error>::err(error::from_errno());
  }

  return result<void, error>::ok();
}

result<std::pair<int, struct sockaddr_in>, error> server::accept() {
  struct sockaddr_in in;
  socklen_t sz = sizeof(in);

  int s = ::accept(sock_, reinterpret_cast<struct sockaddr *>(&in), &sz);
  if (s < 0) {
    return result<std::pair<int, struct sockaddr_in>, error>::err(error::from_errno());
  }

  return result<std::pair<int, struct sockaddr_in>, error>::ok(std::make_pair(s, in));
}

result<void, error> server::close() {
  if (::close(sock_) != 0) {
    return result<void, error>::err(error::from_errno());
  }

  return result<void, error>::ok();
}




