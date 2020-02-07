#pragma once

#include <arpa/inet.h>

#include <string>

#include <unistd.h>
#include <string.h>

class client {
 public:
 client() : sock_(-1) {}

 client(int sock, const struct sockaddr_in &addr) :
  sock_(sock), addr_(addr) {}
 ~client() {
   if (sock_ != -1) { close(sock_); }
  }

 client(const client &from) = delete;
 client & operator =(client &from) = delete;

 std::string hostname() const {
   char buf[64];
   const char *out = inet_ntop(addr_.sin_family, &addr_.sin_addr, buf, sizeof(buf));

   if (out == nullptr) {
     return std::string(strerror(errno));
   }

   return std::string(out);
 }

 int port() const {
   return ntohs(addr_.sin_port);
 }

  uint32_t ip() const {
    return ntohl(addr_.sin_addr.s_addr);
  }

 int fd() const {
   return sock_;
 }

 private:
  int sock_;
  struct sockaddr_in addr_;
};
