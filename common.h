#pragma once

#include <errno.h>
#include <string.h>

class error {
 public:
  static error from_errno() {
    char buf[128];
    buf[0] = 0;
    ::strerror_r(errno, buf, sizeof(buf));
    return error(errno, buf);
  }

 error(const error &from) :
  err_(from.err_), msg_(from.msg_) {
  }

 error(int err, const std::string &msg) :
  err_(err), msg_(msg) {
  }

 error() : err_(0) {}

  const std::string & msg() const { return msg_; }
  int err() const { return err_; }

 private:
  int err_;
  std::string msg_;
};

template<typename K, typename E> class result {
 public:
 result(bool err, const K &k) : err_(err), k_(k) {}
 result(bool err) : err_(err) {}

  static result<K, E> ok(const K &k) {
    result<K, E> r(false, k);
    return r;
  }

  static result<K, E> err(const E &e) {
    result<K, E> r(true);
    r.e_ = e;
    return r;
  }

  operator bool() const { return !err_; }
  bool is_ok() const { return !err_; }
  bool is_err() const { return err_; }
  const K & value() const { return (k_); }
  const E & error() const { return e_; }

 private:
  bool err_;
  K k_;
  E e_;
};

template<typename E> class result<void, E> {
 public:
  result(bool err) : err_(err) {}

  static result<void, E> ok() {
    result<void, E> r(false);
    return r;
  }

  static result<void, E> err(const E &e) {
    result<void, E> r(true);
    r.e_ = e;
    return r;
  }

  operator bool() const { return !err_; }
  bool is_ok() const { return !err_; }
  bool is_err() const { return err_; }
  void value() const {}
  const E & error() const { return e_; }

 private:
  bool err_;
  E e_;
};

