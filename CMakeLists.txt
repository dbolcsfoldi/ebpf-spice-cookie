cmake_minimum_required(VERSION 3.13)
project(turn-ebpf C CXX)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBBCC REQUIRED libbcc)

add_executable(ebpf-user bpf-loader.cc server.cc main.cc)
target_link_libraries(ebpf-user ${LIBBPF_LIBRARIES})
target_include_directories(ebpf-user PUBLIC ${LIBBPF_INCLUDE_DIRS})
target_compile_options(ebpf-user PUBLIC ${LIBBPF_CFLAGS_OTHER})

add_executable(ebpf-user-bcc server.cc main-bcc.cc)
target_link_libraries(ebpf-user-bcc ${LIBBCC_LIBRARIES})
target_include_directories(ebpf-user-bcc PUBLIC ${LIBBCC_INCLUDE_DIRS})
target_compile_options(ebpf-user-bcc PUBLIC ${LIBBCC_CFLAGS_OTHER})


