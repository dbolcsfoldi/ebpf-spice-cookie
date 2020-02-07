# Example of using sockmap eBPF programs

Very simple proof of concept on how to using sockmaps with eBPF. There are lots of these little snippets around but this piece of code relies on libbpf to do the relocations, loading etc. so it should be a bit more straight forward to apply in "real" use cases.

# To build

cmake .
./build.sh

You might need to add libbpf to your pkg-config path as well, e.g. `export PKG_CONFIG_PATH="/usr/lib64/pkgconfig"`

# To run

sudo LD_LIBRARY_PATH=<location of libbpf> ./ebpf-user ebpf-kern.o

and then connect to the 'server' using nc or similar to send data back and forth between the two clients fully 'routed' in the kernel. Useless and yet so delightful. For example:

`nc -4 -p 32769 127.0.0.1 8080`
`nc -4 -p 32768 127.0.0.1 8080`

and type away with the realtime, in-kernel data passover amaze your friends and confuse your enemies.

# To end

Simply exit one of the client using Ctrl^C
