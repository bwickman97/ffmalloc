# ffmalloc
ffmalloc is an experimental memory allocator designed to make "use-after-free" memory errors in C programs unexploitable. It is a "one time allocator" where any given virtual memory address is only returned to the calling application once. Since exploitation of use-after-free errors relies on being able to modify memory associated with "dangling pointers," by not reusing a virtual address region in subsequent allocation, an adversary cannot negatively impact the dangling memory region.

While one-time-allocation presents challenges in terms of speed, memory overhead, and memory fragmentation, ffmalloc shows that these issues can be successfully managed in many real world scenarios. You can read our paper "Preventing Use-After-Free Attacks with Fast Forward Allocation" available at https://www.usenix.org/conference/usenixsecurity21/presentation/wickman.

## Compilation
Compiling with make all will produce multiple libraries. To use ffmalloc as a drop-in replacement for glibc's implementation of malloc link to either libffmallocmt.so to include support for pthreads or libffmallocst.so if your application is single threaded.
