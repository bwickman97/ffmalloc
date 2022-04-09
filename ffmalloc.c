// FFMalloc - an experimental alternative memory allocator
// Unlike conventional allocators, maximizing space efficiency
// is not a design goal. Instead, FFMalloc makes exploiting
// use-after-free bugs in calling applications impossible
// because freed memory is never reused (only released back to
// the operating system when possible). FFMalloc depends on the
// extensive virtual address space available on 64-bit operating
// systems and is unsuitable for a 32-bit OS

#ifdef _WIN64
#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#endif

/*** Compilation control ***/
// If the target application is single threaded then defining
// FFSINGLE_THREADED will remove threading support which slightly
// reduces the library size but also simplifies debugging.
// On Windows, FFSINGLE_THREADED must be defined if FFmalloc is
// compiled as a static library. Thread safety is only supported when
// compiled as a DLL
#if defined(_WIN64) && !defined(_WINDLL)
#define FFSINGLE_THREADED
#endif

// To include statistics collection in the library, define
// FF_PROFILE. There is a small size and time cost to doing so
//#define FF_PROFILE

// On x86_64 allocation alignment is usually 16-byte. However, this is only
// required to support certain SSE instructions. If those are not used then
// alignment can be 8-byte and therefore more efficient. Pointers don't seem
// to ever require 16-byte allignment and so 8-byte alignment will always be 
// used for allocations of 8 bytes or less. This is backed up in practice by
// TCMalloc. To enable 8-byte alignment, define FF_EIGHTBYTEALIGN during
// library compilation
//#define FF_EIGHTBYTEALIGN

/*** Headers ***/
#include "ffmalloc.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN64
#ifdef FF_PROFILE
#include <Psapi.h>
#endif
#else
#include <unistd.h>
#include <sys/mman.h>
#include <limits.h>
#include <errno.h>

#ifndef FFSINGLE_THREADED
#include <sched.h>
#include <pthread.h>
#endif
#ifdef FF_PROFILE
#include <sys/time.h>
#include <sys/resource.h>
#endif

// Caution - defining this symbol allows cross compilation on older Linuxes
// however running on those kernels risks ffmalloc overwriting other
// memory allocations. ffmalloc is only intended for Linux kernel 4.17 or later
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE    0x100000
#endif
#endif

// MAP_POPULATE is Linux-specific.
#ifndef MAP_POPULATE
#define MAP_POPULATE 0
#endif

typedef unsigned char byte;

/*** Library Constants ***/
// GCC and Visual C++ disagree on how many bits "long" is. Define
// key constants to make sure bitwise operations aren't truncated
#define ONE64        UINT64_C(1)
#define TWO64        UINT64_C(2)
#define THREE64      UINT64_C(3)
#define FOUR64       UINT64_C(4)
#define SEVEN64      UINT64_C(7)
#define EIGHT64      UINT64_C(8)
#define FIFTEEN64    UINT64_C(15)
#define SIXTYTHREE64 UINT64_C(63)

// The maximum size of a single memory pool. Must be a power of
// two greater than or equal to either 1MB or the size of a page if
// large (2MB or 1GB) pages are used instead of 4KB
#define POOL_SIZE_BITS 22
#define POOL_SIZE (ONE64 << POOL_SIZE_BITS)

// The size of a single page of memory from the OS
#define PAGE_SIZE UINT64_C(4096)

// Half of an OS memory page
#define HALF_PAGE UINT64_C(2048)

// The number of pages to assign from a pool to a thread cache
// when a thread cache is out of free pages. Must be an integral
// divisor of (POOL_SIZE / PAGE_SIZE)
#define PAGES_PER_REFILL 128

// The minimum number of consecutive pages ready to return to the
// OS required before calling munmap/VirtualFree. Higher values
// help mitigate against VMA growth on Linux and reduce expensive
// system calls on either OS at the cost of holding onto unneeded
// pages longer than strictly necessary.
#define MIN_PAGES_TO_FREE 8

// The maximum number of arenas allowed to exist at the same time
#define MAX_ARENAS 256

// The maximum number of large allocation pool lists allowed per
// arena regardless of processor count
#define MAX_LARGE_LISTS 8

// The maximum number of large allocation pools per each arena per
// CPU list. In other words, each arena including the default will
// have at most MAX_LARGE_LISTS * MAX_POOLS_PER_LIST large pools in
// use at any one time
#define MAX_POOLS_PER_LIST 3

// The number of bits matched at the root level of
// the page pool radix tree. Current x86_64 hardware supports only
// 48-bits in a pointer. Assuming POOL_SIZE is kept at its default
// value of 4MB then 26 bits total need to be tracked.
// Depending on build and processor, Windows might only supports 44-bit
// pointers, but go ahead and pretend it will always use 48 too
#define ROOT_BITS 8
#define STEM_COUNT (ONE64 << ROOT_BITS)

// The number of bits matched at the intermediate level of the page pool
// radix tree
#define STEM_BITS 8
#define LEAVES_PER_STEM (ONE64 << STEM_BITS)

// The number of bits matched at the leaf level of the page pool radix tree
#define LEAF_BITS (48 - ROOT_BITS - STEM_BITS - POOL_SIZE_BITS)
#define POOLS_PER_LEAF (ONE64 << LEAF_BITS)

#ifdef FFSINGLE_THREADED
// For a single threaded process, making lots of small allocations
// from the page pool to the one-and-only thread cache is pointless
#undef PAGES_PER_REFILL
#define PAGES_PER_REFILL (POOL_SIZE / PAGE_SIZE) 

// When single threaded, having multiple parallel large pool lists has
// no advantage and wastes resources
#undef MAX_LARGE_LISTS
#define MAX_LARGE_LISTS 1
#endif

/*** Compiler compatibility ***/
#ifdef _WIN64
#define __attrUnusedParam
#else
// Disable warning about unused size parameter in non-profiling mode
#define __attrUnusedParam __attribute__((unused))
#endif

/*** Alignment control constants and macros ***/

#ifdef FF_EIGHTBYTEALIGN
// Defines the minimum alignment
#define MIN_ALIGNMENT 8

// The number of small allocation bins in a thread cache when using 8-byte 
// alignment
#define BIN_COUNT 45

// Used by init_tcache to indicate the inflection point between evenly spaced
// bins and bins spaced by maximum packing
#define BIN_INFLECTION 19

// Rounds requested allocation size up to the next multiple of 8
#define ALIGN_SIZE(SIZE) ((SIZE + SEVEN64) & ~SEVEN64)

// Select the bin to allocate from based on the size. Below 208 bytes, bins are 
// every 8 bytes. Above 208, bins are unevenly spaced based on the maximal size
// that divides into PAGE_SIZE for a given number of slots then rounded down to 
// the nearest multiple of 8
#define GET_BIN(SIZE) (SIZE <= 208 ? BIN_COUNT - (SIZE >> 3) : PAGE_SIZE / SIZE)

#else
// Defines the minimum alignment
#define MIN_ALIGNMENT 16

// The number of small allocation bins in a thread cache when using 16-byte
// alignment
#define BIN_COUNT 32

// Used by init_tcache to indicate the inflection point between evenly spaced
// bins and bins spaced by maximum packing
#define BIN_INFLECTION 13

// Rounds requested allocation size up to the next multiple of 16
#define ALIGN_SIZE(SIZE) (SIZE <= 8 ? 8 : ((SIZE + FIFTEEN64) & ~FIFTEEN64))

// Select the bin to allocate from based on the size. Allocations smaller than
// eight bytes always come from the eight byte bin. Otherwise, below 304 bytes,
// bins are every 16 bytes. Above 304, bins are unevenly spaced based on the 
// maximal size that divides into PAGE_SIZE for a given number of slots then 
// rounded down to the nearest multiple of 16
#define GET_BIN(SIZE) (SIZE <= 8 ? 0 : SIZE <= 304 ? BIN_COUNT - (SIZE >> 4) : PAGE_SIZE / SIZE)
#endif

#define ALIGN_TO(VALUE, ALIGNMENT) ((VALUE + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))


/*** OS Intrinsic Translation Macros ***/

#ifdef _WIN64
// Counts the number of 1s in an integer. Useful for checking if an integer is
// a power of two
#define FFPOPCOUNT64 _mm_popcnt_u64

// Counts the number of leading (most significant) zeros in a 64-bit integer.
// Used to round up sizes to a power of two
#define FFCOUNTLEADINGZEROS64 __lzcnt64
#else
#define FFPOPCOUNT64 __builtin_popcountl
#define FFCOUNTLEADINGZEROS64 __builtin_clzl
#endif


/*** OS Threading Translation Macros ***/

// These macros substitute in the correct OS specific synchronization
// functions. Or when the library is being compiled for single threading,
// the macros disable the synchronization calls entirely eliminating the
// need for repetative #ifdefs
#ifdef FFSINGLE_THREADED
// When single threaded on any OS, null out all synchronization calls
#define FFEnterCriticalSection(LOCK)
#define FFLeaveCriticalSection(LOCK)
#define FFTryEnterCriticalSection(LOCK) 1
#define FFInitializeCriticalSection(LOCK)
#define FFDeleteCriticalSection(LOCK)

// Atomic operations redefined as basic C statements
#define FFAtomicAnd(DEST, VALUE)                DEST &= VALUE
#define FFAtomicOr(DEST, VALUE)                 DEST |= VALUE
#define FFAtomicAdd(DEST, VALUE)                DEST += VALUE
#define FFAtomicSub(DEST, VALUE)                DEST -= VALUE
#define FFAtomicIncrement(DEST)                 DEST++
#define FFAtomicExchangeAdvancePtr(DEST, VALUE) DEST; DEST += VALUE
#define FFAtomicCompareExchangePtr(DEST, NEW, OLD) (*DEST = *DEST == OLD ? NEW : *DEST) == NEW

// "Thread" local storage functions
#define FFTlsAlloc(INDEX, FUNC) get_free_arena_index(&INDEX)
#define FFTlsFree(INDEX) free_arena_index(INDEX)
#define TLS_CLEANUP_CALLBACK NULL

// Swallow the lock variable declaration
#define FFLOCK(NAME)
#define FFLOCKSTATIC(NAME)

// "Thread" local storage key type
#define FFTLSINDEX size_t

// No threads so no need for volatile variables
#define volatile

#elif defined(_WIN64)
// Synchronization functions on Windows
#define FFEnterCriticalSection(LOCK)      EnterCriticalSection(LOCK)
#define FFLeaveCriticalSection(LOCK)      LeaveCriticalSection(LOCK)
#define FFTryEnterCriticalSection(LOCK)   TryEnterCriticalSection(LOCK)
#define FFInitializeCriticalSection(LOCK) InitializeCriticalSection(LOCK)
#define FFDeleteCriticalSection(LOCK)     DeleteCriticalSection(LOCK)

// Atomic operations
#define FFAtomicAnd(DEST, VALUE)                   InterlockedAnd64(&DEST, VALUE)
#define FFAtomicOr(DEST, VALUE)                    InterlockedOr64(&DEST, VALUE)
#define FFAtomicAdd(DEST, VALUE)                   InterlockedAdd64(&DEST, VALUE)
#define FFAtomicSub(DEST, VALUE)                   InterlockedAdd64(&(LONG64)DEST, -(LONG64)(VALUE))
#define FFAtomicIncrement(DEST)                    InterlockedIncrement64(&DEST);
#define FFAtomicExchangeAdvancePtr(DEST, VALUE)    InterlockedExchangeAdd64(&(uintptr_t)DEST, VALUE)
#define FFAtomicCompareExchangePtr(DEST, NEW, OLD) (InterlockedCompareExchangePointer(DEST, NEW, OLD) == OLD)

// Thread local storage functions
#define FFTlsAlloc(INDEX, FUNC) ((INDEX = TlsAlloc()) != TLS_OUT_OF_INDEXES)
#define FFTlsFree(INDEX) TlsFree(INDEX)
#define TLS_CLEANUP_CALLBACK NULL

// Synchronization types
#define FFLOCK(NAME)       CRITICAL_SECTION NAME;
#define FFLOCKSTATIC(NAME) static CRITICAL_SECTION NAME;

// Thread local storage key type
#define FFTLSINDEX DWORD 

#else
// Synchronization functions on Linux
#define FFEnterCriticalSection(LOCK)      pthread_mutex_lock(LOCK)
#define FFLeaveCriticalSection(LOCK)      pthread_mutex_unlock(LOCK)
#define FFTryEnterCriticalSection(LOCK)   (pthread_mutex_trylock(LOCK) == 0)
#define FFInitializeCriticalSection(LOCK) pthread_mutex_init(LOCK, NULL)
#define FFDeleteCriticalSection(LOCK)     pthread_mutex_destroy(LOCK)

// Atomic Operations
#define FFAtomicAnd(DEST, VALUE)                   __sync_and_and_fetch(&DEST, VALUE)
#define FFAtomicOr(DEST, VALUE)                    __sync_or_and_fetch(&DEST, VALUE)
#define FFAtomicAdd(DEST, VALUE)                   __sync_add_and_fetch(&DEST, VALUE)
#define FFAtomicSub(DEST, VALUE)                   __sync_sub_and_fetch(&DEST, VALUE)
#define FFAtomicIncrement(DEST)                    __sync_add_and_fetch(&DEST, 1)
#define FFAtomicExchangeAdvancePtr(DEST, VALUE)    __sync_fetch_and_add(&(DEST), (byte*)VALUE)
#define FFAtomicCompareExchangePtr(DEST, NEW, OLD) __sync_bool_compare_and_swap(DEST, OLD, NEW)

// Thread local storage functions
#define FFTlsAlloc(INDEX, FUNC) (pthread_key_create(&INDEX, FUNC) == 0)
#define FFTlsFree(INDEX) pthread_key_delete(INDEX)
#define TLS_CLEANUP_CALLBACK cleanup_thread

// Synchronization types
#define FFLOCK(NAME)       pthread_mutex_t NAME;
#define FFLOCKSTATIC(NAME) static pthread_mutex_t NAME;

// Thread local storage key type
#define FFTLSINDEX pthread_key_t
#endif

/*** Metadata Structures ***/

// When a page allocates objects smaller than 64 bytes, interpret the
// bitmap field in the page map as a pointer to an array of bitmaps. 
// Otherwise, the field is the bitmap
union bitmap_t {
	uint64_t single;
	uint64_t* array;
};

// A page map holds the metadata about a page that has been
// allocated from a small allocation page pool
struct pagemap_t {
	// The starting address of the page. Guaranteed to be page aligned
	byte* start;

	// The size of allocations on this page; always a multiple of 8
	size_t allocSize;

	// Individual allocations on the page are tracked by setting
	// or clearing the corresponding bit in the bitmap
	union bitmap_t bitmap;
};

// Interprets the metadata allocation for a pool as either and array
// of page maps (small allocation pools) or an array of pointers to
// the allocations (large allocation pools)
union tracking_t {
	struct pagemap_t* pageMaps;
	uintptr_t* allocations;
};

// A page pool is an initially contiguous region of memory
// from which individual pages are assigned to the thread
// cache's bins. "Holes" in the pool will develop over time
// when enough allocations have been freed that entire pages
// can be returned to the OS
struct pagepool_t {
	// The starting address of the pool. This value is constant
	// and is not incremented even if the initial page is freed
	byte* start;

	// The final address (exclusive) of the pool
	byte* end;

	// The starting address of the next unallocated page in the pool
	byte* nextFreePage;

	// Pool metadata - either an array of page maps or of allocation pointers
	union tracking_t tracking;

	// The index of the next pointer in a large pool to be allocated.
	// The pointer in this slot is not yet allocated, but it
	// is needed so that the size of the last allocated 
	// pointer can still be computed
	size_t nextFreeIndex;

	// The address of the first page not yet freed
	byte* startInUse;

	// The address of the free page block that is continguous to the end of the pool
	byte* endInUse;

	// The arena this pool is a part of
	struct arena_t* arena;

	// Critical section used to lock certain updates on the pool
	FFLOCK(poolLock)
};

// All small (less than half a page) allocations are assigned to a
// size bin based on maximum packing of similar sizes. All allocations
// on a single page are in the same bin.
struct bin_t {
	// Pointer to the next free slot for allocation
	byte* nextAlloc;

	// The size of allocations in this bin. Always a multiple of 8
	size_t allocSize;

	// The number of allocations made so far in this bin. It is
	// reset to 0 when the page is filled and a new page is
	// assigned to the bin
	size_t allocCount;

	// The maximum number of allocations that can be made on one
	// page in this bin
	size_t maxAlloc;

	// Points to the page map object with the tracking bitmap
	struct pagemap_t* page;

#ifdef FF_PROFILE
	// The cummulative number of allocations made from this bin
	// across all pages
	size_t totalAllocCount;
#endif
};

// Each thread is given its own cache of pages to allocate from
struct threadcache_t {
	// The array of small allocation bins for this thread
	struct bin_t bins[BIN_COUNT];

	// To reduce round trips to the page pool, a small number of
	// blank pages are assigned to the thread cache to add to a 
	// bin when it gets full. This points to the next available
	// free page
	struct pagemap_t* nextUnusedPage;

	// The end address (exclusive) of the range of free pages
	// available to the cache
	struct pagemap_t* endUnusedPage;

	// The arena this thread cache allocates from and the source of
	// its free pages
	struct arena_t* arena;
};

// A leaf node in a radix tree that points to a page pool
struct radixleaf_t {
	// Radix leaf node has two arrays, one for start and one for end.
	// The reason is that we can't assume that each pool allocation
	// will be POOL_SIZE aligned (and in fact for ASLR purposes it's
	// better that they aren't). Therefore, looking only at the high
	// order bits of a pointer, we can't tell if its from a pool that
	// starts in the middle of the prefix or ends there

	// Pointers to pools that start on the matching prefix
	struct pagepool_t* poolStart[POOLS_PER_LEAF];

	// Pointers to pools that end on the matching prefix
	struct pagepool_t* poolEnd[POOLS_PER_LEAF];
};

// Intermediate node in a radix tree
struct radixstem_t {
	struct radixleaf_t* leaves[LEAVES_PER_STEM];
};

// Root node of the page pool radix tree
struct radixroot_t {
	struct radixstem_t* stems[STEM_COUNT];
};

// Node in a list of allocation pools
struct poollistnode_t {
	// Pointer to the next node in the list
	struct poollistnode_t* next;

	// Pointer to an allocation page pool
	struct pagepool_t* pool;
};

// An arena is a collection of large and small pools that allocations can be
// specifically drawn from using the ffmalloc extended API. Arenas allow the
// calling application to free all allocations from that arena with one call
// which benefits performance through fewer system calls to VirtualFree or
// munmap and simplifies memory management since each allocation doesn't have
// to be individually freed. Allocations from the standard malloc API come
// from a default arena, but that arena is persistent and allocations need to
// be individually freed.
struct arena_t {
	// List of small pools created in this arena. The head of the list is
	// the pool currently being allocated from
	struct poollistnode_t* volatile smallPoolList;

	// Array of lists of large pools created in this arena. Typically one
	// list per CPU in the system. The head of the list is usually where
	// allocations come from but pools further down will be searched for
	// available space if the first node is locked by another thread
	struct poollistnode_t* volatile largePoolList[MAX_LARGE_LISTS];

	// List of jumbo allocation pools create in this arena
	struct poollistnode_t* volatile jumboPoolList;

	// Index to get the correct thread local storage value for this arena
	// which holds the pointer to the thread cache for invoking thread
	FFTLSINDEX tlsIndex;

	// Lock that protects modifying the small pool list header
	FFLOCK(smallListLock)

	// Locks that protect each large list
	FFLOCK(largeListLock[MAX_LARGE_LISTS])

#ifdef FF_PROFILE
	// Structure to hold arena usage statistics
	ffprofile_t profile;
#endif
};

// Reinterprets freed metadata allocations as a pointer to the next
// available free block
struct usedmd_t {
	byte* next;
};

/*** Library Globals ***/
static int isInit = 0;

// Number of pools currently allocated
// TODO: move this into future global profiling structure
static size_t poolCount = 0;

// The highest pool end address seen yet. The next pool will attempt
// to start at this address
//static byte* volatile poolHighWater;
static byte* poolHighWater;

// Root node of radix tree containing all pools
static struct radixroot_t poolTree;

// Array of arenas. The default arena used by the standard malloc API is
// at index 0
static struct arena_t* volatile arenas[MAX_ARENAS];

// The start of the global metadata allocation pool
static byte* metadataPool;

// The top of the metadata pool - i.e. the next unallocated block
static byte* metadataFree;

// The end of the currently available metadata address space
static byte* metadataEnd;

// Bin headers for the metadata pool
static byte* bins[256];
static byte* metadatabins[2];

// Lock that protects modifications to the pool radix tree
FFLOCKSTATIC(poolTreeLock)

// Locks that protect access to the metadata allocation bins
FFLOCKSTATIC(binLocks[256])
FFLOCKSTATIC(mdBinLocks[2])

// Lock that protects access to the metadata allocation pool
FFLOCKSTATIC(mdPoolLock)

FFLOCKSTATIC(poolAllocLock);

#ifdef FF_PROFILE
// The interval (in calls to malloc) to print usage statistics
unsigned int usagePrintInterval;

// The file that interval usage statistics will be sent to
FILE * usagePrintFile;
#endif // FF_PROFILE


/*** Forward declarations ***/
static int create_pagepool(struct pagepool_t* newPool);
static int create_largepagepool(struct pagepool_t* newPool);
static void destroy_pool_list(struct poollistnode_t* node);
static struct pagepool_t* find_pool_for_ptr(const byte* ptr);
static void init_tcache(struct threadcache_t* tcache, struct arena_t* arena);
static void initialize();
static void init_threading();
static void* ffmetadata_alloc(size_t size);
static void ffmetadata_free(void* ptr, size_t size);
static void free_large_pointer(struct pagepool_t* pool, size_t index, size_t size);
void ffprint_stats_wrapper(void);

#ifdef FF_PROFILE
static void print_current_usage();
#endif

#if !defined(FFSINGLE_THREADED) && !defined(_WIN64)
static void cleanup_thread(void* ptr);
#endif

/*** OS compatibility functions ***/
static size_t os_alloc_total = 0;
static size_t os_alloc_count = 0;
static size_t os_free_count = 0;
#ifdef _WIN64
#define MAP_FAILED NULL
static inline LPVOID os_alloc(LPVOID startAddress, size_t size) {
	void* alloc = VirtualAlloc(startAddress, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	os_alloc_total += size;
	os_alloc_count++;
	return alloc;
}

// Obtains memory from the OS whose starting virtual address is no lower than
// the previous highest address
static inline LPVOID os_alloc_highwater(size_t size) {
	MEM_ADDRESS_REQUIREMENTS addressReqs = { 0 };
	MEM_EXTENDED_PARAMETER param = { 0 };

	addressReqs.LowestStartingAddress = poolHighWater;

	param.Type = MemExtendedParameterAddressRequirements;
	param.Pointer = &addressReqs;

	LPVOID result = VirtualAlloc2(NULL, NULL, size, MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE, &param, 1);

	if (result != NULL) {
		// Incrementing by extra 64K leaves guard pages in between pools for a weak
		// buffer overflow protection
		byte* newHigh = (byte*)result + size + 65536ULL;
		byte* oldHigh = poolHighWater;
		byte* update;
		os_alloc_total += size;
		os_alloc_count++;
		while ((update = InterlockedCompareExchangePointer(&poolHighWater, newHigh, oldHigh)) < newHigh) {
			oldHigh = update;
		}
	}

	return result;
}

// Returns memory to the OS but holds onto the memory addresses
static inline BOOL os_decommit(LPVOID startAddress, size_t size) {
	return VirtualFree(startAddress, size, MEM_DECOMMIT);
}

// Returns memory to the OS and releases the virutal address space
static inline BOOL os_free(LPVOID startAddress) {
	os_free_count++;
	return VirtualFree(startAddress, 0, MEM_RELEASE);
}

#else

/*static inline void* os_alloc(void* startAddress, size_t size) {
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;
	if(startAddress != NULL) {
		flags |= MAP_FIXED_NOREPLACE | MAP_POPULATE;
	}
	return mmap(startAddress, size, PROT_READ | PROT_WRITE, flags, -1, 0);
}*/

static inline void* os_alloc_highwater(size_t size) {
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
	void* result = NULL;
	void* localHigh = FFAtomicExchangeAdvancePtr(poolHighWater, size);

	// If we need more space from the OS, its likely to get used immediately
	// after, so go ahead and pre-fault the pages for faster access. Except
	// don't do that for jumbo allocations since that could cause swapping if
	// the allocation is sufficiently large and the system is under pressure
	if(size == POOL_SIZE) {
		flags |= MAP_POPULATE;
	}

	while(result == NULL) {
		// TODO: Add wrap around if we hit the top of address space
		result = mmap(localHigh, size, PROT_READ | PROT_WRITE,
				flags, -1, 0);
		if(result == MAP_FAILED) {
			// If the failure was because the requested address already has
			// a mapping associated then jump up by POOL_SIZE (since a new 
			// pool created on another thread is the most likely reason)
			// and try again
			if(errno == EEXIST) {
				localHigh = FFAtomicExchangeAdvancePtr(poolHighWater, POOL_SIZE);
				result = NULL;
			}
			else {
				fprintf(stderr, "[ffmalloc] Warning: os_alloc_highwater failed\n");
				return MAP_FAILED;
			}
		}
	}

	return result;
}

#define FALSE -1
static inline int os_decommit(void* startAddress, size_t size) {
	// Surprisingly, benchmarking seems to suggest that unmapping is actually
	// faster than madvise. Revisit in the future
	return munmap(startAddress, size);
	//return madvise(startAddress, size, MADV_FREE);
}

static inline int os_free(void* startAddress) {
	// On Windows, this helper can only completely decommit and unreserve
	// an entire reservation, so no size parameter. Here, we'll look for
	// the pool getting the axe and figure out the size
	struct pagepool_t* pool = find_pool_for_ptr((const byte*)startAddress);
	if (pool != NULL) {
		return munmap(pool->start, pool->end - pool->start);
	}
	else {
		// Wasn't a pool - that shouldn't happen
		// Likely a bug if we get here
		abort();
	}

	errno = EINVAL;
	return -1; 
}
#endif


/*** Dynamic metadata allocation ***/
// FFmalloc has several metadata structures that need to be dynamically allocated
// If we restricted usage to Windows or requiring use of the ff prefix on Linux
// then LocalAlloc or libc malloc respectively could be used. But, we'd like to 
// allow non-prefixed usage via LD_PRELOAD on Linux (or static compilation so long
// as we're the first library). Therefore, we have a mini-allocator for metadata
// allocations. Because this should only be used internally, it does *not*
// implement the forward-only principal. Also note that the "free" equivalent
// requires a size parameter. This simplifies the amount of metadata for the 
// metadata stored

static void* ffpoolmetadata_alloc(int isSmallPool) {
	byte* allocation;
	size_t size = isSmallPool ? (POOL_SIZE / PAGE_SIZE) * sizeof(struct pagemap_t) : 
		(POOL_SIZE >> 20) * PAGE_SIZE;
	size = ALIGN_SIZE(size);

	FFEnterCriticalSection(&mdBinLocks[isSmallPool]);
	if(metadatabins[isSmallPool] == NULL) {
		FFEnterCriticalSection(&mdPoolLock);
		allocation = metadataFree;
		if(allocation + size > metadataEnd) {
			// Need to grow metadata pool space
#ifdef _WIN64
			VirtualAlloc(metadataEnd, POOL_SIZE, MEM_COMMIT, PAGE_READWRITE);
#else
			mprotect(metadataEnd, POOL_SIZE, PROT_READ | PROT_WRITE);
			madvise(metadataEnd, PAGE_SIZE * 16, MADV_WILLNEED);
#endif
			metadataEnd += POOL_SIZE;
#ifdef FF_PROFILE
			FFAtomicAdd(arenas[0]->profile.currentOSBytesMapped, POOL_SIZE);
			if(arenas[0]->profile.currentOSBytesMapped > arenas[0]->profile.maxOSBytesMapped) {
				arenas[0]->profile.maxOSBytesMapped = arenas[0]->profile.currentOSBytesMapped;
			}
#endif
		}
		metadataFree += size;
		FFLeaveCriticalSection(&mdPoolLock);
	}
	else {
		allocation = metadatabins[isSmallPool];
		metadatabins[isSmallPool] = ((struct usedmd_t*)allocation)->next;
	}
	FFLeaveCriticalSection(&mdBinLocks[isSmallPool]);

	memset(allocation, 0, size);
	return allocation;
}

static void ffpoolmetadata_free(void* ptr, int isSmallPool) {
	size_t size = isSmallPool ? (POOL_SIZE / PAGE_SIZE) * sizeof(struct pagemap_t) : 
		(POOL_SIZE >> 20) * PAGE_SIZE;
	size = ALIGN_SIZE(size);

	if (ptr > (void*)metadataFree || ptr < (void*)metadataPool) {
		abort();
	}

	FFEnterCriticalSection(&mdBinLocks[isSmallPool]);

	// Put the freed block at the front of the list and have it point to
	// the former head of the line
	((struct usedmd_t*)ptr)->next = metadatabins[isSmallPool];
	metadatabins[isSmallPool] = (byte*)ptr;

	FFLeaveCriticalSection(&mdBinLocks[isSmallPool]);
}


static void* ffmetadata_alloc(size_t size) {
	// Ensure 16 byte alignment
	size = ALIGN_TO(size, UINT64_C(16));

	// Making the assumption that the radix leaf nodes are the only metadata
	// structures that are bigger than a page. If that changes then we'll be
	// in a bit of a bind here. But for now, go with it
	size_t binID = size >=4096 ? 255 : (size >> 4) - 1;

	byte* allocation;

	FFEnterCriticalSection(&binLocks[binID]);
	if (bins[binID] == NULL) {
		// No freed chunks of this size exist. Allocate space from the top
		// of the pool. Keeping things simple for now and not trying to 
		// break a free 64-byte chunk into 4*16-byte chunks or whatever
		FFEnterCriticalSection(&mdPoolLock);
		allocation = metadataFree;
		if(allocation + size > metadataEnd) {
			// Need to grow metadata pool space
#ifdef _WIN64
			VirtualAlloc(metadataEnd, POOL_SIZE, MEM_COMMIT, PAGE_READWRITE);
#else
			mprotect(metadataEnd, POOL_SIZE, PROT_READ | PROT_WRITE);
			madvise(metadataEnd, PAGE_SIZE * 4, MADV_WILLNEED);
#endif
			metadataEnd += POOL_SIZE;
#ifdef FF_PROFILE
			FFAtomicAdd(arenas[0]->profile.currentOSBytesMapped, POOL_SIZE);
			if(arenas[0]->profile.currentOSBytesMapped > arenas[0]->profile.maxOSBytesMapped) {
				arenas[0]->profile.maxOSBytesMapped = arenas[0]->profile.currentOSBytesMapped;
			}
#endif
		}
		metadataFree += size;
		FFLeaveCriticalSection(&mdPoolLock);
	}
	else {
		// Take the first available chunk from the front of the list
		// and the advance the header to the next chunk
		allocation = bins[binID];
		bins[binID] = ((struct usedmd_t*)allocation)->next;
	}

	FFLeaveCriticalSection(&binLocks[binID]);

	// Simplify logic elsewhere by guaranteeing zeroed blocks
	memset(allocation, 0, size);
	return allocation;
}

static void ffmetadata_free(void* ptr, size_t size) {
	// Ensure 16 byte alignment to find right bin
	size = ALIGN_TO(size, UINT64_C(16));
	size_t binID = size >= 4096 ? 255 : (size >> 4) - 1;

	if (ptr > (void*)metadataFree || ptr < (void*)metadataPool) {
		abort();
	}

	FFEnterCriticalSection(&binLocks[binID]);

	// Put the freed block at the front of the list and have it point to
	// the former head of the line
	((struct usedmd_t*)ptr)->next = bins[binID];
	bins[binID] = (byte*)ptr;

	FFLeaveCriticalSection(&binLocks[binID]);
}


/*** Radix tree implementation ***/

// Gets the page pool that matches the page prefix. Returns NULL if no matching
// pool could be found
struct pagepool_t* find_pool_for_ptr(const byte* ptr) {
	// Compute the index for each level
	size_t stemIndex = (uintptr_t)ptr >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t leafIndex = ((uintptr_t)ptr >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);

	// Find the correct leaf node
	struct radixleaf_t* leaf = poolTree.stems[stemIndex] != NULL ? poolTree.stems[stemIndex]->leaves[leafIndex] : NULL;
	if (leaf != NULL) {
		// Check if there is a pool that starts or ends in this leaf
		// that could possibly contain the given pointer
		struct pagepool_t* pool = leaf->poolStart[((uintptr_t)ptr >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1)];
		if (pool != NULL && ptr >= pool->start) {
			return pool;
		}
		pool = leaf->poolEnd[((uintptr_t)ptr >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1)];
		if (pool != NULL && ptr < pool->end) {
			return pool;
		}
	}

	return NULL;
}

// Inserts a newly created page pool into the radix tree
void add_pool_to_tree(struct pagepool_t* pool) {
	// Compute the level indexes for both the start and end addresses
	size_t startStemIndex = (uintptr_t)pool->start >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t startLeafIndex = ((uintptr_t)pool->start >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);
	size_t startPoolIndex = ((uintptr_t)pool->start >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1);
	size_t endStemIndex = (uintptr_t)pool->end >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t endLeafIndex = ((uintptr_t)pool->end >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);
	size_t endPoolIndex = ((uintptr_t)pool->end >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1);
	
	// Pool creation should be infrequent enough that trying to come up
	// with a fancy lock-free update structure probably isn't worth it
	FFEnterCriticalSection(&poolTreeLock);

	// Make sure that the nodes in the tree exist
	if(poolTree.stems[startStemIndex] == NULL) {
		poolTree.stems[startStemIndex] = (struct radixstem_t*)ffmetadata_alloc(sizeof(struct radixstem_t));
	}
	if(poolTree.stems[startStemIndex]->leaves[startLeafIndex] == NULL) {
		poolTree.stems[startStemIndex]->leaves[startLeafIndex] = (struct radixleaf_t*)ffmetadata_alloc(sizeof(struct radixleaf_t));
	}
	if(poolTree.stems[endStemIndex] == NULL) {
		poolTree.stems[endStemIndex] = (struct radixstem_t*)ffmetadata_alloc(sizeof(struct radixstem_t));
	}
	if(poolTree.stems[endStemIndex]->leaves[endLeafIndex] == NULL) {
		poolTree.stems[endStemIndex]->leaves[endLeafIndex] = (struct radixleaf_t*)ffmetadata_alloc(sizeof(struct radixleaf_t));
	}

	// Add the pool to the tree
	poolTree.stems[startStemIndex]->leaves[startLeafIndex]->poolStart[startPoolIndex] = pool;
	poolTree.stems[endStemIndex]->leaves[endLeafIndex]->poolEnd[endPoolIndex] = pool;

	poolCount++;
	FFLeaveCriticalSection(&poolTreeLock);
}

// Removes a page pool from the lookup tree
void remove_pool_from_tree(struct pagepool_t* pool) {
	// Compute the level indexes for the start and end of the pool
	size_t startStemIndex = (uintptr_t)pool->start >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t startLeafIndex = ((uintptr_t)pool->start >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);
	size_t startPoolIndex = ((uintptr_t)pool->start >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1);
	size_t endStemIndex = (uintptr_t)pool->end >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t endLeafIndex = ((uintptr_t)pool->end >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);
	size_t endPoolIndex = ((uintptr_t)pool->end >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1);

	// Not checking path validity. Caller is responsible for calling only
	// if the pool has definitively been added the tree already
	FFEnterCriticalSection(&poolTreeLock);
	poolTree.stems[startStemIndex]->leaves[startLeafIndex]->poolStart[startPoolIndex] = NULL;
	poolTree.stems[endStemIndex]->leaves[endLeafIndex]->poolEnd[endPoolIndex] = NULL;

	poolCount--;
	FFLeaveCriticalSection(&poolTreeLock);
}


/*** Multi-threaded application support ***/
#ifdef FFSINGLE_THREADED
// Support single threaded applications only

// Array of thread caches, one per arena. Thread caches are still needed even
// when compiled without threading support because they serve as the interface
// for small allocations.
struct threadcache_t* arenaCaches[MAX_ARENAS];

// Single threaded implementation of FFTlsAlloc
static int get_free_arena_index(FFTLSINDEX* index) {
	for(FFTLSINDEX i=0; i<MAX_ARENAS; i++) {
		if(arenaCaches[i] == NULL) {
			arenaCaches[i] = ffmetadata_alloc(sizeof(struct threadcache_t));
			*index = i;
			return 1;
		}
	}

	return 0;
}

// Single threaded implementation of FFTlsFree
static int free_arena_index(FFTLSINDEX index) {
	ffmetadata_free(arenaCaches[index], sizeof(struct threadcache_t));
	arenaCaches[index] = NULL;
	return 0;
}

// One time initialization of the default arena thread cache
static void init_threading() {
	arenaCaches[0] = ffmetadata_alloc(sizeof(struct threadcache_t));
	init_tcache(arenaCaches[0], arenas[0]);
}

// Returns the thread cache for the associated arena
static inline struct threadcache_t* get_threadcache(struct arena_t* arena) {
	if(arenaCaches[arena->tlsIndex]->arena == NULL) {
		init_tcache(arenaCaches[arena->tlsIndex], arena);
	}
	return arenaCaches[arena->tlsIndex];
}

// Returns the index of the large pool list to use - always zero
static unsigned int get_large_list_index() {
	return 0;
}

// End FFSINGLE_THREADED
#else
// Multi-threaded but OS neutral code
// TODO: this should be updated to be null-op for non-default arenas
void destroy_tcache(struct threadcache_t* tcache) {
	if (tcache->nextUnusedPage != NULL && (tcache->nextUnusedPage < tcache->endUnusedPage)) {
		// While it would be better to return unused pages to the pool of origin, that's more
		// complicated than I want to handle right now. So, just give them back to the OS
		os_decommit(tcache->nextUnusedPage->start, (tcache->endUnusedPage - tcache->nextUnusedPage) * PAGE_SIZE);
	}
}
// End OS neutral multi-threaded 
#ifdef _WIN64
// Begin Windows specific multi-threaded support

// Index that retrieves the pointer to the per-thread cache
//static DWORD threadIndex;

static void init_threading() {
	// Nothing to do on Windows. All threading related initialization is handled
	// in DllMain
}

// Windows DLL entry point - handles TLS allocation and cleanup
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	struct threadcache_t* tcache;
	// Pretty much just following the skeleton code here:
	// https://docs.microsoft.com/en-us/windows/desktop/Dlls/using-thread-local-storage-in-a-dynamic-link-library
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// Initialize library and create the default arena
		initialize();

		break;
	case DLL_THREAD_ATTACH:

		break;
	case DLL_THREAD_DETACH:
		// Thread is shutting down. Look for any associated caches
		// to clean up in all active arenas
		for (int i = 0; i < MAX_ARENAS; i++) {
			if(arenas[i] != NULL) {
				tcache = (struct threadcache_t*)TlsGetValue(arenas[i]->tlsIndex);
				if (tcache != NULL) {
					destroy_tcache(tcache);
					ffmetadata_free(tcache, sizeof(struct threadcache_t));
				}
			}
		}
		break;
	case DLL_PROCESS_DETACH:
		// The whole process is being shut down or this library is being unloaded
		// Presents a philosophical question about what to clean up. Should all
		// pages allocated from here be unmapped if they aren't yet freed?

		// At least clean up any TLS
		tcache = (struct threadcache_t*)TlsGetValue(arenas[0]->tlsIndex);
		if (tcache != NULL) {
			destroy_tcache(tcache);
			ffmetadata_free(tcache, sizeof(struct threadcache_t));
		}

		// Give the TLS index back to the OS
		TlsFree(arenas[0]->tlsIndex);
		FFDeleteCriticalSection(&poolTreeLock);
		break;
	}
	return TRUE;
}

// Gets the thread cache associated with the current thread. On the
// first call from a given thread, a new cache is created 
static inline struct threadcache_t* get_threadcache(struct arena_t* arena) {
	struct threadcache_t* tcache = TlsGetValue(arena->tlsIndex);
	if (tcache == NULL) {
		// No thread cache found so create one
		tcache = (struct threadcache_t*)ffmetadata_alloc(sizeof(struct threadcache_t));
		init_tcache(tcache, arena);

		// Save the pointer in the thread local storage
		TlsSetValue(arena->tlsIndex, tcache);
	}

	return tcache;
}

// Returns the index of the large pool list to use based on the active CPU
static inline unsigned int get_large_list_index() {
	return GetCurrentProcessorNumber() % MAX_LARGE_LISTS;
}

// End Windows specific threading
#else
// Start Linux specific threading

// Key that retrieves the pointer to the per-thread cache
//pthread_key_t threadKey;

static __attribute__((constructor)) void linux_mt_init() {
	initialize();
}

// One time initialization of the per-thread local storage
static void init_threading() {
//	pthread_key_create(&threadKey, cleanup_thread);
}

// Thread exit cleanup
static void cleanup_thread(void* ptr) {
	if (ptr != NULL) {
		destroy_tcache((struct threadcache_t*)ptr);
		ffmetadata_free(ptr, sizeof(struct threadcache_t));
	}
}

// Retrieves the specific cache for the currently running thread
static inline struct threadcache_t* get_threadcache(struct arena_t* arena) {
	struct threadcache_t* tcache = (struct threadcache_t*)pthread_getspecific(arena->tlsIndex);
	if (tcache == NULL) {
		// No thread cache found so create one
		tcache = (struct threadcache_t*)ffmetadata_alloc(sizeof(struct threadcache_t));
		init_tcache(tcache, arena);

		// Save the pointer in the thread local storage
		pthread_setspecific(arena->tlsIndex, tcache);
	}

	return tcache;
}

// Returns the index of the large list index to use based on the current CPU
static unsigned int get_large_list_index() {
	int cpuId = sched_getcpu();
	return cpuId < 0 ? 0 : (unsigned int)cpuId % MAX_LARGE_LISTS;
}

// End Linux specific threading
#endif
#endif

/*** Page allocation ***/

// Called when a thread cache is out of pages and needs to be assigned
// more from a pool. The active small pool for the arena is out of pages
// then a new small pool is created
static void assign_pages_to_tcache(struct threadcache_t* tcache) {
	size_t nextFreePageMapIndex;
	byte* nextFreePage;

	// First, select which pool to assign pages from
	struct pagepool_t* pool = tcache->arena->smallPoolList->pool;

	// Advance the free page pointer atomically so that concurrent threads
	// get distinct ranges
	nextFreePage = (byte*)FFAtomicExchangeAdvancePtr(pool->nextFreePage, (PAGES_PER_REFILL * PAGE_SIZE));

	nextFreePageMapIndex = (nextFreePage - pool->start) / PAGE_SIZE;

	// Make sure that the range of pages selected from the pool are
	// actually within the pool. If not, then the pool is full and needs to
	// be retired and a new one created.
	// Counting on PAGES_PER_REFILL to evenly divide POOL_SIZE
	while (nextFreePage + (PAGES_PER_REFILL * PAGE_SIZE) > pool->end) {
		FFEnterCriticalSection(&tcache->arena->smallListLock);
		// Check that while waiting for the lock that the pool wasn't already
		// replaced. If it wasn't, then we can create the new pool
		if (pool == tcache->arena->smallPoolList->pool) {
			struct poollistnode_t* newListHeader = (struct poollistnode_t*)ffmetadata_alloc(sizeof(struct poollistnode_t));
			newListHeader->pool = (struct pagepool_t*)ffmetadata_alloc(sizeof(struct pagepool_t));
			newListHeader->pool->arena = tcache->arena;
			if (create_pagepool(newListHeader->pool) == -1) {
				ffmetadata_free(newListHeader->pool, sizeof(struct pagepool_t));
				ffmetadata_free(newListHeader, sizeof(struct poollistnode_t));
				// TODO: handle failure more gracefully
				abort();
			}
			add_pool_to_tree(newListHeader->pool);
			newListHeader->next = tcache->arena->smallPoolList;
			tcache->arena->smallPoolList = newListHeader;
		}
		pool = tcache->arena->smallPoolList->pool;
		FFLeaveCriticalSection(&tcache->arena->smallListLock);

		nextFreePage = (byte*)FFAtomicExchangeAdvancePtr(pool->nextFreePage, (PAGES_PER_REFILL * PAGE_SIZE));
		nextFreePageMapIndex = (nextFreePage - pool->start) / PAGE_SIZE;
	}

	// Create new page maps
	for (size_t i = 0; i < PAGES_PER_REFILL; i++) {
		pool->tracking.pageMaps[nextFreePageMapIndex + i].start = nextFreePage + (i * PAGE_SIZE);
	}

	// Assign the new page maps to the thread cache
	tcache->nextUnusedPage = pool->tracking.pageMaps + nextFreePageMapIndex;
	tcache->endUnusedPage = tcache->nextUnusedPage + PAGES_PER_REFILL;
}

/*** Initialization functions ***/

// Creates a new arena. Applications do not call this directly but rather
// through the public ffcreate_arena function
static ffresult_t create_arena(struct arena_t* newArena) {
	if(newArena == NULL) {
		return FFBAD_PARAM;
	}

	// Each arena has a unique TLS index that allows the correct arena
	// specific thread cache to be retrieved. Each OS has a unique
	// initialization required before use
	if(!FFTlsAlloc(newArena->tlsIndex, TLS_CLEANUP_CALLBACK)) {
		ffmetadata_free(newArena, sizeof(struct arena_t));
		return FFSYS_LIMIT;
	}		

	// Create the small pool list header
	newArena->smallPoolList = (struct poollistnode_t*)ffmetadata_alloc(sizeof(struct poollistnode_t));
	if(newArena->smallPoolList == NULL) {
		ffmetadata_free(newArena, sizeof(struct arena_t));
		return FFSYS_LIMIT;
	}

	// Create the first small pool and put it in the header node
	newArena->smallPoolList->pool = (struct pagepool_t*)ffmetadata_alloc(sizeof(struct pagepool_t));
	if(newArena->smallPoolList->pool == NULL) {
		ffmetadata_free(newArena->smallPoolList, sizeof(struct poollistnode_t));
		ffmetadata_free(newArena, sizeof(struct arena_t));
		return FFSYS_LIMIT;
	}

	// Initialize the first small pool
	newArena->smallPoolList->pool->arena = newArena;
	if(create_pagepool(newArena->smallPoolList->pool) != 0) {
		ffmetadata_free(newArena->smallPoolList->pool, sizeof(struct pagepool_t));
		ffmetadata_free(newArena->smallPoolList, sizeof(struct poollistnode_t));
		ffmetadata_free(newArena, sizeof(struct arena_t));
		return FFNOMEM;
	}
	add_pool_to_tree(newArena->smallPoolList->pool);

	// Initialize the lock that protects the small list header
	FFInitializeCriticalSection(&newArena->smallListLock);

	// Create the large pool lists
	// TODO: limit to lesser of MAX_LARGE_LISTS and actual CPU count
	for (int i = 0; i < MAX_LARGE_LISTS; i++) {
		struct pagepool_t* pool = (struct pagepool_t*)ffmetadata_alloc(sizeof(struct pagepool_t));
		pool->arena = newArena;
		if (pool == NULL || create_largepagepool(pool) == -1) {
			destroy_pool_list(newArena->smallPoolList);
			// TODO: deconstruct any 
			// successfully created large pools
			ffmetadata_free(newArena, sizeof(struct arena_t));
			return FFNOMEM;
		}
		add_pool_to_tree(pool);
		newArena->largePoolList[i] = (struct poollistnode_t*)ffmetadata_alloc(sizeof(struct poollistnode_t));
		newArena->largePoolList[i]->pool = pool;
		FFInitializeCriticalSection(&newArena->largeListLock[i]);
	}

	return FFSUCCESS;
}

// Creates a new page pool by asking the OS for a block of memory
static int create_pagepool(struct pagepool_t* newPool) {
	// Get an initial range of virtual address space to hold the page maps and bitmaps
	void* metadata = ffpoolmetadata_alloc(1);
	if(metadata == NULL) {
		fprintf(stderr, "create_pagepool metadata alloc failed: %d\n", errno);
		return -1;
	}

	// Get the virtual address space block for the pool itself
	void* poolReserve = os_alloc_highwater(POOL_SIZE);
	if (poolReserve == MAP_FAILED) {
		ffpoolmetadata_free(metadata, 1);
		return -1;
	}
#ifdef FF_PROFILE
	FFAtomicAdd(newPool->arena->profile.currentOSBytesMapped, POOL_SIZE);
	if(newPool->arena->profile.currentOSBytesMapped > newPool->arena->profile.maxOSBytesMapped) {
		// TODO: need thread safety
		newPool->arena->profile.maxOSBytesMapped = newPool->arena->profile.currentOSBytesMapped;
	}
#endif
	newPool->tracking.pageMaps = (struct pagemap_t*)metadata;
	newPool->start = (byte*)poolReserve;
	newPool->nextFreePage = newPool->start;
	newPool->end = newPool->start + POOL_SIZE;
	newPool->startInUse = newPool->start;
	newPool->endInUse = newPool->end;

	// Since nextFreeIndex isn't used by a small pool, we'll set it to SIZE_MAX
	// as a flag to distinguish between the two types of pools in the find
	// pointer code
	newPool->nextFreeIndex = SIZE_MAX;

	FFInitializeCriticalSection(&newPool->poolLock);

	return 0;
}

// Creates a new large allocation pool
static int create_largepagepool(struct pagepool_t* newPool) {
	// Reserve an address range for the metadata
	// Metadata should max out at about a page per 1MB of actual data:
	// (1MB / 2048 bytes/allocations) * (8 bytes/allocation) = 4096 bytes
	void* metadata = ffpoolmetadata_alloc(0);
	if (metadata == NULL) {
		return -1;
	}

	// Reserve an address range for the large pool itself
	void* storage = os_alloc_highwater(POOL_SIZE);
	if (storage == MAP_FAILED) {
		ffpoolmetadata_free(metadata, 0);
		return -1;
	}
#ifdef FF_PROFILE
	FFAtomicAdd(newPool->arena->profile.currentOSBytesMapped, POOL_SIZE);
	while(newPool->arena->profile.currentOSBytesMapped > newPool->arena->profile.maxOSBytesMapped) {
		// TODO: need thread safety
		newPool->arena->profile.maxOSBytesMapped = newPool->arena->profile.currentOSBytesMapped;
	}
#endif
	
	// Add the metadata to the pool
	newPool->tracking.allocations = (uintptr_t*)metadata;

	// Add the storage to the pool
	newPool->start = (byte*)storage;
	newPool->end = (byte*)storage + POOL_SIZE;
	newPool->nextFreePage = (byte*)storage;
	newPool->startInUse = newPool->start;
	newPool->endInUse = newPool->end;

	// There is always one more metadata entry than allocations so that size can
	// be computed by subtracting the pointers. Record the first dummy entry now
	newPool->tracking.allocations[0] = (uintptr_t)storage;

	FFInitializeCriticalSection(&newPool->poolLock);
	return 0;
}

// Helper function to initialize a new jumbo page
static inline int create_jumbopool(struct pagepool_t* newPool, size_t size) {
	// The only metadata required for a jumbo pool is just the size since
	// there will only ever just be the one allocation. Therefore don't
	// allocate a metadata block. Mark it NULL here just to make the point
	newPool->tracking.allocations = NULL;

	// Just like the small pool we'll recycle the nextFreeIndex field as
	// a flag that this isn't a normal pool
	newPool->nextFreeIndex = SIZE_MAX - 1;

	// Since this allocation is coming straight from the OS it needs to be
	// page aligned
	size = ALIGN_TO(size, PAGE_SIZE);

	// Ask the OS for memory
	void* storage;
	storage = os_alloc_highwater(size);
	if(storage == MAP_FAILED) {
		return -1;
	}

#ifdef FF_PROFILE
	// Update statistics
	FFAtomicAdd(newPool->arena->profile.totalBytesAllocated, size);
	FFAtomicAdd(newPool->arena->profile.currentBytesAllocated, size);
	FFAtomicAdd(newPool->arena->profile.currentOSBytesMapped, size);
	if(newPool->arena->profile.currentBytesAllocated > newPool->arena->profile.maxBytesAllocated) {
		// TODO: thread safety
		newPool->arena->profile.maxBytesAllocated = newPool->arena->profile.currentBytesAllocated;
	}
	if(newPool->arena->profile.currentOSBytesMapped > newPool->arena->profile.maxOSBytesMapped) {
		// TODO: need thread safety
		newPool->arena->profile.maxOSBytesMapped = newPool->arena->profile.currentOSBytesMapped;
	}
#endif

	// Record the size of this oddball	
	newPool->start = (byte*)storage;
	newPool->end = (byte*)storage + size;

	// Return success
	return 0;	
}

// Initializes a new thread cache by constructing the bins
static void init_tcache(struct threadcache_t* tcache, struct arena_t* arena) {
	// Initialize all of the bin headers
	// First, the very small bins that are consecutive multiples of 8
	// 8, 16, 24, 32, ... 192, 200, 208
	// Or consecutive multiples of 16 after 16 when using 16 byte alignment
	// 8, 16, 32, 48, ... 272, 288, 304
	for (size_t b = 1; b <= (BIN_COUNT - BIN_INFLECTION); b++) {
		tcache->bins[BIN_COUNT - b].allocSize = b * MIN_ALIGNMENT;
		tcache->bins[BIN_COUNT - b].maxAlloc = PAGE_SIZE / (b * MIN_ALIGNMENT);

		// Set allocCount equal to maxAlloc and not 0 even though its 
		// empty so that the first allocation from bin will actually trigger
		// allocating a page instead of pre-emptively doing that now and
		// wasting it on a bin that might not get used
		tcache->bins[BIN_COUNT - b].allocCount = tcache->bins[BIN_COUNT - b].maxAlloc;
		tcache->bins[BIN_COUNT - b].page = NULL;
#ifdef FF_PROFILE
		tcache->bins[BIN_COUNT - b].totalAllocCount = 0;
#endif
	}

	// Next, the bins that are consecutive in max allocation per page
	// 336, 368, 400, ... 816, 1024, 1360, 2048, 4096+ when 16-byte aligned
	// Note that additional bins in between wouldn't be any more space
	// efficient. For example, you can get 3 * 1360 per page and 2 * 2048
	// but also only 2 * 1536 so having a bin for that size is no more
	// efficient than just dumping it into the 2048 bin
	for (size_t b = 1; b < BIN_INFLECTION; b++) {
		// Bin sizes need to be rounded down to correct alignment
		tcache->bins[b].allocSize = ((PAGE_SIZE / b) & ~(MIN_ALIGNMENT - 1));
		tcache->bins[b].maxAlloc = b;
		tcache->bins[b].allocCount = b;
		tcache->bins[b].page = NULL;
#ifdef FF_PROFILE
		tcache->bins[b].totalAllocCount = 0;
#endif
	}

#ifndef FF_EIGHTBYTEALIGN
	// The bin for 8 byte allocations doesn't fit the pattern when doing
	// 16-byte alignment
	tcache->bins[0].allocSize = 8;
	tcache->bins[0].maxAlloc = PAGE_SIZE / 8;
	tcache->bins[0].allocCount = PAGE_SIZE / 8;
	tcache->bins[0].page = NULL;
#ifdef FF_PROFILE
	tcache->bins[0].totalAllocCount = 0;
#endif
#endif

	// Remember which arena this cache is connected to
	tcache->arena = arena;

	// Get some pages for this new cache to use
	assign_pages_to_tcache(tcache);
}

// Performs one-time setup of metadata structures
static void initialize() {
	isInit = 2;

	// Set up lock that protects modifications to the pool radix tree
	FFInitializeCriticalSection(&poolTreeLock);

	FFInitializeCriticalSection(&poolAllocLock);

	// Initialize metadata pool locks
	FFInitializeCriticalSection(&mdPoolLock);
	for (int i = 0; i < 256; i++) {
		FFInitializeCriticalSection(&binLocks[i]);
	}
	FFInitializeCriticalSection(&mdBinLocks[0]);
	FFInitializeCriticalSection(&mdBinLocks[1]);

#ifndef _WIN64
	// Find the top of the heap on Linux then add 1GB so that there is
	// no contention with small mallocs from libc when used side-by-side
	poolHighWater = (byte*)sbrk(0) + 0x40000000;

	// Create a large contiguous range of virtual address space but don't
	// actually map the addresses to pages just yet
	metadataPool = (byte*)mmap(NULL, 1024UL * 1048576UL, PROT_NONE, 
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	metadataFree = metadataPool;
	metadataEnd = metadataPool + POOL_SIZE;

	mprotect(metadataPool, POOL_SIZE, PROT_READ | PROT_WRITE);
#else
	metadataPool = (byte*)VirtualAlloc(NULL, 1024ULL * 1048576ULL, MEM_RESERVE, PAGE_NOACCESS);
	VirtualAlloc(metadataPool, POOL_SIZE, MEM_COMMIT, PAGE_READWRITE);
	metadataFree = metadataPool;
	metadataEnd = metadataPool + POOL_SIZE;
	poolHighWater = metadataPool + 1024ULL * 1048576ULL + 65536ULL;
#endif

	// Create the default arena used to handle standard malloc API calls
	//arenas[0] = (struct arena_t*)ffmetadata_alloc(sizeof(struct arena_t));
	// Manually allocate initial arena to prevent segfault since ffmetadata_alloc
	// relies on arenas[0] to be initialized when profiling is enabled
	arenas[0] = (struct arena_t*)metadataPool;
	metadataFree += ALIGN_TO(sizeof(struct arena_t), UINT64_C(16));
#ifdef FF_PROFILE
	arenas[0]->profile.currentOSBytesMapped = POOL_SIZE;
#endif
	if(create_arena(arenas[0]) != FFSUCCESS) {
		// Bad news, not much to do except quit
		abort();
	}

	// Initialize OS threading support
	init_threading();

#ifdef FF_PROFILE
	atexit(ffprint_stats_wrapper);
#ifdef FF_INSTRUMENTED
	ffprint_usage_on_interval(stderr, FF_INTERVAL);
#endif
#endif

	isInit = 1;
}

// Destroys a page pool returning all memory to the OS
static void destroy_pool(struct pagepool_t* pool) {
	// Return the pool memory itself
	if(os_free(pool->start) != 0) {
		abort();
	}

	// Return the metadata depending on the pool type
	if(pool->nextFreeIndex == SIZE_MAX) {
		// Small pool
		// Free bitmaps back to the internal allocator. That requires
		// checking every page map for bitmaps
		byte* lastPage = pool->nextFreePage < pool->end ? pool->nextFreePage : pool->end;
		for(size_t i = 0; i < (lastPage - pool->start) / PAGE_SIZE; i++) {
			size_t allocSize = pool->tracking.pageMaps[i].allocSize & ~SEVEN64;
			if(allocSize > 0 && allocSize < 64) {
				size_t bitmapCount = ((PAGE_SIZE / allocSize) & SIXTYTHREE64) != 0 ?
					((PAGE_SIZE / allocSize) >> 6) + 1 : ((PAGE_SIZE / allocSize) >> 6);
				ffmetadata_free(pool->tracking.pageMaps[i].bitmap.array, bitmapCount * 8);
			}
		}

		// Now free all of the page maps
		ffpoolmetadata_free(pool->tracking.pageMaps, 1);
	}
	else if(pool->nextFreeIndex == SIZE_MAX - 1) {
		// Jumbo pool
		// Nothing else to do here since a jumbo pool has no additional
		// metadata to clean up
	}
	else {
		// Large pool
		ffpoolmetadata_free(pool->tracking.allocations, 0);
	}

	remove_pool_from_tree(pool);
	FFDeleteCriticalSection(&pool->poolLock);
}

// Destroys each pool in a pool list as well as the list itself
static void destroy_pool_list(struct poollistnode_t* node) {
	struct poollistnode_t* lastNode;

	while(node != NULL) {
		destroy_pool(node->pool);
		lastNode = node;
		node = node->next;
		ffmetadata_free(lastNode, sizeof(struct poollistnode_t));
	}
}

// Destroys an arena by freeing all pools and associated metadata
static void destroy_arena(struct arena_t* arena) {
	destroy_pool_list(arena->smallPoolList);
	destroy_pool_list(arena->jumboPoolList);
	for(int i = 0; i < MAX_LARGE_LISTS; i++) {
		if(arena->largePoolList[i] != NULL) {
			destroy_pool_list(arena->largePoolList[i]);
		}
		FFDeleteCriticalSection(&arena->largeListLock[i]);
	}

	// TODO: When a thread ends before the arena is destroyed, the 
	// appropriate OS specific handler will clean up its thread cache
	// Here, we need to find a way to delete any thread caches for
	// threads that haven't yet exited (but hopefully know not to
	// allocate from this arena anymore)
	
	FFTlsFree(arena->tlsIndex);

	FFDeleteCriticalSection(&arena->smallListLock);

	ffmetadata_free(arena, sizeof(struct arena_t));
}


/*** Search functions ***/

// Helper function to find the page within a pool that a small pointer was 
// allocated from. On success, the function will return the index within the 
// page where the pointer is located and pagemap will point to the pointer to
// the pagemap. The return value will be less than 0 on failure
static int64_t find_small_ptr(const byte* ptr, const struct pagepool_t* pool, struct pagemap_t** pageMap) {
	// Find the location in the metadata where the page for this pointer is tracked
	size_t mapIndex = (ptr - pool->start) / PAGE_SIZE;
	struct pagemap_t* page = pool->tracking.pageMaps + mapIndex;
	*pageMap = page;

	// Found the page. Find the allocation's place in the bitmap
	uint64_t index = (ptr - page->start) / (page->allocSize & ~SEVEN64);

	// Validate that this is a potentially valid address - i.e. not an
	// address in the middle of an allocation. Trusting compiler optimizations
	// to not issue two divisions to keep things quick
	if((ptr - page->start) % (page->allocSize & ~SEVEN64) != 0) {
		return -2;
	}
	
	// Is the pointer actually allocated?
	if (page->allocSize < 64) {
		uint64_t array = index >> 6;
		uint64_t pos = index - (array << 6);
		if (!(page->bitmap.array[array] & (ONE64 << pos))) {
			return -1;
		}
	}
	else {
		if (!(page->bitmap.single & (ONE64 << index))) {
			return -1;
		}
	}

	return index;
}

// Helper function to find the location within a large allocation pool of a
// specific allocation. Returns the size of the allocation on success or 0 if
// the allocation is not found. Also, if the allocation is found then the 
// index of the allocation in the metadata array is copied to the location 
// pointed to by metadataIndex
static size_t find_large_ptr(const byte* ptr, struct pagepool_t* pool, size_t* metadataIndex) {
	size_t left = 0;
	size_t right = pool->nextFreeIndex;
	size_t current = (right - left) / 2;

	// The metadata array is guaranteed to be sorted, so we can treat it like
	// a binary search tree.
	while (left != right) {
		if (pool->tracking.allocations[current] == (uintptr_t)ptr) {
			if (current == pool->nextFreeIndex) {
				// The final entry in the metadata is not an actual allocation
				return 0;
			}
			// Found the pointer
			*metadataIndex = current;
			return ((pool->tracking.allocations[current + 1] & ~SEVEN64) - pool->tracking.allocations[current]);
		}
		else if ((uintptr_t)ptr < pool->tracking.allocations[current]) {
			// Search left
			right = current;
		}
		else {
			// Search right
			left = current + 1;
		}
		current = left + ((right - left) / 2);
	}

	// The allocation was not found
	return 0;
}


/*** Malloc helper functions ***/

// Actual implementation of malloc for small sizes
static void* ffmalloc_small(size_t size, struct arena_t* arena) {
	struct bin_t* bin;

	// Get the correct thread cache. By allocating
	// from a per-thread cache, we don't have to 
	// acquire and release locks 
	struct threadcache_t* tcache = get_threadcache(arena);

	// Select the correct bin based on size and alignment
	bin = &tcache->bins[GET_BIN(size)];

#ifdef FF_PROFILE
	bin->totalAllocCount++;
#endif

	// If the bin is full or first allocation then get a new page
	if (bin->allocCount == bin->maxAlloc) {
		// Do we have any pages left in the local free page cache?
		if (tcache->nextUnusedPage >= tcache->endUnusedPage) {
			// Local cache is empty. Need to go refresh from a page pool
			assign_pages_to_tcache(tcache);
		}

		// Connect the bin to the page map
		bin->page = tcache->nextUnusedPage;

		// Remove the page map from the local free cache
		tcache->nextUnusedPage++;

		// Update the size record on the page map
		bin->page->allocSize = bin->allocSize;

		// Reset the allocation pointers for the bin
		bin->allocCount = 0;
		bin->nextAlloc = bin->page->start;

		// If the bin holds more than 64 allocations, then point
		// the page map to a new bitmap array
		if (bin->maxAlloc > 64) {
			size_t bitmapCount = (bin->maxAlloc & SIXTYTHREE64) ? 
				(bin->maxAlloc >> 6) + 1 : (bin->maxAlloc >> 6);
			bin->page->bitmap.array = (uint64_t*)ffmetadata_alloc(bitmapCount * 8);
		}
	}

	// Mark the next allocation on the page as in use on the bitmap. 
	// Must use atomic operations to mark the bitmap because even though this is
	// the only cache that can allocate from here, any thread could be freeing a
	// previous allocation
	if (bin->maxAlloc <= 64) {
		FFAtomicOr(bin->page->bitmap.single, (ONE64 << bin->allocCount));
	}
	else {
		FFAtomicOr(bin->page->bitmap.array[bin->allocCount >> 6], (ONE64 << (bin->allocCount & SIXTYTHREE64)));
	}

	// Save pointer to allocation. Advance bin to next allocation
	byte* thisAlloc = bin->nextAlloc;
	bin->nextAlloc += bin->allocSize;
	bin->allocCount++;

	// Mark the page as full if so
	if (bin->allocCount == bin->maxAlloc) {
		bin->page->allocSize |= 4UL;
	}

#ifdef FF_PROFILE
	// Final statistics update
	FFAtomicAdd(arena->profile.totalBytesAllocated, bin->allocSize);
	FFAtomicAdd(arena->profile.currentBytesAllocated, bin->allocSize);
	// TODO: thread safe update
	if (arena->profile.currentBytesAllocated > arena->profile.maxBytesAllocated)
		arena->profile.maxBytesAllocated = arena->profile.currentBytesAllocated;
#endif

	// Return successfully allocated buffer
	return thisAlloc;
}

// Helper to actually implement a large allocation from a specific pool
// Note: caller is responsible for acquiring/releasing pool lock if needed
// before calling this function
static inline void* ffmalloc_large_from_pool(size_t size, size_t alignment, struct pagepool_t* pool) {
	uintptr_t alignedNext = ALIGN_TO((uintptr_t)pool->nextFreePage, alignment);

	// Record the metadata
	// For a standard 8 or 16 byte allignment we just record the address of
	// the next allocation to the end of the list. This allocation was already
	// recorded on the previous call. The reason is that size is stored 
	// implicitly as the difference between consecutive pointers therefore,
	// for N allocations we need N+1 pointers in the metadata.
	// When the alignment is greater than 8/16, the returned pointer could
	// be greater than what was recorded last time so we also have to 
	// update that pointer - effectively growing the previous allocation.
	// The alternative would be to create and immediately mark free the
	// little spacer allocation in between but there isn't any obvious
	// benefit to doing so
#ifdef FF_PROFILE
	FFAtomicAdd(pool->arena->profile.totalBytesAllocated, size + ((byte*)alignedNext - pool->nextFreePage));
	FFAtomicAdd(pool->arena->profile.currentBytesAllocated, size + ((byte*)alignedNext - pool->nextFreePage));
	if(pool->arena->profile.currentBytesAllocated > pool->arena->profile.maxBytesAllocated) {
		// TODO: need thread safe update here
		pool->arena->profile.maxBytesAllocated = pool->arena->profile.currentBytesAllocated;
	}
#endif
	pool->nextFreePage = ((byte*)alignedNext + size);
	if(alignment > MIN_ALIGNMENT) {
		pool->tracking.allocations[pool->nextFreeIndex] = alignedNext;
	}
	pool->tracking.allocations[++pool->nextFreeIndex] = (uintptr_t)pool->nextFreePage;

	// If there is less than the minimum large size allocation left, then 
	// change the last metadata entry so that this allocation gets the remaining
	// space
	if (pool->end - pool->nextFreePage < (ptrdiff_t)(HALF_PAGE + MIN_ALIGNMENT)) {
#ifdef FF_PROFILE
		FFAtomicAdd(pool->arena->profile.currentBytesAllocated, pool->end - pool->nextFreePage);
		FFAtomicAdd(pool->arena->profile.totalBytesAllocated, pool->end - pool->nextFreePage);
#endif
		pool->tracking.allocations[pool->nextFreeIndex] = (uintptr_t)pool->end;
		pool->nextFreePage = pool->end;
	}

	// Return the allocation
	return (void*)alignedNext;
}


// Release any remaining unallocated space in the pool when the pool is being
// removed from the active allocation list. The pool may be destroyed if all
// allocations have also already been freed
static inline void trim_large_pool(struct pagepool_t* pool) {
	if(pool->tracking.allocations[pool->nextFreeIndex] < (uintptr_t)pool->end) {
		size_t remainingSize = (uintptr_t)pool->end - pool->tracking.allocations[pool->nextFreeIndex];
#ifdef FF_PROFILE
		// Must update counter here because it will be decremented
		// inside call to free
		FFAtomicAdd(pool->arena->profile.currentBytesAllocated, remainingSize);
#endif
		// Mark the balance of free space as a single allocation
		pool->nextFreeIndex++;
		pool->tracking.allocations[pool->nextFreeIndex] = (uintptr_t)pool->end;
		pool->nextFreePage = pool->end;

		// Release the slack space
		free_large_pointer(pool, pool->nextFreeIndex - 1, remainingSize);
	}

	// Mark the pool as no longer being allocated from
	pool->tracking.allocations[pool->nextFreeIndex] |= FOUR64;

	// Destroy the pool if completely released
	if(pool->startInUse >= pool->endInUse) {
		destroy_pool(pool);
	}
}

// Finds a suitable large pool to allocate from, or creates a new pool 
// if neccessary
static void* ffmalloc_large(size_t size, size_t alignment, struct arena_t* arena) {
	struct poollistnode_t* node;
	struct poollistnode_t* tailNode;
	struct pagepool_t* pool = NULL;
	byte* alignedNext;
	unsigned int loopCount = 0;
	const unsigned int listId = get_large_list_index();

	node = arena->largePoolList[listId];
	tailNode = node;

	// Loop through the large pools assigned to this processor looking for one
	// that has space. There may be pools on other CPUs that would be a better
	// fit but we don't check those
	while (node != NULL) {
		pool = node->pool;
		alignedNext = (byte*)ALIGN_TO((uintptr_t)pool->nextFreePage, alignment);
		if (alignedNext + size > pool->end) {
			// No space in this pool, advance to the next one
			tailNode = node;
			node = node->next;
			loopCount++;
		}
		else {
			// Space available allocate from here if possible
#ifdef FFSINGLE_THREADED
			return ffmalloc_large_from_pool(size, alignment, pool);
#else
			FFEnterCriticalSection(&pool->poolLock);
			void* allocation;

			// Since we don't lock before checking the size (to avoid a lock pileup)
			// we have to check the size again here inside the lock to make sure that
			// there is still space available
			alignedNext = (byte*)ALIGN_TO((uintptr_t)pool->nextFreePage, alignment);
			if (alignedNext + size <= pool->end) {
				allocation = ffmalloc_large_from_pool(size, alignment, pool);
				FFLeaveCriticalSection(&pool->poolLock);
				return allocation;
			}
			else {
				// Lost the race, try the next bin
				node = node->next;
			}
			FFLeaveCriticalSection(&pool->poolLock);
#endif
		}
	}

	// None of the current pools on this CPU have space
	FFEnterCriticalSection(&arena->largeListLock[listId]);

	// While waiting for the lock, was a new pool created?
	if (tailNode->next != NULL) {
		pool = tailNode->next->pool;
		FFEnterCriticalSection(&pool->poolLock);
		alignedNext = (byte*)ALIGN_TO((uintptr_t)pool->nextFreePage, alignment);

		// Does the new pool have enough space to service this request? If so,
		// allocate and be done
		if (alignedNext + size <= pool->end) {
			void* allocation = ffmalloc_large_from_pool(size, alignment, pool);
			FFLeaveCriticalSection(&pool->poolLock);
			FFLeaveCriticalSection(&arena->largeListLock[listId]);
			return allocation;
		}
		FFLeaveCriticalSection(&pool->poolLock);

		while (tailNode->next != NULL) {
			tailNode = tailNode->next;
		}
	}

	// If we get here, either we entered the lock straight away or another pool
	// was created while waiting for the lock, but we must have been in the back
	// of the line because its already too small. Either way, create a new large
	// allocation pool
	pool = (struct pagepool_t*)ffmetadata_alloc(sizeof(struct pagepool_t));
	if (pool == NULL) {
		fprintf(stderr, "Out of metadata space creating large pool\n");
		FFLeaveCriticalSection(&arena->largeListLock[listId]);
		return NULL;
	}
	pool->arena = arena;
	if (create_largepagepool(pool) == -1) {
		// Maybe there is a way to recover here, but for the moment
		// the caller is just all out of luck
		ffmetadata_free(pool, sizeof(struct pagepool_t));
		FFLeaveCriticalSection(&arena->largeListLock[listId]);
		return NULL;
	}

	// Pool creation successful so add it to the tree for later pointer lookup
	add_pool_to_tree(pool);

	// Finally allocate the block requested 
	// No need for locks here because nobody else can see this until
	// it's added to the list
	void* allocation = ffmalloc_large_from_pool(size, alignment, pool);

	node = (struct poollistnode_t*)ffmetadata_alloc(sizeof(struct poollistnode_t));
	node->pool = pool;

	tailNode->next = node;

	if (loopCount >= MAX_POOLS_PER_LIST) {
		node = arena->largePoolList[listId];
		arena->largePoolList[listId] = arena->largePoolList[listId]->next;
		trim_large_pool(node->pool);
		// TODO: Pool needs to be held onto for destroy arena. Save it where?
	}
	FFLeaveCriticalSection(&arena->largeListLock[listId]);

	return allocation;
}

// Helper function to allocate larger than POOL_SIZE requests
static void* ffmalloc_jumbo(size_t size, struct arena_t* arena) {
	// A larger than POOL_SIZE request will require its own oddly sized pool
	// Start by creating the pool object
	struct pagepool_t* jumboPool = (struct pagepool_t*)ffmetadata_alloc(sizeof(struct pagepool_t));

	if(jumboPool == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	struct poollistnode_t* newNode = (struct poollistnode_t*)ffmetadata_alloc(sizeof(struct poollistnode_t));
	if(newNode == NULL) {
		ffmetadata_free(jumboPool, sizeof(struct pagepool_t));
		errno = ENOMEM;
		return NULL;
	}
	
	// Connect page to caller's arena and initialize
	jumboPool->arena = arena;
	if(create_jumbopool(jumboPool, size) == -1) {
		ffmetadata_free(jumboPool, sizeof(struct pagepool_t));
		ffmetadata_free(newNode, sizeof(struct poollistnode_t));
		errno = ENOMEM;
		return NULL;
	}

	// Record the pool in the global pool tree
	add_pool_to_tree(jumboPool);

	// Add to the list of jumbo pools in this arena
	newNode->pool = jumboPool;
#ifdef FFSINGLE_THREADED
	newNode->next = arena->jumboPoolList;
	arena->jumboPoolList = newNode;
#else
	struct poollistnode_t* currenthead;
	do {
		currenthead = arena->jumboPoolList;
		newNode->next = currenthead;
	} while (!FFAtomicCompareExchangePtr(&arena->jumboPoolList, newNode, currenthead));
#endif

	// Return the start of the pool as the new allocation
	return jumboPool->start;
}


/*** Free helper functions ***/

// Helper function to return a small pool page back to the OS
static void free_page(struct pagepool_t* pool, struct pagemap_t* pageMap) {
	byte* startAddress = pageMap->start;
	byte* endAddress = startAddress + PAGE_SIZE;
	unsigned int leftIsFreed = 0;
	unsigned int rightIsFreed = 0;
	struct pagemap_t* currentPage = pageMap;
	struct pagemap_t* leftmostPage = pageMap;
	struct pagemap_t* rightmostPage = pageMap;

	FFEnterCriticalSection(&pool->poolLock);

	// Check earlier pages to see if they are also unused but not yet returned
	// to the OS. Stop when the beginning of the pool, an in use page, or a
	// released page is reached
	while (startAddress > pool->start) {
		currentPage--;
		if ((currentPage->allocSize & SEVEN64) == 5) {
			// Page is no longer actively being allocated from, all allocations
			// have been freed, but page has not been returned to OS
			startAddress -= PAGE_SIZE;
			leftmostPage = currentPage;
		}
		else if((currentPage->allocSize & SEVEN64) == 7) {
			// Page has been returned to the OS
			leftIsFreed++;
			break;
		}
		else {
			break;
		}
	}

	if (startAddress == pool->start) {
		leftIsFreed++;
	}

	// Same as above, except now check following pages
	currentPage = pageMap;
	while (endAddress < pool->end) {
		currentPage++;
		if ((currentPage->allocSize & SEVEN64) == 5) {
			// Page is no longer actively being allocated from, all allocations
			// have been freed, but page has not been returned to OS
			endAddress += PAGE_SIZE;
			rightmostPage = currentPage;
		}
		else if ((currentPage->allocSize & SEVEN64) == 7) {
			// Page has been returned to the OS
			rightIsFreed++;
			break;
		}
		else {
			break;
		}
	}

	if (endAddress == pool->end) {
		rightIsFreed++;
	}

	// Check if the computed range of pages meets either the minimum size 
	// threshold or if the range constitutes an "island" connecting two
	// freed regions. If so, then return the pages to the OS
	if ((endAddress - startAddress >= (ptrdiff_t)(PAGE_SIZE * MIN_PAGES_TO_FREE)) || (leftIsFreed != 0 && rightIsFreed != 0)) {
		if(os_decommit((void*)startAddress, endAddress - startAddress) == FALSE) {
			if(errno == ENOMEM) {
				// Likely out of VMAs. Don't die here - continue on in the hopes that
				// more frees will allow VMAs to retire completely
				FFLeaveCriticalSection(&pool->poolLock);
				return;
			}
			fprintf(stderr, "Error: %d Couldn't unmap %p to %p\n", errno, startAddress, endAddress);
			fflush(stderr);
			abort();
		}
#ifdef FF_PROFILE
		FFAtomicSub(pool->arena->profile.currentOSBytesMapped, endAddress - startAddress);
#endif

		// Mark all of the pages as returned to the OS
		for (currentPage = leftmostPage; currentPage <= rightmostPage; currentPage++) {
			currentPage->allocSize |= 2UL;
		}

		// Update the "in use" pointers which measure the earliest and latest address
		// not yet freed in the pool. When those meet or cross then the whole pool is
		// completely freed and its metadata data can be freed
		if (startAddress <= pool->startInUse) {
			for (currentPage = rightmostPage; ((currentPage->allocSize & TWO64) != 0) && (currentPage->start < pool->endInUse) && (currentPage->start + PAGE_SIZE < pool->end); currentPage++) {
			}
			if (currentPage->start > pool->start) {
				pool->startInUse = currentPage->start;
			}
		}
		if (endAddress >= pool->endInUse) {
			for (currentPage = leftmostPage; ((currentPage->allocSize & TWO64) != 0) && currentPage->start >= pool->startInUse && (currentPage->start > pool->start); currentPage--) {
				if (currentPage->start > pool->start) {
					if ((currentPage - 1)->start == NULL) {
						currentPage--;
						break;
					}
				}
			}
			pool->endInUse = currentPage->start + PAGE_SIZE;
		}
		if (pool->startInUse >= pool->endInUse) {
			// All space in the pool has been allocated and subsequently freed. Destroy
			// this pool to free up metadata resources
			FFLeaveCriticalSection(&pool->poolLock);
			destroy_pool(pool);
			return;
		}
	}
	FFLeaveCriticalSection(&pool->poolLock);
}

// Helper function to mark a small allocation freed
static inline void free_small_ptr(struct pagepool_t* pool, struct pagemap_t* pageMap, size_t index) {
#ifdef FF_PROFILE
	FFAtomicSub(pool->arena->profile.currentBytesAllocated, (pageMap->allocSize & ~SEVEN64));
#endif
	if (pageMap->allocSize < 64) {
		// Find the right bitmap and location
		size_t array = (index >> 6);
		size_t pos = index - (array << 6);

		// Clear the "allocated" flag
		FFAtomicAnd(pageMap->bitmap.array[array], ~(ONE64 << pos));

		// Check if the page can be released to the OS
		if (pageMap->allocSize & 4UL) {
			uint64_t result = 0;
			size_t bitmaps = (PAGE_SIZE / (pageMap->allocSize & ~SEVEN64)) >> 6;
			if ((PAGE_SIZE / (pageMap->allocSize & ~SEVEN64)) & SIXTYTHREE64) {
				bitmaps++;
			}
			for (size_t i = 0; i < bitmaps; i++) {
				result |= pageMap->bitmap.array[i];
			}

			if (result == 0) {
				// All allocations are now freed
				// Mark page as ready to be released
				pageMap->allocSize |= 1;
				//ffmetadata_free(pageMap->bitmap.array, bitmaps * 8);
				free_page(pool, pageMap);
			}
		}
	}
	else {
		// Clear the "allocated" flag in the bitmap
		FFAtomicAnd(pageMap->bitmap.single, ~(ONE64 << index));

		// Check if the page can be released to the OS
		if ((pageMap->allocSize & 4UL) && (pageMap->bitmap.single == 0)) {
			pageMap->allocSize |= 1;
			free_page(pool, pageMap);
		}
	}
}

// Helper function that frees a large pointer
static void free_large_pointer(struct pagepool_t* pool, size_t index, __attrUnusedParam size_t size) {
	size_t firstFreeIndex;
	size_t lastFreeIndex;

	// Lock this pool while the free happens
	FFEnterCriticalSection(&pool->poolLock);

	// Mark the allocation as freed in the metadata
	pool->tracking.allocations[index] |= ONE64;

#ifdef FF_PROFILE
	FFAtomicSub(pool->arena->profile.currentBytesAllocated, size);
#endif
	// Start searching for the start of the contiguous free region. The search ends when
	// the beginning of the list is reached, an in use block is found, or a block that
	// has already at least partially been unmapped
	firstFreeIndex = index;
	while ((firstFreeIndex > 0) && ((pool->tracking.allocations[firstFreeIndex - 1] & THREE64) == 1)) {
		firstFreeIndex--;
	}

	unsigned int leftIsFreed = 0;
	unsigned int rightIsFreed = 0;

	// This is potentially the location to start unmapping from. However, it might need to
	// be adjusted forward or backwards depending on what the previous block was marked as
	uintptr_t startFreeAddr = (pool->tracking.allocations[firstFreeIndex] & ~THREE64);
	if ((startFreeAddr & (PAGE_SIZE - 1)) != 0) {
		if ((pool->tracking.allocations[firstFreeIndex - 1] & TWO64) != 0) {
			// The previous allocation has been at least partially unmapped
			// but there is still the remaining bit in this page. So, adjust
			// the start address backwards to the start of this frame
			startFreeAddr = (startFreeAddr & ~(PAGE_SIZE - 1));
			leftIsFreed++;
		}
		else {
			// The previous allocation is still in use, so this page cannot
			// be unmapped. Adjust the start address forward to the start
			// of the next page
			startFreeAddr = ((startFreeAddr + PAGE_SIZE) & ~(PAGE_SIZE - 1));
		}
	}
	else if(firstFreeIndex == 0 || (pool->tracking.allocations[firstFreeIndex - 1] & TWO64)) {
		leftIsFreed++;
	}

	// Now start searching for the end of the contiguous free region. As before, stop when
	// the end of the list is reached, an allocated block is reached, or a partially
	// unmapped allocation is found
	lastFreeIndex = index;
	while ((lastFreeIndex < pool->nextFreeIndex) && ((pool->tracking.allocations[lastFreeIndex + 1] & THREE64) == 1)) {
		lastFreeIndex++;
	}

	// Potentially the end of the region to unmap. If it doesn't fall on a page boundary
	// it will need to be adjusted forward or backwards
	uintptr_t endFreeAddr = (pool->tracking.allocations[lastFreeIndex + 1] & ~SEVEN64);
	if(endFreeAddr == 0) {
		fprintf(stderr, "endFreeAddr == 0 test 1\n");
		fflush(stderr);
		abort();
	}

	if ((endFreeAddr & (PAGE_SIZE - 1)) != 0) {
		if ((pool->tracking.allocations[lastFreeIndex + 1] & TWO64) != 0) {
			// The allocation following the region to be freed has already
			// been partially freed, but the portion on this same page also
			// needs to be freed so adjust the end address to the end of the page
			endFreeAddr = ((endFreeAddr + PAGE_SIZE) & ~(PAGE_SIZE - 1));
			if(endFreeAddr == 0) {
				fprintf(stderr, "endFreeAddr == 0 test 2\n");
				fflush(stderr);
				abort();
			}
			rightIsFreed++;
		}
		else {
			// The next allocation is still in use, so nothing on this page can
			// be freed yet. Move the end address back to the start of the page
			endFreeAddr = (endFreeAddr & ~(PAGE_SIZE - 1));
		}
	}
	else {
		if((byte*)endFreeAddr >= pool->end || (pool->tracking.allocations[lastFreeIndex + 1] & TWO64)) {
			rightIsFreed++;
		}
	}

	if((byte*)startFreeAddr <= pool->startInUse) {
		if((byte*)endFreeAddr < pool->end) {
			size_t contFreeIndex = lastFreeIndex; 
			while(contFreeIndex < pool->nextFreeIndex && ((pool->tracking.allocations[contFreeIndex + 1] & TWO64) != 0)) {
				contFreeIndex++;
			}
			pool->startInUse = (byte*)(pool->tracking.allocations[contFreeIndex + 1] & ~SEVEN64);
		}
		else {
			pool->startInUse = pool->end;
		}
	}

	// The whole pool is now empty, destroy it (which will also finish freeing up the indicated allocation)
	if((pool->startInUse >= pool->endInUse) && (pool->tracking.allocations[pool->nextFreeIndex] >= (uintptr_t)pool->end + FOUR64)) {
		FFLeaveCriticalSection(&pool->poolLock);
		destroy_pool(pool);
#ifdef FF_PROFILE
		// Update the physical memory statistics
		FFAtomicSub(pool->arena->profile.currentOSBytesMapped, (size_t)(endFreeAddr - startFreeAddr));
#endif
	}
	else if (endFreeAddr > startFreeAddr) {
		// Set a minimum number of pages before actually returning them to the OS
		// On Linux, this helps reduce fragmentation which results in VMA bloat which
		// can wrek our ability to request new pages. Alternately, if this is an island
		// between two free regions, return it regardless of size so that 1) it doesn't
		// get orphaned and 2) eliminates a VMA on Linux
		if ((endFreeAddr - startFreeAddr >= (PAGE_SIZE * MIN_PAGES_TO_FREE)) || (leftIsFreed !=0 && rightIsFreed != 0)) {
			if (os_decommit((void*)startFreeAddr, endFreeAddr - startFreeAddr) == FALSE) {
#ifndef _WIN64
				if(errno == ENOMEM) {
					// Likely ran out of VMAs. Just continue without marking anything as
					// being cleaned up, that way a future fffree can try again and hopefully
					// make progress
					FFLeaveCriticalSection(&pool->poolLock);
					return;
				}

				fprintf(stderr, "Large pool decommit fail: %d, %p size: %ld\n", errno, (void*)startFreeAddr, endFreeAddr - startFreeAddr);
#else
				fprintf(stderr, "Large pool decommit fail: %d, %p size: %lld\n", GetLastError(), (void*)startFreeAddr, endFreeAddr - startFreeAddr);
#endif
				fflush(stderr);
				abort();
			}
#ifdef FF_PROFILE
			// Update the physical memory statistics
			FFAtomicSub(pool->arena->profile.currentOSBytesMapped, (size_t)(endFreeAddr - startFreeAddr));
#endif

			// Lastly, mark all the pointers as unmapped
			for (size_t i = firstFreeIndex; i <= lastFreeIndex; i++) {
				pool->tracking.allocations[i] |= THREE64;
			}
		}
	}
	FFLeaveCriticalSection(&pool->poolLock);
}

// Frees a jumbo allocation by deleting the associated pool
static inline void free_jumbo(struct pagepool_t* pool) {
#ifdef FF_PROFILE
	FFAtomicSub(pool->arena->profile.currentBytesAllocated, (size_t)(pool->end - pool->start));
	FFAtomicSub(pool->arena->profile.currentOSBytesMapped, (size_t)(pool->end - pool->start));
#endif
	destroy_pool(pool);
}

/*** Public API functions ***/

// Replacement for malloc. Returns a pointer to an available
// memory region >= size or NULL upon failure
void* ffmalloc(size_t size) {
	void* allocation;
#if defined(FFSINGLE_THREADED) || !defined(_WIN64)
	if (isInit == 2) {
		abort();
	}
	if (!isInit) {
		initialize();
	}
#endif

	// Returning NULL when size==0 would be legal according to the man
	// pages. This would be the preferred behavior because an allocation
	// of zero is almost certain to turn into a call to realloc and that's
	// expensive for this library. However, at least one of the PARSEC 
	// benchmarks won't run if we do that so begrudingly return a minimum
	// allocation for size 0
	if (size == 0) {
		size = 8;
	}

#ifdef FF_PROFILE
	FFAtomicIncrement(arenas[0]->profile.mallocCount);
	FFAtomicAdd(arenas[0]->profile.totalBytesRequested, size);
#endif
	// If size is very close to SIZE_MAX, the ALIGN_SIZE macro will 
	// return 0
	if(size > SIZE_MAX - MIN_ALIGNMENT) {
		errno = ENOMEM;
		return NULL;
	}

	// All allocations are at least 8 byte aligned. Round up if needed
	size = ALIGN_SIZE(size);

	// Small (less than half page size) allocations are allocated
	// in matching sized bins per thread. Large allocations come
	// out of a single central pool. Allocations larger than a single
	// pool become their own pool
	if (size <= (HALF_PAGE)) {
		allocation = ffmalloc_small(size, arenas[0]);
	}
	else if (size < (POOL_SIZE - HALF_PAGE)) {
		allocation = ffmalloc_large(size, MIN_ALIGNMENT, arenas[0]);
	}
	else {
		allocation = ffmalloc_jumbo(size, arenas[0]);
	}

#ifdef FF_PROFILE
	print_current_usage();
#endif
	if(allocation == NULL) {
		errno = ENOMEM;
	}
	return allocation;
}

// Replacement for realloc. Returns a pointer to a memory region
// that is >= size and also contains the contents pointed to by ptr
// if ptr is not NULL. The return value may be equal to ptr and will
// be NULL on error.
void* ffrealloc(void* ptr, size_t size) {
	// Per the man page for realloc, calling with ptr == NULL is
	// equal to malloc(size). When ptr isn't NULL, calling
	// realloc with size == 0 is the same as free(ptr)
	if (ptr == NULL) {
		return ffmalloc(size);
	}
	else if (size == 0) {
		fffree(ptr);
		return NULL;
	}
	
	struct pagepool_t* pool = find_pool_for_ptr((const byte*)ptr);
	if (pool == NULL) {
		// Program is trying to free a bad pointer
		// Or more likely there is a bug in this library
		fprintf(stderr, "Attempt to realloc %p but no matching pool\n", ptr);
		fflush(stderr);
		abort();
	}

#ifdef FF_PROFILE
	FFAtomicIncrement(arenas[0]->profile.reallocCount);
#endif

	// Was this a large or small allocation pool?
	if (pool->nextFreeIndex < SIZE_MAX - 1) {
		// Large allocation
		size_t index = 0;
		size_t oldSize = find_large_ptr((const byte*)ptr, pool, &index);

		// Pointer not found - abort with extreme prejudice
		// Likely a bug that needs cleaning up
		if (oldSize == 0) {
			fprintf(stderr, "realloc bad large ptr: %p\n", ptr);
			fprintf(stderr, "pool:    %p\n", pool);
			fprintf(stderr, "pool st: %p\n", pool->start);
			fflush(stderr);
			abort();
		}

		// When the reallocation size isn't bigger than the current size
		// just quit and tell the app to keep using the same allocation
		if (size <= oldSize) {
			return ptr;
		}

#ifdef FF_GROWLARGEREALLOC
		// Check if the allocation happens to be at the end of the large
		// pool and thus can be grown without extending into previously
		// allocated space. It seems like this would be uncommon but
		// profiling the SPECint PerlBench test says that its at least
		// occassionally very common

		// Potential integer overflow issue below. Since inplace resize 
		// is only possible if the new size would still fit within the 
		// pool, checking that size < POOL_SIZE should be sufficient
		if(size < POOL_SIZE) {
			FFEnterCriticalSection(&pool->poolLock);
			size_t additionalSize = ALIGN_SIZE(size) - oldSize;
			if(index == pool->nextFreeIndex-1 && (pool->nextFreePage + additionalSize <= pool->end)) {
#ifdef FF_PROFILE
				FFAtomicIncrement(arenas[0]->profile.reallocCouldGrow);
				FFAtomicAdd(arenas[0]->profile.currentBytesAllocated, additionalSize);
				FFAtomicAdd(arenas[0]->profile.totalBytesAllocated, additionalSize);
				FFAtomicAdd(arenas[0]->profile.totalBytesRequested, size - oldSize);
#endif
				pool->nextFreePage += additionalSize;
				pool->tracking.allocations[pool->nextFreeIndex] += additionalSize;
				FFLeaveCriticalSection(&pool->poolLock);
				return ptr;
			}
			FFLeaveCriticalSection(&pool->poolLock);
		}
#endif

		// A bigger reallocation size requires copying the old data to
		// the new location and then freeing the old allocation
		void* temp = ffmalloc(size);
		memcpy(temp, ptr, oldSize);
		free_large_pointer(pool, index, oldSize);
		return temp;
	}
	else if (pool->nextFreeIndex == SIZE_MAX - 1) {
		// Jumbo allocation - the pool is the allocation
		// How big was it?
		size_t jumboSize = pool->end - pool->start;

		// Is it still big enough?
		// TODO: Add code to trim pages from the end if the size is
		// sufficiently smaller
		// Also consider expansion if possible in the single threaded
		// case
		if(size <= jumboSize) {
			return pool->start;
		}

		// Not big enough so we'll have to create a new allocation
		void* newJumbo = ffmalloc(size);
		if(newJumbo == NULL) {
			errno = ENOMEM;
			return NULL;
		}

		// Copy into the new buffer
		memcpy(newJumbo, ptr, jumboSize);

		// Release memory associated with the old allocation and cleanup metadata
		free_jumbo(pool);

		// Return success
		return newJumbo;
	}
	else {
		// Small allocation
		struct pagemap_t* pageMap = NULL;

		// Find the specific page and index of this allocation
		int64_t index = find_small_ptr((const byte*)ptr, pool, &pageMap);

		// For now, fail violently if we can't find the pointer
		// (likely a bug in the library somewhere)
		if (index < 0) {
			// Not a valid pointer
			fprintf(stderr, "realloc bad small ptr: %p\n", ptr);
			fprintf(stderr, "pool: %p\n", pool);
			fprintf(stderr, "pageMap: %p\n", pageMap);
			fflush(stderr);
			abort();
		}

		if (size <= (pageMap->allocSize & ~SEVEN64)) {
			return ptr;
		}

		void* temp = ffmalloc(size);
		memcpy(temp, ptr, (pageMap->allocSize & ~SEVEN64));
		free_small_ptr(pool, pageMap, index);
		return temp;
	}
}

// Replacement for reallocarray. Equivalent to realloc(ptr, nmemb * size)
// but will return NULL and signal ENOMEM if the multiplication overflows
void* ffreallocarray(void* ptr, size_t nmemb, size_t size) {
	// Overflow check. Existing allocation remains unaltered if there is overflow
	if (nmemb && size > (SIZE_MAX / nmemb)) {
		errno = ENOMEM;
		return NULL;
	}

#ifdef FF_PROFILE
	FFAtomicIncrement(arenas[0]->profile.reallocarrayCount);
#endif

	return ffrealloc(ptr, nmemb * size);
}

// Replacement for calloc. Returns a pointer to a memory region
// that is >= nmemb * size and is guaranteed to be zeroed out.
// Returns NULL on error
void* ffcalloc(size_t nmemb, size_t size) {
        // Don't bother with size 0 allocations
        if (nmemb == 0 || size == 0)
                return NULL;

	// Ensure multiplication won't overflow
	if (size > (SIZE_MAX / nmemb)) {
		return NULL;
	}

#if defined(FFSINGLE_THREADED) || !defined(_WIN64)
	if(isInit == 2) {
		abort();
	}
	if (!isInit) {
		initialize();
	}
#endif
#ifdef FF_PROFILE
	FFAtomicIncrement(arenas[0]->profile.callocCount);
#endif

	// Either VirtualAlloc or mmap guarantee us zeroed pages and since
	// we don't use mremap there is no chance of recycling a dirty
	// page and therefore no need to explicitly zero out the allocation
	//return ffmalloc(nmemb?nmemb * size:size);
	return ffmalloc(nmemb*size);
}

// Replacment for free. Marks an allocation previously returned by
// ffmalloc, ffrealloc, or ffcalloc as no longer in use. The memory
// page might be returned to the OS depending on the status of other
// allocations from the same page
void fffree(void* ptr) {
	// Per the specification for free, calling with ptr == NULL is
	// legal and is a no-op
	if (ptr == NULL)
		return;

	struct pagepool_t* pool = find_pool_for_ptr((const byte*)ptr);
	if (pool == NULL) {
		// Program is trying to free a bad pointer
		// Or more likely there is a bug in this library
		fprintf(stderr, "Attempt to free %p but no matching pool\n", ptr);
		fflush(stderr);
		abort();
	}

#ifdef FF_PROFILE
	FFAtomicIncrement(arenas[0]->profile.freeCount);
#endif

	// Was this a large or small allocation pool?
	if (pool->nextFreeIndex < SIZE_MAX - 1) {
		// Large allocation
		size_t index = 0;
		size_t size = find_large_ptr((const byte*)ptr, pool, &index);

		// Pointer not found - abort with extreme prejudice
		// Likely a bug that needs cleaning up
		if (size == 0) {
			fprintf(stderr, "free bad large ptr: %p\n", ptr);
			fprintf(stderr, "pool:    %p\n", pool);
			fprintf(stderr, "pool st: %p\n", pool->start);
			fflush(stderr);
			abort();
		}

		free_large_pointer(pool, index, size);
	}
	else if (pool->nextFreeIndex == SIZE_MAX - 1) {
		// Jumbo allocation
		free_jumbo(pool);
	}
	else {
		// Small allocation
		struct pagemap_t* pageMap = NULL;

		// Find the specific page and index of this allocation
		int64_t index = find_small_ptr((const byte*)ptr, pool, &pageMap);

		// For now, fail violently if we can't find the pointer
		if (index < 0) {
			// Not a valid pointer
			fprintf(stderr, "free bad ptr: %p\n", ptr);
			fprintf(stderr, "ptr size:     %ld\n", pageMap->allocSize & ~SEVEN64);
			fprintf(stderr, "pool start:   %p\n", pool->start);
			fprintf(stderr, "page start:   %p\n", pageMap->start);
			fflush(stderr);
			abort();
		}

		free_small_ptr(pool, pageMap, index);
	}
}

static inline void* ffmemalign_internal(size_t alignment, size_t size) {
#ifdef FF_PROFILE
	FFAtomicIncrement(arenas[0]->profile.posixAlignCount);
	FFAtomicAdd(arenas[0]->profile.totalBytesRequested, size);
#endif

	// Allocation can be serviced from the small bin only if both the size
	// and the alignment fit into the small bin
	if(size <= HALF_PAGE && alignment <= HALF_PAGE) {
		if(size <= alignment) {
			// When size is less than alignment, just returning an
			// allocation of size == alignment will guarantee the
			// requested alignment
			return ffmalloc_small(alignment, arenas[0]);
		}
		else {
			// When size is greater than alignment, rounding size
			// up to the next power of two will ensure alignment
			return ffmalloc_small(ONE64<<(64-FFCOUNTLEADINGZEROS64(size-1)), arenas[0]);
		}
	}

	// Either size or alignment won't fit into the normal small bins so
	// even if the size is small, it will have to come out of the large
	// allocation bin to get the requested alignment

	// Round size up to a multiple of base alignment if needed
	size = ALIGN_SIZE(size);

	if(size >= POOL_SIZE) {
		return ffmalloc_jumbo(size, arenas[0]);
	}
	else {
		return ffmalloc_large(size, alignment, arenas[0]);
	}

	return NULL;
}

// Replacement for posix_memalign. Returns a pointer to a block of memory that
// is >= size and that has at least the specified alignment, which must be a
// power of two
int ffposix_memalign(void** ptr, size_t alignment, size_t size) {
	// Don't bother with zero byte allocations
	// Also check against overflow below
	if(size == 0 || (size >= SIZE_MAX - PAGE_SIZE )) {
		*ptr = NULL;
		return EINVAL;
	}

	// Alignment must be at least sizeof(void*) and alignment must be a
	// power of two
	if(alignment < 8 || FFPOPCOUNT64(alignment) != 1) {
		*ptr = NULL;
		return EINVAL;
	}

	// Current jumbo allocation code is missing alignment support but all
	// jumbo allocations will be at least page aligned. For now it is an
	// error to request more than page alignment for a jumbo allocation
	if(size + PAGE_SIZE >= POOL_SIZE && alignment > PAGE_SIZE) {
		*ptr = NULL;
		return EINVAL;
	}

	*ptr = ffmemalign_internal(alignment, size);
	if(*ptr == NULL) {
		return ENOMEM;
	}

	return 0;
}

// Replacement for memalign. The man page says this is obsolete but it turns
// up in PARSEC benchmark so here it is. The address of the returned allocation
// will be a multiple of alignment and alignment must be a power of two.
void* ffmemalign(size_t alignment, size_t size) {
	// Forbid zero byte allocations
	// Protect against integer overflow later
	if(size == 0 || (size >= SIZE_MAX - PAGE_SIZE)) {
		return NULL;
	}

	// Verify that alignment is a power of two
	if(FFPOPCOUNT64(alignment) != 1) {
		errno = EINVAL;
		return NULL;
	}

	// The man page is silent on whether a minimum value for alignment is
	// enforced (compare to posix_memalign). Since none is mentioned, 
	// allow all values but anything less than pointer size will just be
	// handled as a regular malloc
	if(alignment <= sizeof(void*)) {
		return ffmalloc(size);
	}

	// The jumbo allocation code doesn't support custom alignment right now
	// but any jumbo alignment will be page aligned. So, error out if the
	// request is bigger than page size otherwise carry on
	if(size + PAGE_SIZE >= POOL_SIZE && alignment > PAGE_SIZE) {
		errno = EINVAL;
		return NULL;
	}

	return ffmemalign_internal(alignment, size);
}

// Replacment for aligned_alloc. Alignment must be a power of two and size
// must be a multiple of alignment. Returned pointer will point to a region
// that is >= size and at least alignment aligned or NULL on failure
void *ffaligned_alloc(size_t alignment, size_t size) {
	// Don't allow zero byte allocations
	// Protect against integer overflow
	if(size == 0 || (size >= SIZE_MAX - PAGE_SIZE)) {
		return NULL;
	}

	// Alignment must be at least sizeof(void*) and alignment must be a
	// power of two
	if(alignment < 8 || FFPOPCOUNT64(alignment) != 1) {
		errno = EINVAL;
		return NULL;
	}

	// Description of aligned_alloc says that size must be a multiple of
	// alignment
	if(size < alignment || (size % alignment != 0)) {
		errno = EINVAL;
		return NULL;
	}

	// Missing alignment support in jumbo code so forbid greater than page
	// alignment for jumbo allocations until that's fixed. All jumbo
	// allocations will be page aligned anyways
	if(size + PAGE_SIZE >= POOL_SIZE && alignment > PAGE_SIZE) {
		errno = EINVAL;
		return NULL;
	}

#ifdef FF_PROFILE
	FFAtomicIncrement(arenas[0]->profile.allocAlignCount);
	FFAtomicAdd(arenas[0]->profile.totalBytesRequested, size);
#endif

	if (size >= POOL_SIZE) {
		return ffmalloc_jumbo(size, arenas[0]);
	}
	// Allocation can be serviced from the small bin only if both the size
	// and the alignment fit into the small bin
	else if(size <= HALF_PAGE && alignment <= HALF_PAGE) {
		return ffmalloc_small(ONE64<<(64-FFCOUNTLEADINGZEROS64(size-1)), arenas[0]);
	}
	else {
		// Either size or alignment won't fit into the normal small bins so
		// even if the size is small, it will have to come out of the large
		// allocation bin to get the requested alignment
		return ffmalloc_large(size, alignment, arenas[0]);
	}
}

// Replacement for malloc_usable_size. Returns the actual amount of space
// allocated to a given pointer which could be greater than the requested size
size_t ffmalloc_usable_size(const void* ptr) {
	// The man page for this function is vague on how this function handles
	// errors other than being explicit that a NULL value for ptr should
	// return zero
	if(ptr == NULL) {
		return 0;
	}

	// Follow above logic and any invalid pointer will result in size of
	// zero and errno will not be set
	struct pagepool_t* pool = find_pool_for_ptr((const byte*)ptr);
	if (pool == NULL) {
		return 0;
	}

	// Was this a large or small allocation pool?
	if (pool->nextFreeIndex < SIZE_MAX - 1) {
		// Large allocation
		size_t index = 0;
		return find_large_ptr((const byte*)ptr, pool, &index);
	}
	else if(pool->nextFreeIndex == SIZE_MAX - 1) {
		// Jumbo allocation
		return pool->end - pool->start;
	}
	else {
		// Small allocation
		struct pagemap_t* pageMap = NULL;

		// Find the specific page and index of this allocation
		int64_t index = find_small_ptr((const byte*)ptr, pool, &pageMap);

		if (index < 0) {
			// Not a valid pointer
			return 0;
		}

		// Mask out the low order status bits before returning size
		return (pageMap->allocSize & ~SEVEN64);
	}
}

/*** Deprecated malloc API - only included when not using FF prefix ***/
#ifndef USE_FF_PREFIX
// Allocates size bytes. The returned address will be page size aligned
// Equivalent to memalign(PAGE_SIZE, size)
void* valloc(size_t size) {
	return ffmemalign(PAGE_SIZE, size);
}

// Rounds size up to a multiple of PAGE_SIZE. Returned address will be
// page size aligned
void* pvalloc(size_t size) {
	if(size >= SIZE_MAX - PAGE_SIZE) {
		return NULL;
	}
	return ffmemalign(PAGE_SIZE, ALIGN_TO(size, PAGE_SIZE));
}
#endif

/*** FFMalloc extended API ***/

// Duplicates the string into memory allocated by ffmalloc. The caller is
// responsible for calling fffree
char* ffstrdup(const char* s) {
	if(s == NULL) {
		return NULL;
	}

	size_t length = strlen(s) + 1;
	char* newString = (char*)ffmalloc(length);
	if(newString != NULL) {
		// Visual C does *not* like strcpy, but we need to be portable so get the
		// compiler to quit complaining just this one time
#pragma warning( push )
#pragma warning( disable : 4996 )
		strcpy(newString, s);
#pragma warning( pop )
		return newString;
	}

	errno = ENOMEM;
	return NULL;
}

// Duplicates the first n characters of the string into memory allocated by
// ffmalloc. The caller is responsible for calling fffree
char* ffstrndup(const char* s, size_t n) {
	if(s == NULL || n == SIZE_MAX) {
		return NULL;
	}

	char* newString = (char*)ffmalloc(n + 1);
	if(newString != NULL) {
#pragma warning( push )
#pragma warning( disable : 4996 )
		strncpy(newString, s, n);
#pragma warning( pop )

		// strncpy may not null terminate the string if there is no
		// null byte in the first n characters of s
		newString[n] = '\0';
		return newString;
	}

	errno = ENOMEM;
	return NULL;
}

#ifdef FF_PROFILE
// Gets usage statistics for ffmalloc excluding custom arenas
ffresult_t ffget_statistics(ffprofile_t* profile) {
	if(profile == NULL) {
		return FFBAD_PARAM;
	}

	memcpy(profile, &arenas[0]->profile, sizeof(ffprofile_t));

	return FFSUCCESS;
}

// Gets usage statistics for a custom arena
ffresult_t ffget_arena_statistics(ffprofile_t* profile, ffarena_t arenaKey) {
	// Ensure that the arena key is in range and exists
	if(arenaKey == 0 || arenaKey >= MAX_ARENAS || arenas[arenaKey] == NULL) {
		return FFBAD_ARENA;
	}

	if(profile == NULL) {
		return FFBAD_PARAM;
	}

	memcpy(profile, &arenas[arenaKey]->profile, sizeof(ffprofile_t));

	return FFSUCCESS;
}

// Gets combined usage statistics for all arenas active or destroyed plus the
// default allocation arena. Caller is responsible for freeing the returned
// structure
/* Not yet implemented. Need destroy_arena to save results to new global counter
ffresult_t ffget_global_statistics(ffprofile_t* profile) {
	if(profile == NULL) {
		return FFBAD_PARAM;
	}

	return FFSUCCESS;
}*/
#endif

// Creates a new allocation arena
ffresult_t ffcreate_arena(ffarena_t* newArenaKey) {
	// First make sure we've got some place to return this arena to
	if(newArenaKey == NULL) {
		return FFBAD_PARAM;
	}

	// Reserve metadata space for the arena
	struct arena_t* newArena = (struct arena_t*)ffmetadata_alloc(sizeof(struct arena_t));

	// Find a free slot in the arena array
	for(ffarena_t i = 1; i < MAX_ARENAS; i++) {
		if(arenas[i] == NULL) {
			// Found a slot, try and claim it
			if(FFAtomicCompareExchangePtr(&arenas[i], newArena, NULL)) {
				// Slot succesfully claimed
				ffresult_t result = create_arena(arenas[i]);
				if(result == FFSUCCESS) {
					*newArenaKey = i;
				}
				return result;
			}
		}
	}

	// No free slots left to put a new arena in
	ffmetadata_free(newArena, sizeof(struct arena_t));
	return FFMAX_ARENAS;
}

// Frees all memory allocated from a specific arena and then destroys the arena
ffresult_t ffdestroy_arena(ffarena_t arena) {
	// Ensure that the arena key is in range and exists. Also note that
	// destroying the default arena is not allowed
	if(arena == 0 || arena >= MAX_ARENAS || arenas[arena] == NULL) {
		return FFBAD_ARENA;
	}

	// No attempt at thread safety - caller is responsible for ensuring
	// this is called only once when finished
	destroy_arena(arenas[arena]);
	arenas[arena] = NULL;

	return FFSUCCESS;
}

// Allocates memory with the same algorithm as ffmalloc but from a custom arena
ffresult_t ffmalloc_arena(ffarena_t arenaKey, void** ptr, size_t size) {
	struct arena_t* arena = NULL;

	// Ensure the out pointer parameter is valid
	if(ptr == NULL) {
		return FFBAD_PARAM;
	}

	// Check that the arena key is in range and exists. Technically,
	// nothing bad would happen by allowing allocation out of the default
	// arena here. However, it would violate the spirit of the API which is
	// that the arena key should be generated by ffcreate_arena. Second, 
	// the caller should not depend on the default arena being zero since
	// that's an internal implementation detail. Lastly, it would violate 
	// principle of least surprise since zero definitely can't be used with
	// ffdestroy_arena and the caller may be confused that zero can be
	// allocated from but not destroyed
	if(arenaKey == 0 || arenaKey >= MAX_ARENAS || arenas[arenaKey] == NULL) {
		return FFBAD_ARENA;
	}
	else {
		arena = arenas[arenaKey];
	}
	
	// Prohibit zero byte allocations. It can't be realloc'ed to bigger
	// than 8 anyways without a copy so just ask for what you need to start
	// Also protect against overflow due to alignment below
	if(size == 0 || size > SIZE_MAX - MIN_ALIGNMENT) {
		return FFBAD_PARAM;
	}

#ifdef FF_PROFILE
	FFAtomicIncrement(arena->profile.mallocCount);
	FFAtomicAdd(arena->profile.totalBytesRequested, size);
#endif
	// Round size up to a multiple of 8 if needed
	size = ALIGN_SIZE(size);

	// Allocate from the right pool in the requested arena
	if(size <= HALF_PAGE) {
		*ptr = ffmalloc_small(size, arena);
	}
	else if(size < (POOL_SIZE - HALF_PAGE)) {
		*ptr = ffmalloc_large(size, MIN_ALIGNMENT, arena);
	}
	else {
		*ptr = ffmalloc_jumbo(size, arena);
	}

	return *ptr == NULL ? FFNOMEM : FFSUCCESS;
}


//#ifdef _DEBUG
/**
 Frees all data and metadata allocated by an ffmalloc family function
 */
void fffree_all() {
	for (size_t l1 = 0; l1 < STEM_COUNT; l1++) {
		if (poolTree.stems[l1] != NULL) {
			for (size_t l2 = 0; l2 < LEAVES_PER_STEM; l2++) {
				struct radixleaf_t* leaf = poolTree.stems[l1]->leaves[l2];
				if (leaf != NULL) {
					for (size_t l3 = 0; l3 < POOLS_PER_LEAF; l3++) {
						if(leaf->poolStart[l3] != NULL) {
							os_free(leaf->poolStart[l3]->start);
							os_free(leaf->poolStart[l3]->tracking.pageMaps);
						}
					}
				}
			}
		}
	}
}

void ffdump_pool_details() {
	printf("alloc count: %ld\n", os_alloc_count);
	printf("alloc amount %ld\n", os_alloc_total);
	printf("free count %ld\n", os_free_count);
	for (size_t l1 = 0; l1 < STEM_COUNT; l1++) {
		if (poolTree.stems[l1] != NULL) {
			for (size_t l2 = 0; l2 < LEAVES_PER_STEM; l2++) {
				struct radixleaf_t* leaf = poolTree.stems[l1]->leaves[l2];
				if (leaf != NULL) {
					for (size_t l3 = 0; l3 < POOLS_PER_LEAF; l3++) {
						if (leaf->poolStart[l3] != NULL) {
							size_t released = 0;
							size_t pending = 0;
							size_t inuse = 0;
							size_t tcache = 0;
							struct pagepool_t* pool = leaf->poolStart[l3];
							//printf("Pool start: %p ", pool->start);
							if (pool->nextFreeIndex == SIZE_MAX) {
								byte* lastFreePage = pool->end < pool->nextFreePage ? pool->end : pool->nextFreePage;
								for (size_t x = 0; x < (lastFreePage - pool->start) / PAGE_SIZE; x++) {
									if ((pool->tracking.pageMaps[x].allocSize & THREE64) == 3) {
										released++;
									}
									else if ((pool->tracking.pageMaps[x].allocSize & THREE64) == 1) {
										pending++;
									}
									else if (pool->tracking.pageMaps[x].allocSize == 0) {
										tcache++;
									}
									else {
										inuse++;
									}
								}
								size_t unassigned = (pool->end - lastFreePage) / PAGE_SIZE;
								//if (pending > 0 || inuse > 0 || unassigned > 0 || tcache > 0) {
									printf("Small pool addr: %p with %ld pages unassigned, ", pool->start, unassigned);
									printf("%ld pending free, ", pending);
									printf("%ld freed, ", released);
									printf("%ld in tcache reserve, ", tcache);
									printf("%ld in use\n", inuse);
								//}
									if (released == 1024) {
										printf("startInUse: %p endInUse: %p\n", pool->startInUse, pool->endInUse);
									}
							}
							else if (pool->nextFreeIndex == SIZE_MAX - 1) {
								printf("Jumbo pool start: %p\n", pool->start);
							}
							else {
								printf("Large pool start: %p with %ld bytes free\n", pool->start, (uintptr_t)pool->end - pool->tracking.allocations[pool->nextFreeIndex]);
							}
						}
					}
				}
			}
		}
	}
}

/**
 Gets the number of pools currently active
 @return The number of pools ffmalloc has currently in use
 */
size_t ffget_pool_count() {
	return poolCount;
}

#ifdef FF_PROFILE
void ffprint_stats_wrapper(void) {
	ffprint_statistics(stderr);
}

#ifdef _WIN64
void ffprint_statistics(FILE * const dest) {
	ffprofile_t* stats = &arenas[0]->profile;
	fprintf(dest, "*** FFMalloc Stats ***\n");
    fprintf(dest, "Malloc:         %lld\n", stats->mallocCount);
    fprintf(dest, "Realloc:        %lld\n", stats->reallocCount);
    fprintf(dest, "Calloc:         %lld\n", stats->callocCount);
    fprintf(dest, "Free:           %lld\n", stats->freeCount);
    fprintf(dest, "POSIX Align:    %lld\n", stats->posixAlignCount);
    fprintf(dest, "Alloc Align:    %lld\n", stats->allocAlignCount);
    fprintf(dest, "TotBytes Reqst: %lld\n", stats->totalBytesRequested);
    fprintf(dest, "TotBytes Alloc: %lld\n", stats->totalBytesAllocated);
    fprintf(dest, "CurBytes Alloc: %lld\n", stats->currentBytesAllocated);
    fprintf(dest, "MaxBytes Alloc: %lld\n", stats->maxBytesAllocated);
    fprintf(dest, "CurOSBytes Map: %lld\n", stats->currentOSBytesMapped);
    fprintf(dest, "MaxOSBytes Map: %lld\n\n", stats->maxOSBytesMapped);
}
#endif


#ifdef FF_PROFILE
void ffprint_statistics(FILE * const dest) {
	ffprofile_t* stats = &arenas[0]->profile;
	fprintf(dest, "*** FFMalloc Stats ***\n");
	fprintf(dest, "Malloc:         %ld\n", stats->mallocCount);
	fprintf(dest, "Realloc:        %ld\n", stats->reallocCount);
#ifdef FF_GROWLARGEREALLOC
	fprintf(dest, "Realloc Grow:   %ld\n", stats->reallocCouldGrow);
#endif
	fprintf(dest, "Calloc:         %ld\n", stats->callocCount);
	fprintf(dest, "Free:           %ld\n", stats->freeCount);
	fprintf(dest, "POSIX Align:    %ld\n", stats->posixAlignCount);
	fprintf(dest, "Alloc Align:    %ld\n", stats->allocAlignCount);
	fprintf(dest, "TotBytes Reqst: %ld\n", stats->totalBytesRequested);
	fprintf(dest, "TotBytes Alloc: %ld\n", stats->totalBytesAllocated);
	fprintf(dest, "CurBytes Alloc: %ld\n", stats->currentBytesAllocated);
	fprintf(dest, "MaxBytes Alloc: %ld\n", stats->maxBytesAllocated);
	fprintf(dest, "CurOSBytes Map: %ld\n", stats->currentOSBytesMapped);
	fprintf(dest, "MaxOSBytes Map: %ld\n", stats->maxOSBytesMapped);

	struct rusage usage;
	getrusage(RUSAGE_SELF, &usage);
	fprintf(dest, "Linux MaxRSS:   %ld\n\n", usage.ru_maxrss * 1024L);
}
#endif

// Prints current usage statistics to the specified file each time the cummulative
// number of calls to malloc/calloc/realloc (that caused a malloc) is a multiple
// of interval
void ffprint_usage_on_interval(FILE * const dest, unsigned int interval) {
	usagePrintFile = dest;
	if (interval == 0) {
		usagePrintInterval = INT_MAX;
	}
	else {
		usagePrintInterval = interval;
	}
}

static void print_current_usage() {
	// Should print: OS mem, current physical bytes, current alloc bytes, free bytes need release
	// free bytes awaiting assign
	size_t releasedPages = 0;
	size_t pendingReleasePages = 0;
	size_t pendingReleaseLargeBytes = 0;
	size_t tcachePages = 0;
	size_t inusePages = 0;
	size_t unassignedPages = 0;
	size_t unassignedLargeBytes = 0;
	size_t currentOSReported = 0;
	size_t smallFreeOnInUsePage = 0;
	size_t poolMetadata = 0;
	size_t smallPageWaste = 0;
	size_t smallPoolCount = 0;
	size_t largePoolCount = 0;
	size_t jumboPoolCount = 0;
	size_t largePoolAssigned = 0;
	size_t numEmptyLargePool = 0;

	if (usagePrintFile != NULL && (arenas[0]->profile.mallocCount % usagePrintInterval == 0)) {
		for (size_t l1 = 0; l1 < STEM_COUNT; l1++) {
			if (poolTree.stems[l1] != NULL) {
				for (size_t l2 = 0; l2 < LEAVES_PER_STEM; l2++) {
					struct radixleaf_t* leaf = poolTree.stems[l1]->leaves[l2];
					if (leaf != NULL) {
						for (size_t l3 = 0; l3 < POOLS_PER_LEAF; l3++) {
							if (leaf->poolStart[l3] != NULL) {
								struct pagepool_t* pool = leaf->poolStart[l3];
								if (pool->nextFreeIndex == SIZE_MAX) {
									// Small pool
									size_t poolInUsePages = 0;
									size_t smallNeedsReleasePages = 0;
									smallPoolCount++;
									poolMetadata += POOL_SIZE / PAGE_SIZE * sizeof(struct pagemap_t);
									byte* lastFreePage = pool->end < pool->nextFreePage ? pool->end : pool->nextFreePage;
									for (size_t x = 0; x < (lastFreePage - pool->start) / PAGE_SIZE; x++) {
										if ((pool->tracking.pageMaps[x].allocSize & THREE64) == 3) {
											releasedPages++;
										}
										else if ((pool->tracking.pageMaps[x].allocSize & THREE64) == 1) {
											pendingReleasePages++;
										}
										else if (pool->tracking.pageMaps[x].allocSize == 0) {
											tcachePages++;
										}
										else {
											inusePages++;
											poolInUsePages++;
											size_t allocSize = (pool->tracking.pageMaps[x].allocSize & ~SEVEN64);
											size_t maxAlloc = PAGE_SIZE / allocSize;
											smallPageWaste += PAGE_SIZE - (maxAlloc * allocSize);
											if (allocSize >= 64) {
												size_t count = FFPOPCOUNT64(pool->tracking.pageMaps[x].bitmap.single);
												smallFreeOnInUsePage += ((maxAlloc - count) * allocSize);
												if(count == 0) {
													smallNeedsReleasePages++;
												}
											}
											else {
												size_t bitmapCount = (maxAlloc & SIXTYTHREE64) ?
													(maxAlloc >> 6) + 1 : (maxAlloc >> 6);
												size_t totalCount = 0;
												for (size_t index = 0; index < bitmapCount; index++) {
													size_t count = FFPOPCOUNT64(pool->tracking.pageMaps[x].bitmap.array[index]);
													totalCount += count;
													if (index != (bitmapCount - 1)) {
														smallFreeOnInUsePage += (64 - count) * allocSize;
													}
													else {
														size_t lastBitmapMax = maxAlloc - ((bitmapCount - 1) * 64);
														smallFreeOnInUsePage += (lastBitmapMax - count) * allocSize;
													}
												}
												if(totalCount == 0) {
													smallNeedsReleasePages++;
												}
											}
										}
									}
									unassignedPages += (pool->end - lastFreePage) / PAGE_SIZE;
									/*if(unassignedPages == 0 && smallNeedsReleasePages >= 1024) {
										fprintf(stderr, "Small pool empty: %p\n", pool);
										abort();
									}*/
								}
								else if (pool->nextFreeIndex == SIZE_MAX - 1) {
									// Jumbo pool
									jumboPoolCount++;
								}
								else {
									// Large pool
									largePoolCount++;
									poolMetadata += (POOL_SIZE >> 20) * PAGE_SIZE;
									size_t thisPoolInUse = 0;
									for (size_t index = 0; index < pool->nextFreeIndex; index++) {
										if ((pool->tracking.allocations[index] & 2) == 2) {
											// Freed and (at least partially) returned
										}
										else if ((pool->tracking.allocations[index] & 3) == 1) {
											// Freed pending return
											pendingReleaseLargeBytes += ((pool->tracking.allocations[index + 1] & ~SEVEN64) -
												(pool->tracking.allocations[index] & ~SEVEN64));
										}
										else {
											thisPoolInUse += (pool->tracking.allocations[index + 1] & ~SEVEN64) - pool->tracking.allocations[index];	
										}
									}
									if(thisPoolInUse == 0) {
										numEmptyLargePool++;
										/*fprintf(stderr, "Empty pool: %p\n", pool);
										if(numEmptyLargePool > 4) {
											abort();
										}*/
									}
									largePoolAssigned += thisPoolInUse;

									if ((uintptr_t)pool->end > pool->tracking.allocations[pool->nextFreeIndex]) {
										unassignedLargeBytes += ((uintptr_t)pool->end - (pool->tracking.allocations[pool->nextFreeIndex] & ~SEVEN64));
									}
								}
							}
						}
					}
				}
			}
		}

#ifdef _WIN64
		PROCESS_MEMORY_COUNTERS pmc;
		if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
			currentOSReported = pmc.PagefileUsage;
			peakOSReported = pmc.PeakPagefileUsage;
		}
		char* fmtString = "%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld\n";
#else
		// This all is only valid so long as large OS pages are not supported
		FILE* stat = fopen("/proc/self/statm", "r");
		if (stat) {
			fscanf(stat, "%lu ", &currentOSReported);
			fclose(stat);
			currentOSReported *= 4096;
		}
		char* fmtString = "%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld\n";
#endif

		fprintf(usagePrintFile, fmtString, //peakOSReported,
			arenas[0]->profile.mallocCount,
			arenas[0]->profile.reallocCount,
			currentOSReported,
			arenas[0]->profile.currentOSBytesMapped, 
			arenas[0]->profile.currentBytesAllocated,
			poolMetadata,
			smallPageWaste,
			smallFreeOnInUsePage,
			pendingReleasePages * PAGE_SIZE, 
			pendingReleaseLargeBytes,
			(unassignedPages + tcachePages) * PAGE_SIZE, 
			unassignedLargeBytes,
			largePoolAssigned,
			smallPoolCount, largePoolCount, jumboPoolCount,
			numEmptyLargePool);
	}
}
#endif
