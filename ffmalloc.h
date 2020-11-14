// Header file for FFMalloc

#pragma once
#ifdef __cplusplus
extern "C" {
#endif

// Need size_t
#include <sys/types.h>

#ifdef FF_INSTRUMENTED
#define FF_INTERVAL 5000
#ifndef FF_PROFILE
#define FF_PROFILE
#endif
#endif

#ifdef FF_PROFILE
// Need FILE
#include <stdio.h>
#endif

// When compiling FFMalloc as a Windows DLL decorate the public API
// functions with the needed symbols to export them through the link
// library. Exclude these symbols on non-Windows or a Windows static
// library with no threading support. Lastly, when used with a 
// Windows application linking against the FFMalloc DLL, decorate
// the API with the symbols needed for import
#ifdef _WIN64
#define USE_FF_PREFIX
#ifdef FFMALLOC_EXPORTS
#define FFMALLOC_API __declspec(dllexport)
#elif !defined(FFSINGLE_THREADED)
#define FFMALLOC_API __declspec(dllimport)
#else
#define FFMALLOC_API
#endif
#else
#define FFMALLOC_API
#endif


// When USE_FF_PREFIX is not defined, the public API will match the names
// of the standard allocation functions. Useful when using LD_PRELOAD to 
// force an existing binary on Linux to use this allocator
#ifndef USE_FF_PREFIX
#define ffmalloc             malloc
#define ffrealloc            realloc
#define ffreallocarray       reallocarray
#define ffcalloc             calloc
#define fffree               free
#define ffmemalign           memalign
#define ffposix_memalign     posix_memalign
#define ffaligned_alloc      aligned_alloc
#define ffmalloc_usable_size malloc_usable_size
#ifdef FF_WRAP_MMAP
#define ffmmap               mmap
#define ffmunmap             munmap	
#endif
#endif

/*** Custom types for the extended API functions ***/

// The returned success or error message from an extended API function
typedef unsigned int ffresult_t;

// Handle to a custom arena
typedef unsigned int ffarena_t;

#ifdef FF_PROFILE
typedef struct ffprofiling_struct {
	// The number of times that ffmalloc has been called including
	// indirectly through ffrealloc, ffcalloc, or similar
	size_t mallocCount;

	// The number of times that ffrealloc has been called
	size_t reallocCount;

	// The number of times that ffreallocarray has been called
	size_t reallocarrayCount;

	// The number of times that ffcalloc has been called
	size_t callocCount;

	// The number of times that fffree has been called including
	// indirectly through ffrealloc
	size_t freeCount;

	// The number of times that ffposix_memalign has been called
	size_t posixAlignCount;

	// The number of times that ffallign_alloc has been called
	size_t allocAlignCount;

	// The total number of bytes requested by as measured by ffmalloc
	// This will exclude whenever ffrealloc is called with a size less
	// than the current allocation size
	size_t totalBytesRequested;

	// The total number of bytes in memory consumed by allocations after
	// adjusting requested sizes upwards for required alignments
	size_t totalBytesAllocated;

	// The number of bytes in memory associated with unfreed allocations
	// at this point in time. This does not include "lost" bytes that have
	// been fffree'd but whose pages have not yet been returned to the OS
	size_t currentBytesAllocated;

	// The highest seen value for currentBytesAllocated
	size_t maxBytesAllocated;

	// The sum of the sizes of all allocation ranges currently in use even
	// if not yet faulted and mapped. Excludes pages mapped for metadata
	size_t currentOSBytesMapped;

	// The highest value for currentOSBytesMapped seen
	size_t maxOSBytesMapped;
	size_t reallocCouldGrow;
} ffprofile_t;
#endif

/*** Extended API error codes ***/

// Returned when the function completed successfully. Any out parameters will
// have valid values
#define FFSUCCESS 0

// The supplied arena key was not created by ffcreate_arena or has already
// been destroyed
#define FFBAD_ARENA 1U

// No additional arenas can be created because the limit has been reached
#define FFMAX_ARENAS 2U

// An additional arena could not be created because FFMalloc could not
// get the required pages allocated from the OS
#define FFNOMEM 3U

// An additional arena could not be created because a system limitation
// other than memory was reached, probably thread local storage indexes
#define FFSYS_LIMIT 4U

// A supplied parameter could not be validated, usually an out parameter
// pointer that is NULL
#define FFBAD_PARAM 5U

/*** Declare standard malloc API functions ***/
FFMALLOC_API void* ffmalloc(size_t size);
FFMALLOC_API void* ffrealloc(void* ptr, size_t size);
FFMALLOC_API void* ffreallocarray(void* ptr, size_t nmemb, size_t size);
FFMALLOC_API void* ffcalloc(size_t nmemb, size_t size);
FFMALLOC_API void fffree(void* ptr);
FFMALLOC_API void* ffmemalign(size_t alignment, size_t size);
FFMALLOC_API int ffposix_memalign(void **ptr, size_t alignment, size_t size);
FFMALLOC_API void* ffaligned_alloc(size_t alignment, size_t size);
FFMALLOC_API size_t ffmalloc_usable_size(const void* ptr);

/*** Deprecated malloc API - only included in no-prefix mode ***/
#ifndef FF_USE_PREFIX
FFMALLOC_API void* valloc(size_t size);
FFMALLOC_API void* pvalloc(size_t size);
#endif

/*** Optionally wrap mmap ***/
#ifdef FF_WRAP_MMAP
void* ffmmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int ffmunmap(void* addr, size_t length);
#endif

/*** Declare FFMalloc extended API ***/

// Duplicates a string. Memory is allocated from ffmalloc so the caller is
// responsible for fffreeing the string
FFMALLOC_API char* ffstrdup(const char* s);

// Duplicates the first n characters of a string. Memory is allocated 
// from ffmalloc so the caller must fffree the string when finished
FFMALLOC_API char* ffstrndup(const char* s, size_t n);

// Creates a new allocation arena
FFMALLOC_API ffresult_t ffcreate_arena(ffarena_t* newArena);

// Destroys an allocation arena and frees all memory allocated from it
FFMALLOC_API ffresult_t ffdestroy_arena(ffarena_t arenaKey);

// Allocates memory in the same manner as ffmalloc except from a specific arena
FFMALLOC_API ffresult_t ffmalloc_arena(ffarena_t arenaKey, void** ptr, size_t size);

#ifdef FF_PROFILE
// Gets usage statistics for ffmalloc excluding custom arenas
FFMALLOC_API ffresult_t ffget_statistics(ffprofile_t* profileDestination);

// Gets usage statistics for a custom arena
FFMALLOC_API ffresult_t ffget_arena_statistics(ffprofile_t* profileDestination, ffarena_t arenaKey);

// Gets combined usage statistics for all arenas active or destroyed plus the
// default allocation arena. 
// *** Not implemented yet ***
//FFMALLOC_API ffresult_t ffget_global_statistics(ffprofile_t* profileDestination);

// Outputs the same statistics as ffget_statistics to the supplied file
FFMALLOC_API void ffprint_statistics(FILE * const dest);

// Prints current usage statistics to the specified file each time the cummulative
// number of calls to malloc/calloc/realloc (that caused a malloc) is a multiple
// of interval
FFMALLOC_API void ffprint_usage_on_interval(FILE * const dest, unsigned int interval);
#endif

//#ifdef _DEBUG
FFMALLOC_API void fffree_all();
FFMALLOC_API size_t ffget_pool_count();
FFMALLOC_API void ffdump_pool_details();
//#endif // DEBUG

#ifdef __cplusplus
}
#endif
