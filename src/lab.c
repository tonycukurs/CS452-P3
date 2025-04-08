#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg) \
    do                            \
    {                             \
        perror(msg);              \
        raise(SIGKILL);           \
    } while (0)

/**
 * @brief Convert bytes to the correct K value
 *
 * @param bytes the number of bytes
 * @return size_t the K value that will fit bytes
 */
size_t btok(size_t bytes)
{
    // DO NOT use math.pow
    size_t k = 0;
    size_t size = 1;
    
    while (size < bytes) {
        size *= 2;
        k++;
    }
    
    return k;
}

/**
 * @brief Calculate the buddy of a block
 * According to paper formula: buddy_k(x) = x + 2^k (if x mod 2^(k+1) = 0) or x - 2^k (if x mod 2^(k+1) = 2^k)
 * This can be implemented using a simple XOR operation as mentioned in exercise 28 of the paper
 *
 * @param pool The memory pool
 * @param block The block to find the buddy of
 * @return struct avail* Pointer to the buddy block
 */
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block)
{
    size_t k = block->kval;
    size_t block_size = (1UL << k); // 2^k
    uintptr_t block_addr = (uintptr_t)block;
    uintptr_t base_addr = (uintptr_t)pool->base;
    
    // Calculate the offset from the base
    uintptr_t offset = block_addr - base_addr;
    
    // Calculate the buddy's offset using XOR with 2^k (formula from the paper)
    uintptr_t buddy_offset = offset ^ block_size;
    
    // Return the buddy's address
    return (struct avail *)(base_addr + buddy_offset);
}

void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    // Check for zero size first
    if (size == 0) {
        return NULL;
    }
    
    // Get the kval for the requested size with enough room for the header
    size_t req_size = size + sizeof(struct avail);
    size_t k = btok(req_size);
    
    if (k < MIN_K)
        k = MIN_K;
    
    // R1. [Find block.] Find smallest j where k ≤ j ≤ m for which AVAIL[j] list is not empty
    size_t j = k;
    while (j <= pool->kval_m && pool->avail[j].next == &pool->avail[j]) {
        j++;  // Move to next size if this list is empty
    }
    
    // There was not enough memory to satisfy the request
    if (j > pool->kval_m) {
        errno = ENOMEM;
        return NULL;
    }
    
    // R2. [Remove from list.] 
    // Set L ← AVAILF[j], P ← LINKF(L), AVAILF[j] ← P, LINKB(P) ← LOC(AVAIL[j]), and TAG(L) ← 0
    struct avail *L = pool->avail[j].next;
    struct avail *P = L->next;
    pool->avail[j].next = P;
    P->prev = &pool->avail[j];
    L->tag = 0;  // TAG(L) ← 0 (reserved)
    
    // R3. [Split required?] If j = k, done (found and reserved a block)
    while (j > k) {
        // R4. [Split.] Decrease j by 1, then split
        j--;
        size_t buddy_size = (1UL << j);
        struct avail *buddy = (struct avail *)((char *)L + buddy_size);
        
        // Initialize buddy block as specified in the paper
        buddy->tag = 1;  // TAG(P) ← 1 (available)
        buddy->kval = j;
        
        // Add buddy to appropriate availability list
        // LINKF(P) ← LINKB(P) ← LOC(AVAIL[j]), AVAILF[j] ← AVAILB[j] ← P
        buddy->next = pool->avail[j].next;
        buddy->prev = &pool->avail[j];
        pool->avail[j].next->prev = buddy;
        pool->avail[j].next = buddy;
    }
    
    // Ensure block has the final size stored
    L->kval = k;
    
    // Return pointer to user memory (after the header)
    return (void *)(L + 1);
}

void buddy_free(struct buddy_pool *pool, void *ptr)
{
    if (!ptr) return;  // Handle NULL pointer
    
    // Get block header from user pointer
    struct avail *L = (struct avail *)((char *)ptr - sizeof(struct avail));
    
    // Validate that this is a reserved block
    if (L->tag != 0) {  // TAG(P) = 0 for reserved blocks
        // This is a double free or invalid pointer
        return;
    }
    
    size_t k = L->kval;
    
    // S1. [Is buddy available?] 
    while (k < pool->kval_m) {
        struct avail *P = buddy_calc(pool, L);
        
        // If k = m or TAG(P) = 0 or (TAG(P) = 1 and KVAL(P) ≠ k), go to S3
        if (P->tag != 1 || P->kval != k) {
            break;  // Buddy not available or wrong size
        }
        
        // S2. [Combine with buddy.]
        // Remove block P from the AVAIL[k] list
        P->prev->next = P->next;
        P->next->prev = P->prev;
        
        // Set k ← k + 1, and if P < L set L ← P
        k++;
        if (P < L) {
            L = P;
        }
        
        // Return to S1
    }
    
    // S3. [Put on list.] 
    // Set TAG(L) ← 1, P ← AVAILF[k], LINKF(L) ← P, LINKB(P) ← L, 
    // KVAL(L) ← k, LINKB(L) ← LOC(AVAIL[k]), AVAILF[k] ← L
    L->tag = 1;  // TAG(L) ← 1 (available)
    L->kval = k;
    
    // Add block to the appropriate availability list
    struct avail *P = pool->avail[k].next;
    L->next = P;
    P->prev = L;
    L->prev = &pool->avail[k];
    pool->avail[k].next = L;
}

/**
 * @brief This is a simple version of realloc.
 *
 * @param pool The memory pool
 * @param ptr  The user memory
 * @param size the new size requested
 * @return void* pointer to the new user memory
 */
void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
{
    // Required for Grad Students
    // Optional for Undergrad Students
    if (!ptr) {
        return buddy_malloc(pool, size);
    }
    
    if (size == 0) {
        buddy_free(pool, ptr);
        return NULL;
    }
    
    // Get the original block and its size
    struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));
    size_t old_k = block->kval;
    size_t old_size = (1UL << old_k) - sizeof(struct avail);
    
    // Calculate required k-value for new size
    size_t req_size = size + sizeof(struct avail);
    size_t new_k = btok(req_size);
    if (new_k < MIN_K) new_k = MIN_K;
    
    // If new size fits within current block, just return the original pointer
    if (new_k <= old_k) {
        return ptr;
    }
    
    // Allocate new larger block
    void *new_ptr = buddy_malloc(pool, size);
    if (!new_ptr) {
        return NULL;  // Failed to allocate
    }
    
    // Copy old data to new block and free old block
    memcpy(new_ptr, ptr, old_size);
    buddy_free(pool, ptr);
    
    return new_ptr;
}

void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = 0;
    if (size == 0)
        kval = DEFAULT_K;
    else
        kval = btok(size);

    if (kval < MIN_K)
        kval = MIN_K;
    if (kval > MAX_K)
        kval = MAX_K - 1;

    // Make sure pool struct is cleared out
    memset(pool, 0, sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);
    
    // Memory map a block of raw memory to manage
    pool->base = mmap(
        NULL,                              /* addr to map to */
        pool->numbytes,                    /* length */
        PROT_READ | PROT_WRITE,            /* prot */
        MAP_PRIVATE | MAP_ANONYMOUS,       /* flags */
        -1,                                /* fd -1 when using MAP_ANONYMOUS */
        0                                  /* offset 0 when using MAP_ANONYMOUS */
    );
    if (MAP_FAILED == pool->base)
    {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    // Initialize lists for each size according to paper equations (13) and (14)
    for (size_t i = 0; i <= kval; i++)
    {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;  // Change to use 0/1 values if preferred
    }

    // Add in the first block as in paper equation (13)
    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = 1;  // TAG(0) = 1 (available)
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval)
    {
        handle_error_and_die("buddy_destroy avail array");
    }
    // Zero out the array so it can be reused if needed
    memset(pool, 0, sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x

/**
 * This function can be useful to visualize the bits in a block. This can
 * help when figuring out the buddy_calc function!
 */
static void printb(unsigned long int b)
{
     size_t bits = sizeof(b) * 8;
     unsigned long int curr = UINT64_C(1) << (bits - 1);
     for (size_t i = 0; i < bits; i++)
     {
          if (b & curr)
          {
               printf("1");
          }
          else
          {
               printf("0");
          }
          curr >>= 1L;
     }
}