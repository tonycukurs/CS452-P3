#include <assert.h>
#include <stdlib.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include "harness/unity.h"
#include "../src/lab.h"


void setUp(void) {
  // set stuff up here
}

void tearDown(void) {
  // clean stuff up here
}



/**
 * Check the pool to ensure it is full.
 */
void check_buddy_pool_full(struct buddy_pool *pool)
{
  //A full pool should have all values 0-(kval-1) as empty
  for (size_t i = 0; i < pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }

  //The avail array at kval should have the base block
  assert(pool->avail[pool->kval_m].next->tag == BLOCK_AVAIL);
  assert(pool->avail[pool->kval_m].next->next == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].prev->prev == &pool->avail[pool->kval_m]);

  //Check to make sure the base address points to the starting pool
  //If this fails either buddy_init is wrong or we have corrupted the
  //buddy_pool struct.
  assert(pool->avail[pool->kval_m].next == pool->base);
}

/**
 * Check the pool to ensure it is empty.
 */
void check_buddy_pool_empty(struct buddy_pool *pool)
{
  //An empty pool should have all values 0-(kval) as empty
  for (size_t i = 0; i <= pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }
}

/**
 * Test allocating 1 byte to make sure we split the blocks all the way down
 * to MIN_K size. Then free the block and ensure we end up with a full
 * memory pool again
 */
void test_buddy_malloc_one_byte(void)
{
  fprintf(stderr, "->Test allocating and freeing 1 byte\n");
  struct buddy_pool pool;
  int kval = MIN_K;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  void *mem = buddy_malloc(&pool, 1);
  //Make sure correct kval was allocated
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests the allocation of one massive block that should consume the entire memory
 * pool and makes sure that after the pool is empty we correctly fail subsequent calls.
 */
void test_buddy_malloc_one_large(void)
{
  fprintf(stderr, "->Testing size that will consume entire memory pool\n");
  struct buddy_pool pool;
  size_t bytes = UINT64_C(1) << MIN_K;
  buddy_init(&pool, bytes);

  //Ask for an exact K value to be allocated. This test makes assumptions on
  //the internal details of buddy_init.
  size_t ask = bytes - sizeof(struct avail);
  void *mem = buddy_malloc(&pool, ask);
  assert(mem != NULL);

  //Move the pointer back and make sure we got what we expected
  struct avail *tmp = (struct avail *)mem - 1;
  assert(tmp->kval == MIN_K);
  assert(tmp->tag == BLOCK_RESERVED);
  check_buddy_pool_empty(&pool);

  //Verify that a call on an empty tool fails as expected and errno is set to ENOMEM.
  void *fail = buddy_malloc(&pool, 5);
  assert(fail == NULL);
  assert(errno = ENOMEM);

  //Free the memory and then check to make sure everything is OK
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests to make sure that the struct buddy_pool is correct and all fields
 * have been properly set kval_m, avail[kval_m], and base pointer after a
 * call to init
 */
void test_buddy_init(void)
{
  fprintf(stderr, "->Testing buddy init\n");
  //Loop through all kval MIN_k-DEFAULT_K and make sure we get the correct amount allocated.
  //We will check all the pointer offsets to ensure the pool is all configured correctly
  for (size_t i = MIN_K; i <= DEFAULT_K; i++)
    {
      size_t size = UINT64_C(1) << i;
      struct buddy_pool pool;
      buddy_init(&pool, size);
      check_buddy_pool_full(&pool);
      buddy_destroy(&pool);
    }
}

/**
 * Tests multiple allocations and fragmentation.
 */
void test_buddy_multiple_allocations(void) {
  fprintf(stderr, "->Testing multiple allocations and fragmentation\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << MIN_K;
  buddy_init(&pool, size);
  
  // Allocate several small blocks
  void *ptr1 = buddy_malloc(&pool, 100);
  void *ptr2 = buddy_malloc(&pool, 200);
  void *ptr3 = buddy_malloc(&pool, 300);
  void *ptr4 = buddy_malloc(&pool, 400);
  
  // Ensure all allocations succeeded
  TEST_ASSERT_NOT_NULL(ptr1);
  TEST_ASSERT_NOT_NULL(ptr2);
  TEST_ASSERT_NOT_NULL(ptr3);
  TEST_ASSERT_NOT_NULL(ptr4);
  
  // Free in a specific order to test coalescing
  buddy_free(&pool, ptr2);
  buddy_free(&pool, ptr4);
  buddy_free(&pool, ptr1);
  buddy_free(&pool, ptr3);
  
  // Check pool is back to full state
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests allocation up to capacity.
 */
void test_buddy_allocation_capacity(void) {
  fprintf(stderr, "->Testing allocation up to capacity\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << MIN_K;
  buddy_init(&pool, size);
  
  // Calculate how many blocks of a specific size we can allocate
  size_t block_size = 1024;
  size_t num_blocks = (size / 2) / (block_size + sizeof(struct avail));
  
  // Allocate blocks until near capacity
  void *pointers[100]; // Adjust array size based on expected allocations
  size_t count = 0;
  
  for (size_t i = 0; i < num_blocks; i++) {
    void *ptr = buddy_malloc(&pool, block_size);
    if (ptr == NULL) break;
    pointers[count++] = ptr;
  }
  
  // Ensure we got some allocations
  TEST_ASSERT_TRUE(count > 0);
  
  // Next allocation should fail
  void *ptr = buddy_malloc(&pool, block_size);
  TEST_ASSERT_NULL(ptr);
  TEST_ASSERT_EQUAL(ENOMEM, errno);
  
  // Free all allocations
  for (size_t i = 0; i < count; i++) {
    buddy_free(&pool, pointers[i]);
  }
  
  // Pool should be full again
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests zero-size allocation.
 */
void test_buddy_malloc_zero(void) {
  fprintf(stderr, "->Testing zero-size allocation\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << MIN_K;
  buddy_init(&pool, size);
  
  void *ptr = buddy_malloc(&pool, 0);
  TEST_ASSERT_NULL(ptr);
  
  buddy_destroy(&pool);
}

/**
 * Tests varying allocation sizes.
 */
void test_buddy_varying_sizes(void) {
  fprintf(stderr, "->Testing varying allocation sizes\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << MIN_K;
  buddy_init(&pool, size);
  
  // Allocate blocks with powers of 2 sizes
  void *ptr1 = buddy_malloc(&pool, 64);
  void *ptr2 = buddy_malloc(&pool, 128);
  void *ptr3 = buddy_malloc(&pool, 256);
  void *ptr4 = buddy_malloc(&pool, 512);
  
  // Write to memory to check usability
  memset(ptr1, 0xAA, 64);
  memset(ptr2, 0xBB, 128);
  memset(ptr3, 0xCC, 256);
  memset(ptr4, 0xDD, 512);
  
  // Free in reverse order
  buddy_free(&pool, ptr4);
  buddy_free(&pool, ptr3);
  buddy_free(&pool, ptr2);
  buddy_free(&pool, ptr1);
  
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests buddy coalescing.
 */
void test_buddy_coalescing(void) {
  fprintf(stderr, "->Testing buddy coalescing\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << MIN_K;
  buddy_init(&pool, size);
  
  // Allocate blocks of the same size to force specific buddy relationships
  void *ptr1 = buddy_malloc(&pool, 4096);
  void *ptr2 = buddy_malloc(&pool, 4096);
  void *ptr3 = buddy_malloc(&pool, 4096);
  void *ptr4 = buddy_malloc(&pool, 4096);
  
  // Free non-adjacent blocks first
  buddy_free(&pool, ptr1);
  buddy_free(&pool, ptr3);
  
  // Then free their buddies to force coalescing
  buddy_free(&pool, ptr2);
  buddy_free(&pool, ptr4);
  
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

int main(void) {
  time_t t;
  unsigned seed = (unsigned)time(&t);
  fprintf(stderr, "Random seed:%d\n", seed);
  srand(seed);
  printf("Running memory tests.\n");

  UNITY_BEGIN();
  RUN_TEST(test_buddy_init);
  RUN_TEST(test_buddy_malloc_one_byte);
  RUN_TEST(test_buddy_malloc_one_large);
  RUN_TEST(test_buddy_multiple_allocations);
  RUN_TEST(test_buddy_allocation_capacity);
  RUN_TEST(test_buddy_malloc_zero);
  RUN_TEST(test_buddy_varying_sizes);
  RUN_TEST(test_buddy_coalescing);
return UNITY_END();
}

