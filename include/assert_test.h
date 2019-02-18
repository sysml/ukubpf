#include <uk/assert.h>
#define  TEST_ZERO_CHK(val)         \
    do {                  \
        UK_ASSERT(val == 0);  \
    } while(0)

#define  TEST_NOT_ZERO_CHK(val)     \
    do { 						\
        UK_ASSERT(val != 0);  \
    } while(0)

#define  TEST_EXPR(expr)    \
    do {                   \
	UK_ASSERT(expr);\
    } while(0)

#define TEST_NOT_NULL(val)		\
	do {			\
		UK_ASSERT(val); \
	} while(0)
