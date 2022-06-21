#pragma once
#include <assert.h>

#define sp_assert_equal(a, b) \
do {                                                                \
    if ((a) != (b)) {                                               \
        printf("NOT EQUAL: %d, 0x%x != %d, 0x%x\n", (int)(a), (int)(a), (int)(b), (int)(b)); \
        assert((a) == (b));                                         \
    }                                                               \
} while(0)

#define sp_assert_not_equal(a, b) \
do {                                                                \
    if ((a) == (b)) {                                               \
        printf("ASSERT NOT EQUAL: %d, 0x%x\n", (int)(b), (int)(b)); \
        assert((a) != (b));                                         \
    }                                                               \
} while(0)

