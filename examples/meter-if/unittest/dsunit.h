#pragma once
#include <stdint.h>
#include <ctype.h>
#include <assert.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define assert_equal        assert_equal_int
#define assert_not_equal    assert_not_equal_int

#define assert_equal_int(a, b) \
    do { \
        int64_t _a = (int64_t)(a); int64_t _b = (int64_t)(b); \
        if ((int64_t)(_a) != (int64_t)(_b)) { \
            printf("\n%s, %s()@%d: %ld, 0x%lx != %ld, 0x%lx\n", __FILE__, __func__, __LINE__, \
                    (int64_t)(_a), (int64_t)(_a), (int64_t)(_b), (int64_t)(_b)); \
            fflush(stdout); \
            exit(1); \
        } \
    } while(0)

#define assert_not_equal_int(a, b) \
    do { \
        int64_t _a = (int64_t)(a); int64_t _b = (int64_t)(b); \
        if ((int64_t)(_a) == (int64_t)(_b)) { \
            printf("\n%s, %s()@%d: %ld, 0x%lx == %ld, 0x%lx\n", __FILE__, __func__, __LINE__, \
                    (int64_t)(_a), (int64_t)(_a), (int64_t)(_b), (int64_t)(_b)); \
            fflush(stdout); \
            exit(1); \
        } \
    } while(0)

#define assert_equal_string(a, b) \
    do { \
        char * _a = (char *)(a); char *_b = (char *)(b); \
        if (0 != strcmp((_a), (_b))) { \
            printf("\n%s, %s()@%d: %s != %s\n", __FILE__, __func__, __LINE__, (_a), (_b)); \
            fflush(stdout); \
            exit(1); \
        } \
    } while(0)

#define assert_true(a) \
    do { \
        int (_a) = (int)(a); \
        if (!_a) { \
            printf("\n%s, %s()@%d: NOT TRUE\n", __FILE__, __func__, __LINE__); \
            fflush(stdout); \
            exit(1); \
        } \
    } while (0)

#define assert_null(a) \
    do { \
        if (NULL != a) { \
            printf("\n%s, %s()@%d: NOT NULL\n", __FILE__, __func__, __LINE__); \
            fflush(stdout); \
            exit(1); \
        } \
    } while (0)

#define assert_not_null(a) \
    do { \
        if (NULL == a) { \
            printf("\n%s, %s()@%d: NULL\n", __FILE__, __func__, __LINE__); \
            fflush(stdout); \
            exit(1); \
        } \
    } while (0)

#undef assert
#define assert() \
    do { \
        printf("\n%s, %s()@%d: assert\n", __FILE__, __func__, __LINE__); \
        fflush(stdout); \
        exit(1); \
    } while (0)

static char * _func_in_unittest = NULL;

#define run_test(func) \
    do { \
        if (fork() == 0) { \
            _func_in_unittest = #func ; \
            func(); \
            printf("Done: %s\n", #func); \
            _func_in_unittest = NULL; \
            exit(0); \
        } else { \
            int status; \
            wait (&status); \
            if(WEXITSTATUS(status) != 0) exit(1); \
        } \
    } while(0)  

#define close_test() \
    do { \
        int status; \
        wait(&status); \
    } while(0)

static void segv_handler (int signal_number)
{
    fprintf(stderr, "\nSegmentation Fault @ %s\n\n", _func_in_unittest ? _func_in_unittest : "");
    exit(-1);
}

#define _setup()  { \
    struct sigaction sa; \
    memset(&sa, 0, sizeof(sa)); \
    sa.sa_handler = &segv_handler; \
    sigaction(SIGSEGV, &sa, NULL); \
}
