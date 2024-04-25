#include <assert.h>
#include <hdrbg.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifndef __STDC_NO_THREADS__
#include <threads.h>
#endif

#define WORKERS_SIZE 8
#define CUSTOM_ITERATIONS (1L << 16)

/******************************************************************************
 * Ad hoc verification.
 *
 * @param hd_ HDRBG object.
 *
 * @return Ignored.
 *****************************************************************************/
int
hdrbg_tests_custom(void *hd_)
{
    struct hdrbg_t *hd = hd_;
    for (int long i = 0; i < CUSTOM_ITERATIONS; ++i)
    {
        uint64_t r = hdrbg_rand(hd);
        if (r > 0)
        {
            assert(hdrbg_uint(hd, r) < r);
            assert(hdrbg_err_get() == HDRBG_ERR_NONE);
        }
        assert(hdrbg_uint(hd, 0) == UINT64_MAX);
        assert(hdrbg_err_get() == HDRBG_ERR_INVALID_REQUEST_UINT);
        assert(hdrbg_err_get() == HDRBG_ERR_NONE);
    }
    for (int long i = 0; i < CUSTOM_ITERATIONS; ++i)
    {
        uint64_t uleft = hdrbg_rand(hd);
        int64_t left = *(int64_t *)&uleft;
        uint64_t uright = hdrbg_rand(hd);
        int64_t right = *(int64_t *)&uright;
        int64_t middle = hdrbg_span(hd, left, right);
        if (left < right)
        {
            assert(left <= middle && middle < right);
        }
        else
        {
            assert(middle == -1);
            assert(hdrbg_err_get() == HDRBG_ERR_INVALID_REQUEST_SPAN);
        }
        assert(hdrbg_err_get() == HDRBG_ERR_NONE);
    }
    assert(hdrbg_fill(hd, false, NULL, 65537UL) == -1);
    assert(hdrbg_err_get() == HDRBG_ERR_INVALID_REQUEST_FILL);
    assert(hdrbg_err_get() == HDRBG_ERR_NONE);
    return 0;
}

/******************************************************************************
 * Main function.
 *****************************************************************************/
int
main(void)
{
    printf("Testing a dynamically-allocated HDRBG object.\n");
    FILE *tv = fopen("Hash_DRBG.dat", "rb");
    struct hdrbg_t *hds[WORKERS_SIZE];
    for (int i = 0; i < WORKERS_SIZE; ++i)
    {
        hds[i] = hdrbg_init(true);
        hdrbg_tests(hds[i], tv);
        rewind(tv);
    }
#ifndef __STDC_NO_THREADS__
    thrd_t workers[WORKERS_SIZE];
#endif
    for (int i = 0; i < WORKERS_SIZE; ++i)
    {
#ifndef __STDC_NO_THREADS__
        thrd_create(workers + i, hdrbg_tests_custom, hds[i]);
#else
        hdrbg_tests_custom(hds[i]);
#endif
    }
    for (int i = 0; i < WORKERS_SIZE; ++i)
    {
#ifndef __STDC_NO_THREADS__
        thrd_join(workers[i], NULL);
#endif
        hdrbg_zero(hds[i]);
    }
    printf("All tests passed.\n");

    printf("Testing the internal HDRBG object.\n");
    rewind(tv);
    hdrbg_tests(NULL, tv);
    hdrbg_tests_custom(NULL);
    fclose(tv);
    printf("All tests passed.\n");
}
