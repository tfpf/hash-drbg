#include <assert.h>
#include <hdrbg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/******************************************************************************
 * Test a particular HDRBG object.
 *
 * @param hd HDRBG object.
 * @param tv Test vectors file.
 *****************************************************************************/
void tests(struct hdrbg_t *hd, FILE *tv)
{
    hdrbg_tests(hd, tv);

    for(int i = 0; i < 30000; ++i)
    {
        uint64_t r = hdrbg_rand(hd);
        if(r > 0)
        {
            assert(hdrbg_uint(hd, r) < r);
        }
    }

    for(int i = 0; i < 30000; ++i)
    {
        uint64_t uleft = hdrbg_rand(hd);
        int64_t left = *(int64_t *)&uleft;
        uint64_t uright = hdrbg_rand(hd);
        int64_t right = *(int64_t *)&uright;
        if(left < right)
        {
            int64_t middle = hdrbg_span(hd, left, right);
            assert(left <= middle && middle < right);
        }
    }

    size_t r_length = hdrbg_fill(hd, false, NULL, 65537ULL);
    assert(r_length == 0);
    assert(hdrbg_err_get() == HDRBG_ERR_INVALID_REQUEST);
    assert(hdrbg_err_get() == HDRBG_ERR_NONE);
}

/******************************************************************************
 * Main function.
 *****************************************************************************/
int main(void)
{
    printf("Testing a dynamically-allocated HDRBG object.\n");
    FILE *tv = fopen("Hash_DRBG.dat", "rb");
    struct hdrbg_t *hd = hdrbg_init(true);
    tests(hd, tv);
    hdrbg_zero(hd);
    printf("All tests passed.\n");

    printf("Testing the internal HDRBG object.\n");
    rewind(tv);
    tests(NULL, tv);
    fclose(tv);
    printf("All tests passed.\n");
}
