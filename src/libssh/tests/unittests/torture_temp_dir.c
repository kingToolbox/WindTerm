#include "config.h"

#include "torture.h"
#define LIBSSH_STATIC

const char template[] = "temp_dir_XXXXXX";

static int setup(void **state)
{
    char *temp_dir = NULL;

    temp_dir = torture_make_temp_dir(template);
    assert_non_null(temp_dir);

    *state = (void *)temp_dir;

    return 0;
}

static int teardown(void **state)
{
    char *temp_dir = *((char **)state);

    torture_rmdirs((const char *)temp_dir);

    free(temp_dir);

    return 0;
}


static void torture_create_temp_dir(void **state)
{
    char *temp_dir = *((char **)state);

    printf("Created temp dir: %s\n", temp_dir);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_create_temp_dir, setup, teardown),
    };

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);

    return rc;
}

