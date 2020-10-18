#include "config.h"

#include "torture.h"
#define LIBSSH_STATIC

const char template[] = "temp_file_XXXXXX";

static int setup(void **state)
{
    char *file_name = NULL;

    file_name  = torture_create_temp_file(template);
    assert_non_null(file_name);

    *state = (void *)file_name;

    return 0;
}

static int teardown(void **state)
{
    int rc;
    char *file_name = *((char **)state);

    assert_non_null(file_name);

    rc = unlink(file_name);
    assert_int_equal(rc, 0);

    SAFE_FREE(file_name);

    return 0;
}


static void torture_temp_file(void **state)
{
    char *file_name = *((char **)state);
    FILE *fp = NULL;

    assert_non_null(file_name);

    fp = fopen(file_name, "r");
    assert_non_null(fp);

    fclose(fp);

    printf("Created temp file: %s\n", file_name);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_temp_file, setup, teardown),
    };

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);

    return rc;
}

