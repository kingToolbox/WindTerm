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

static void torture_back_and_forth(void **state)
{
    char *temp_dir = *((char **)state);
    char *cwd = NULL;
    char *after_change = NULL;
    char *after_changing_back = NULL;
    int rc = 0;

    cwd = torture_get_current_working_dir();
    assert_non_null(cwd);

    printf("Current dir: %s\n", cwd);

    rc = torture_change_dir(temp_dir);
    assert_int_equal(rc, 0);

    after_change = torture_get_current_working_dir();
    assert_non_null(after_change);

    printf("Current dir after change: %s\n", after_change);

    rc = torture_change_dir(cwd);
    assert_int_equal(rc, 0);

    after_changing_back = torture_get_current_working_dir();
    assert_non_null(after_changing_back);

    printf("Back to dir: %s\n", after_changing_back);

    SAFE_FREE(cwd);
    SAFE_FREE(after_change);
    SAFE_FREE(after_changing_back);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_back_and_forth,
                                        setup, teardown),
    };

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);

    return rc;
}

