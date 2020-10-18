#include "config.h"

#define LIBSSH_STATIC

#include <errno.h>
#include "torture.h"
#include "libssh/libssh.h"

static void torture_ssh_init(void **state) {
    int rc;

    (void) state;

    rc = ssh_init();
    assert_int_equal(rc, SSH_OK);
    rc = ssh_finalize();
    assert_int_equal(rc, SSH_OK);
}

static void torture_ssh_init_after_finalize(void **state) {

    int rc;

    (void) state;

    rc = ssh_init();
    assert_int_equal(rc, SSH_OK);
    rc = ssh_finalize();
    assert_int_equal(rc, SSH_OK);
    rc = ssh_init();
    assert_int_equal(rc, SSH_OK);
    rc = ssh_finalize();
    assert_int_equal(rc, SSH_OK);
}

static void torture_is_ssh_initialized(UNUSED_PARAM(void **state)) {

    int rc;
    bool initialized = false;

    /* Make sure the library is not initialized */
    while (is_ssh_initialized()) {
        rc = ssh_finalize();
        assert_return_code(rc, errno);
    }

    rc = ssh_init();
    assert_return_code(rc, errno);
    initialized = is_ssh_initialized();
    assert_true(initialized);
    rc = ssh_finalize();
    assert_return_code(rc, errno);
    initialized = is_ssh_initialized();
    assert_false(initialized);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_ssh_init),
        cmocka_unit_test(torture_ssh_init_after_finalize),
        cmocka_unit_test(torture_is_ssh_initialized),
    };

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);

    return rc;
}
