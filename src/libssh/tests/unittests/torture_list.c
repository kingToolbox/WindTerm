#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "error.c"
#include "misc.c"

static void torture_ssh_list_new(void **state) {
    struct ssh_list *xlist;

    (void) state;

    xlist = ssh_list_new();

    assert_non_null(xlist);
    assert_null(xlist->root);
    assert_null(xlist->end);

    assert_int_equal(ssh_list_count(xlist), 0);

    ssh_list_free(xlist);
}

static void torture_ssh_list_append(void **state) {
    struct ssh_list *xlist;
    int rc;

    (void) state;

    xlist = ssh_list_new();
    assert_non_null(xlist);

    rc = ssh_list_append(xlist, "item1");
    assert_true(rc == 0);
    assert_non_null(xlist->root);
    assert_non_null(xlist->root->data);
    assert_non_null(xlist->end);
    assert_non_null(xlist->end->data);
    assert_string_equal((const char *) xlist->root->data, "item1");
    assert_string_equal((const char *) xlist->end->data, "item1");

    rc = ssh_list_append(xlist, "item2");
    assert_true(rc == 0);
    assert_non_null(xlist->root);
    assert_non_null(xlist->root->data);
    assert_non_null(xlist->end);
    assert_non_null(xlist->end->data);
    assert_string_equal((const char *) xlist->root->data, "item1");
    assert_string_equal((const char *) xlist->end->data, "item2");

    rc = ssh_list_append(xlist, "item3");
    assert_true(rc == 0);
    assert_non_null(xlist->root);
    assert_non_null(xlist->root->data);
    assert_non_null(xlist->root->next);
    assert_non_null(xlist->root->next->data);
    assert_non_null(xlist->root->next->next);
    assert_non_null(xlist->root->next->next->data);
    assert_non_null(xlist->end);
    assert_non_null(xlist->end->data);
    assert_string_equal((const char *) xlist->root->data, "item1");
    assert_string_equal((const char *) xlist->root->next->data, "item2");
    assert_string_equal((const char *) xlist->root->next->next->data, "item3");
    assert_string_equal((const char *) xlist->end->data, "item3");

    assert_int_equal(ssh_list_count(xlist), 3);

    ssh_list_free(xlist);
}

static void torture_ssh_list_prepend(void **state) {
    struct ssh_list *xlist;
    int rc;

    (void) state;

    xlist = ssh_list_new();
    assert_non_null(xlist);

    rc = ssh_list_prepend(xlist, "item1");
    assert_true(rc == 0);
    assert_non_null(xlist->root);
    assert_non_null(xlist->root->data);
    assert_non_null(xlist->end);
    assert_non_null(xlist->end->data);
    assert_string_equal((const char *) xlist->root->data, "item1");
    assert_string_equal((const char *) xlist->end->data, "item1");

    rc = ssh_list_append(xlist, "item2");
    assert_true(rc == 0);
    assert_non_null(xlist->root);
    assert_non_null(xlist->root->data);
    assert_non_null(xlist->end);
    assert_non_null(xlist->end->data);
    assert_string_equal((const char *) xlist->root->data, "item1");
    assert_string_equal((const char *) xlist->end->data, "item2");

    rc = ssh_list_prepend(xlist, "item3");
    assert_true(rc == 0);
    assert_non_null(xlist->root);
    assert_non_null(xlist->root->data);
    assert_non_null(xlist->root->next);
    assert_non_null(xlist->root->next->data);
    assert_non_null(xlist->root->next->next);
    assert_non_null(xlist->end);
    assert_non_null(xlist->end->data);
    assert_string_equal((const char *) xlist->root->data, "item3");
    assert_string_equal((const char *) xlist->root->next->data, "item1");
    assert_string_equal((const char *) xlist->root->next->next->data, "item2");
    assert_string_equal((const char *) xlist->end->data, "item2");

    assert_int_equal(ssh_list_count(xlist), 3);

    ssh_list_free(xlist);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_ssh_list_new),
        cmocka_unit_test(torture_ssh_list_append),
        cmocka_unit_test(torture_ssh_list_prepend),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
