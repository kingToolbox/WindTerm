#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/priv.h>
#include <libssh/callbacks.h>
#include <libssh/misc.h>

static int myauthcallback (const char *prompt, char *buf, size_t len,
    int echo, int verify, void *userdata) {
    (void) prompt;
    (void) buf;
    (void) len;
    (void) echo;
    (void) verify;
    (void) userdata;
    return 0;
}

static int setup(void **state)
{
    struct ssh_callbacks_struct *cb;

    cb = malloc(sizeof(struct ssh_callbacks_struct));
    assert_non_null(cb);
    ZERO_STRUCTP(cb);

    cb->userdata = (void *) 0x0badc0de;
    cb->auth_function = myauthcallback;

    ssh_callbacks_init(cb);
    *state = cb;

    return 0;
}

static int teardown(void **state)
{
    free(*state);

    return 0;
}

static void torture_callbacks_size(void **state) {
    struct ssh_callbacks_struct *cb = *state;;

    assert_int_not_equal(cb->size, 0);
}

static void torture_callbacks_exists(void **state) {
    struct ssh_callbacks_struct *cb = *state;

    assert_int_not_equal(ssh_callbacks_exists(cb, auth_function), 0);
    assert_int_equal(ssh_callbacks_exists(cb, log_function), 0);

    /*
     * We redefine size so auth_function is outside the range of
     * callbacks->size.
     */
    cb->size = (unsigned char *) &cb->auth_function - (unsigned char *) cb;
    assert_int_equal(ssh_callbacks_exists(cb, auth_function), 0);

    /* Now make it one pointer bigger so we spill over the auth_function slot */
    cb->size += sizeof(void *);
    assert_int_not_equal(ssh_callbacks_exists(cb, auth_function), 0);
}

struct test_mock_state {
    int executed;
};

static void test_mock_ssh_logging_callback(int priority,
                                           const char *function,
                                           const char *buffer,
                                           void *userdata)
{
    struct test_mock_state *t = (struct test_mock_state *)userdata;

    check_expected(priority);
    check_expected(function);
    check_expected(buffer);

    t->executed++;
}

static void torture_log_callback(void **state)
{
    struct test_mock_state t = {
        .executed = 0,
    };

    (void)state; /* unused */

    ssh_set_log_callback(test_mock_ssh_logging_callback);
    ssh_set_log_userdata(&t);
    ssh_set_log_level(1);

    expect_value(test_mock_ssh_logging_callback, priority, 1);
    expect_string(test_mock_ssh_logging_callback, function, "torture_log_callback");
    expect_string(test_mock_ssh_logging_callback, buffer, "torture_log_callback: test");

    SSH_LOG(SSH_LOG_WARN, "test");

    assert_int_equal(t.executed, 1);
}

static void cb1(ssh_session session, ssh_channel channel, void *userdata){
    int *v = userdata;
    (void) session;
    (void) channel;
    *v += 1;
}

static void cb2(ssh_session session, ssh_channel channel, int status, void *userdata){
    int *v = userdata;
    (void) session;
    (void) channel;
    (void) status;
    *v += 10;
}

static void torture_callbacks_execute_list(void **state){
    struct ssh_list *list = ssh_list_new();
    int v = 0, w = 0;
    struct ssh_channel_callbacks_struct c1 = {
            .channel_eof_function = cb1,
            .userdata = &v
    };
    struct ssh_channel_callbacks_struct c2 = {
            .channel_exit_status_function = cb2,
            .userdata = &v
    };
    struct ssh_channel_callbacks_struct c3 = {
            .channel_eof_function = cb1,
            .channel_exit_status_function = cb2,
            .userdata = &w
    };

    (void)state;
    ssh_callbacks_init(&c1);
    ssh_callbacks_init(&c2);
    ssh_callbacks_init(&c3);

    ssh_list_append(list, &c1);
    ssh_callbacks_execute_list(list,
                               ssh_channel_callbacks,
                               channel_eof_function,
                               NULL,
                               NULL);
    assert_int_equal(v, 1);

    v = 0;
    ssh_list_append(list, &c2);
    ssh_callbacks_execute_list(list,
                               ssh_channel_callbacks,
                               channel_eof_function,
                               NULL,
                               NULL);
    assert_int_equal(v, 1);
    ssh_callbacks_execute_list(list,
                               ssh_channel_callbacks,
                               channel_exit_status_function,
                               NULL,
                               NULL,
                               0);
    assert_int_equal(v, 11);

    v = 0;
    w = 0;
    ssh_list_append(list, &c3);
    ssh_callbacks_execute_list(list,
                               ssh_channel_callbacks,
                               channel_eof_function,
                               NULL,
                               NULL);
    assert_int_equal(v, 1);
    assert_int_equal(w, 1);
    ssh_callbacks_execute_list(list,
                               ssh_channel_callbacks,
                               channel_exit_status_function,
                               NULL,
                               NULL,
                               0);
    assert_int_equal(v, 11);
    assert_int_equal(w, 11);

    ssh_list_free(list);

}

static int cb3(ssh_session session, ssh_channel channel, void *userdata){
    int *v = userdata;
    (void)session;
    (void)channel;
    *v = 1;
    return 10;
}

static void torture_callbacks_iterate(void **state){
    struct ssh_list *list = ssh_list_new();
    int v = 0, w = 0;
    struct ssh_channel_callbacks_struct c1 = {
            .channel_eof_function = cb1,
            .channel_shell_request_function = cb3,
            .userdata = &v
    };
    struct ssh_channel_callbacks_struct c2 = {
            .channel_eof_function = cb1,
            .channel_shell_request_function = cb3,
            .userdata = &v
    };

    (void)state; /* unused */

    ssh_callbacks_init(&c1);
    ssh_callbacks_init(&c2);

    ssh_list_append(list, &c1);
    ssh_list_append(list, &c2);

    ssh_callbacks_iterate(list, ssh_channel_callbacks, channel_eof_function){
        ssh_callbacks_iterate_exec(channel_eof_function, NULL, NULL);
    }
    ssh_callbacks_iterate_end();

    assert_int_equal(v, 2);

    v = 0;
    ssh_callbacks_iterate(list, ssh_channel_callbacks, channel_shell_request_function){
        w = ssh_callbacks_iterate_exec(channel_shell_request_function, NULL, NULL);
        if (w) {
            break;
        }
    }
    ssh_callbacks_iterate_end();

    assert_int_equal(w, 10);
    assert_int_equal(v, 1);

    ssh_list_free(list);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_callbacks_size, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_callbacks_exists, setup, teardown),
        cmocka_unit_test(torture_log_callback),
        cmocka_unit_test(torture_callbacks_execute_list),
        cmocka_unit_test(torture_callbacks_iterate)
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
