#define LIBSSH_STATIC

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libssh/libssh.h>
#include "torture.h"

#define TEST_SERVER_PORT 2222

struct hostkey_state {
    const char *hostkey;
    char *hostkey_path;
    enum ssh_keytypes_e key_type;
    int fd;
};

static int setup(void **state) {
    struct hostkey_state *h;
    mode_t mask;
    int rc;

    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    rc = ssh_init();
    if (rc != SSH_OK) {
        return -1;
    }

    h = malloc(sizeof(struct hostkey_state));
    assert_non_null(h);

    h->hostkey_path = strdup("/tmp/libssh_hostkey_XXXXXX");

    mask = umask(S_IRWXO | S_IRWXG);
    h->fd = mkstemp(h->hostkey_path);
    umask(mask);
    assert_return_code(h->fd, errno);
    close(h->fd);

    h->key_type = SSH_KEYTYPE_ECDSA_P256;
    h->hostkey = torture_get_testkey(h->key_type, 0);

    torture_write_file(h->hostkey_path, h->hostkey);

    *state = h;

    return 0;
}

static int teardown(void **state) {
    struct hostkey_state *h = (struct hostkey_state *)*state;

    unlink(h->hostkey);
    free(h->hostkey_path);
    free(h);

    ssh_finalize();

    return 0;
}

/* For x11_screen_number, need something that is not equal to htonl
   itself */
static const uint32_t x11_screen_number = 1;

static void *client_thread(void *arg) {
    unsigned int test_port = TEST_SERVER_PORT;
    int rc;
    ssh_session session;
    ssh_channel channel;

    /* unused */
    (void)arg;

    usleep(200);
    session = torture_ssh_session(NULL, "localhost",
                                  &test_port,
                                  "foo", "bar");
    assert_non_null(session);

    channel = ssh_channel_new(session);
    assert_non_null(channel);

    rc = ssh_channel_open_session(channel);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_channel_request_x11(channel, 0, NULL, NULL,
                                 (uint32_t)x11_screen_number);
    assert_int_equal(rc, SSH_OK);

    ssh_free(session);
    return NULL;
}

static int auth_password_accept(ssh_session session,
                                const char *user,
                                const char *password,
                                void *userdata) {
    /* unused */
    (void)session;
    (void)user;
    (void)password;
    (void)userdata;

    return SSH_AUTH_SUCCESS;
}

struct channel_data {
    int req_seen;
    uint32_t screen_number;
};

static void ssh_channel_x11_req(ssh_session session,
                                ssh_channel channel,
                                int single_connection,
                                const char *auth_protocol,
                                const char *auth_cookie,
                                uint32_t screen_number,
                                void *userdata) {
    struct channel_data *channel_data = userdata;

    /* unused */
    (void)session;
    (void)channel;
    (void)single_connection;
    (void)auth_protocol;
    (void)auth_cookie;

    /* We've seen an x11 request.  Record the screen number */
    channel_data->req_seen = 1;
    channel_data->screen_number = screen_number;
}

static ssh_channel channel_open(ssh_session session, void *userdata) {
    ssh_channel channel = NULL;
    ssh_channel_callbacks channel_cb = userdata;

    /* unused */
    (void)userdata;

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        goto out;
    }
    ssh_set_channel_callbacks(channel, channel_cb);

 out:
    return channel;
}

static void test_ssh_channel_request_x11(void **state) {
    struct hostkey_state *h = (struct hostkey_state *)*state;
    int rc, event_rc;
    pthread_t client_pthread;
    ssh_bind sshbind;
    ssh_session server;
    ssh_event event;

    struct channel_data channel_data;
    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &channel_data,
        .channel_x11_req_function = ssh_channel_x11_req
    };
    struct ssh_server_callbacks_struct server_cb = {
        .userdata = &channel_cb,
        .auth_password_function = auth_password_accept,
        .channel_open_request_session_function = channel_open
    };

    memset(&channel_data, 0, sizeof(channel_data));
    ssh_callbacks_init(&channel_cb);
    ssh_callbacks_init(&server_cb);

    /* Create server */
    sshbind = torture_ssh_bind("localhost",
                               TEST_SERVER_PORT,
                               h->key_type,
                               h->hostkey_path);
    assert_non_null(sshbind);

    /* Get client to connect */
    rc = pthread_create(&client_pthread, NULL, client_thread, NULL);
    assert_return_code(rc, errno);

    server = ssh_new();
    assert_non_null(server);

    rc = ssh_bind_accept(sshbind, server);
    assert_int_equal(rc, SSH_OK);

    /* Handle client connection */
    ssh_set_server_callbacks(server, &server_cb);

    rc = ssh_handle_key_exchange(server);
    assert_int_equal(rc, SSH_OK);

    event = ssh_event_new();
    assert_non_null(event);

    ssh_event_add_session(event, server);

    event_rc = SSH_OK;
    while (!channel_data.req_seen && event_rc == SSH_OK) {
        event_rc = ssh_event_dopoll(event, -1);
    }

    /* Cleanup */
    ssh_event_free(event);
    ssh_free(server);
    ssh_bind_free(sshbind);

    rc = pthread_join(client_pthread, NULL);
    assert_int_equal(rc, 0);

    assert_true(channel_data.req_seen);
    assert_int_equal(channel_data.screen_number,
                     x11_screen_number);
}

int torture_run_tests(void) {
    int rc;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ssh_channel_request_x11,
                                        setup,
                                        teardown)
    };

    rc = cmocka_run_group_tests(tests, NULL, NULL);
    return rc;
}

