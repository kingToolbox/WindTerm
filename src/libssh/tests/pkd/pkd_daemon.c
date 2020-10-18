/*
 * pkd_daemon.c -- a sample public-key testing daemon using libssh
 *
 * Uses public key authentication to establish an exec channel and
 * echo back payloads to the user.
 *
 * (c) 2014 Jon Simons
 */

#include "config.h"

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/kex.h>

#include "torture.h" // for ssh_fips_mode()
#include "pkd_daemon.h"

#include <setjmp.h> // for cmocka
#include <cmocka.h>

static int pkdout_enabled;
static int pkderr_enabled;

static void pkdout(const char *fmt, ...) PRINTF_ATTRIBUTE(1, 2);
static void pkderr(const char *fmt, ...) PRINTF_ATTRIBUTE(1, 2);

static void pkdout(const char *fmt, ...) {
    va_list vargs;
    if (pkdout_enabled) {
        va_start(vargs, fmt);
        vfprintf(stdout, fmt, vargs);
        va_end(vargs);
    }
}

static void pkderr(const char *fmt, ...) {
    va_list vargs;
    if (pkderr_enabled) {
        va_start(vargs, fmt);
        vfprintf(stderr, fmt, vargs);
        va_end(vargs);
    }
}

/*
 * pkd state: only one thread can run pkd at a time ---------------------
 */

static struct {
    int rc;
    pthread_t tid;
    int keep_going;
    volatile int pkd_ready;
} ctx;

static struct {
    int server_fd;
    int req_exec_received;
    int close_received;
    int eof_received;
} pkd_state;

static void pkd_sighandler(int signum) {
    (void) signum;
}

static int pkd_init_libssh(void)
{
    int rc = ssh_threads_set_callbacks(ssh_threads_get_pthread());
    return (rc == SSH_OK) ? 0 : 1;
}

static int pkd_init_server_fd(short port) {
    int rc = 0;
    int yes = 1;
    struct sockaddr_in addr;

    int server_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        rc = -1;
        goto out;
    }

    rc = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    if (rc != 0) {
        goto outclose;
    }

    memset(&addr, 0x0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    rc = bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0) {
        goto outclose;
    }

    rc = listen(server_fd, 128);
    if (rc == 0) {
        goto out;
    }

outclose:
    close(server_fd);
    server_fd = -1;
out:
    pkd_state.server_fd = server_fd;
    return rc;
}

static int pkd_accept_fd(void)
{
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    do {
        fd = accept(pkd_state.server_fd, (struct sockaddr *) &addr, &len);
    } while ((ctx.keep_going != 0) && (fd < 0) && (errno == EINTR));

    return fd;
}

static void pkd_eof(ssh_session session,
                    ssh_channel channel,
                    void *userdata) {
    (void) session;
    (void) channel;
    (void) userdata;
    pkdout("pkd_eof\n");
    pkd_state.eof_received = 1;
}

static void pkd_chan_close(ssh_session session,
                           ssh_channel channel,
                           void *userdata) {
    (void) session;
    (void) channel;
    (void) userdata;
    pkdout("pkd_chan_close\n");
    pkd_state.close_received = 1;
}

static int pkd_req_exec(ssh_session s,
                        ssh_channel c,
                        const char *cmd,
                        void *userdata) {
    (void) s;
    (void) c;
    (void) cmd;
    (void) userdata;
    /* assumes pubkey authentication has already succeeded */
    pkdout("pkd_req_exec\n");
    pkd_state.req_exec_received = 1;
    return 0;
}

/* assumes there is only ever a single channel */
static struct ssh_channel_callbacks_struct pkd_channel_cb = {
    .channel_eof_function = pkd_eof,
    .channel_close_function = pkd_chan_close,
    .channel_exec_request_function = pkd_req_exec,
};

static int pkd_auth_pubkey_cb(ssh_session s,
                              const char *user,
                              ssh_key key,
                              char state,
                              void *userdata) {
    (void) s;
    (void) user;
    (void) key;
    (void) state;
    (void) userdata;
    pkdout("pkd_auth_pubkey_cb keytype %s, state: %d\n",
           ssh_key_type_to_char(ssh_key_type(key)), state);
    if ((state == SSH_PUBLICKEY_STATE_NONE) ||
        (state == SSH_PUBLICKEY_STATE_VALID)) {
        return SSH_AUTH_SUCCESS;
    }
    return SSH_AUTH_DENIED;
}

static int pkd_service_request_cb(ssh_session session,
                                  const char *service,
                                  void *userdata) {
    (void) session;
    (void) userdata;
    pkdout("pkd_service_request_cb: %s\n", service);
    return (0 == (strcmp(service, "ssh-userauth"))) ? 0 : -1;
}

static ssh_channel pkd_channel_openreq_cb(ssh_session s,
                                          void *userdata) {
    ssh_channel c = NULL;
    ssh_channel *out = (ssh_channel *) userdata;

    /* assumes pubkey authentication has already succeeded */
    pkdout("pkd_channel_openreq_cb\n");

    c = ssh_channel_new(s);
    if (c == NULL) {
        pkderr("ssh_channel_new: %s\n", ssh_get_error(s));
        return NULL;
    }

    ssh_callbacks_init(&pkd_channel_cb);
    pkd_channel_cb.userdata = userdata;
    if (ssh_set_channel_callbacks(c, &pkd_channel_cb) != SSH_OK) {
        pkderr("ssh_set_channel_callbacks: %s\n", ssh_get_error(s));
        ssh_channel_free(c);
        c = NULL;
    }

    *out = c;

    return c;
}

static struct ssh_server_callbacks_struct pkd_server_cb = {
    .auth_pubkey_function = pkd_auth_pubkey_cb,
    .service_request_function = pkd_service_request_cb,
    .channel_open_request_session_function = pkd_channel_openreq_cb,
};

static int pkd_exec_hello(int fd, struct pkd_daemon_args *args)
{
    int rc = -1;
    ssh_bind b = NULL;
    ssh_session s = NULL;
    ssh_event e = NULL;
    ssh_channel c = NULL;
    enum ssh_bind_options_e opts = -1;

    int level = args->opts.libssh_log_level;
    enum pkd_hostkey_type_e type = args->type;
    const char *hostkeypath = args->hostkeypath;
    const char *default_kex = NULL;
    char *all_kex = NULL;
    size_t kex_len = 0;
    const char *all_ciphers = NULL;
    const uint64_t rekey_data_limit = args->rekey_data_limit;
    bool process_config = false;

    pkd_state.eof_received = 0;
    pkd_state.close_received  = 0;
    pkd_state.req_exec_received = 0;

    b = ssh_bind_new();
    if (b == NULL) {
        pkderr("ssh_bind_new\n");
        goto outclose;
    }

    if (type == PKD_RSA) {
        opts = SSH_BIND_OPTIONS_RSAKEY;
    } else if (type == PKD_ED25519) {
        opts = SSH_BIND_OPTIONS_HOSTKEY;
#ifdef HAVE_DSA
    } else if (type == PKD_DSA) {
        opts = SSH_BIND_OPTIONS_DSAKEY;
#endif
    } else if (type == PKD_ECDSA) {
        opts = SSH_BIND_OPTIONS_ECDSAKEY;
    } else {
        pkderr("unknown hostkey type: %d\n", type);
        rc = -1;
        goto outclose;
    }

    rc = ssh_bind_options_set(b, opts, hostkeypath);
    if (rc != 0) {
        pkderr("ssh_bind_options_set: %s\n", ssh_get_error(b));
        goto outclose;
    }

    rc = ssh_bind_options_set(b, SSH_BIND_OPTIONS_LOG_VERBOSITY, &level);
    if (rc != 0) {
        pkderr("ssh_bind_options_set log verbosity: %s\n", ssh_get_error(b));
        goto outclose;
    }

    rc = ssh_bind_options_set(b, SSH_BIND_OPTIONS_PROCESS_CONFIG,
                              &process_config);
    if (rc != 0) {
        pkderr("ssh_bind_options_set process config: %s\n", ssh_get_error(b));
        goto outclose;
    }

    if (!ssh_fips_mode()) {
        /* Add methods not enabled by default */
#define GEX_SHA1 "diffie-hellman-group-exchange-sha1"
        default_kex = ssh_kex_get_default_methods(SSH_KEX);
        kex_len = strlen(default_kex) + strlen(GEX_SHA1) + 2;
        all_kex = malloc(kex_len);
        if (all_kex == NULL) {
            pkderr("Failed to alloc more memory.\n");
            goto outclose;
        }
        snprintf(all_kex, kex_len, "%s," GEX_SHA1, default_kex);
        rc = ssh_bind_options_set(b, SSH_BIND_OPTIONS_KEY_EXCHANGE, all_kex);
        free(all_kex);
        if (rc != 0) {
            pkderr("ssh_bind_options_set kex methods: %s\n", ssh_get_error(b));
            goto outclose;
        }

        /* Enable all supported ciphers */
        all_ciphers = ssh_kex_get_supported_method(SSH_CRYPT_C_S);
        rc = ssh_bind_options_set(b, SSH_BIND_OPTIONS_CIPHERS_C_S, all_ciphers);
        if (rc != 0) {
            pkderr("ssh_bind_options_set Ciphers C-S: %s\n", ssh_get_error(b));
            goto outclose;
        }

        all_ciphers = ssh_kex_get_supported_method(SSH_CRYPT_S_C);
        rc = ssh_bind_options_set(b, SSH_BIND_OPTIONS_CIPHERS_S_C, all_ciphers);
        if (rc != 0) {
            pkderr("ssh_bind_options_set Ciphers S-C: %s\n", ssh_get_error(b));
            goto outclose;
        }
    }

    s = ssh_new();
    if (s == NULL) {
        pkderr("ssh_new\n");
        goto outclose;
    }

    rc = ssh_options_set(s, SSH_OPTIONS_REKEY_DATA, &rekey_data_limit);
    if (rc != 0) {
        pkderr("ssh_options_set rekey data: %s\n", ssh_get_error(s));
        goto outclose;
    }

    /*
     * ssh_bind_accept loads host key as side-effect.  If this
     * succeeds, the given 'fd' will be closed upon 'ssh_free(s)'.
     */
    rc = ssh_bind_accept_fd(b, s, fd);
    if (rc != SSH_OK) {
        pkderr("ssh_bind_accept_fd: %s\n", ssh_get_error(b));
        goto outclose;
    }

    /* accept only publickey-based auth */
    ssh_set_auth_methods(s, SSH_AUTH_METHOD_PUBLICKEY);

    /* initialize callbacks */
    ssh_callbacks_init(&pkd_server_cb);
    pkd_server_cb.userdata = &c;
    rc = ssh_set_server_callbacks(s, &pkd_server_cb);
    if (rc != SSH_OK) {
        pkderr("ssh_set_server_callbacks: %s\n", ssh_get_error(s));
        goto out;
    }

    /* first do key exchange */
    rc = ssh_handle_key_exchange(s);
    if (rc != SSH_OK) {
        pkderr("ssh_handle_key_exchange: %s\n", ssh_get_error(s));
        goto out;
    }

    /* setup and pump event to carry out exec channel */
    e = ssh_event_new();
    if (e == NULL) {
        pkderr("ssh_event_new\n");
        goto out;
    }

    rc = ssh_event_add_session(e, s);
    if (rc != SSH_OK) {
        pkderr("ssh_event_add_session\n");
        goto out;
    }

    /* poll until exec channel established */
    while ((ctx.keep_going != 0) &&
           (rc != SSH_ERROR) && (pkd_state.req_exec_received == 0)) {
        rc = ssh_event_dopoll(e, -1 /* infinite timeout */);
    }

    if (rc == SSH_ERROR) {
        pkderr("ssh_event_dopoll\n");
        goto out;
    } else if (c == NULL) {
        pkderr("poll loop exited but exec channel not ready\n");
        rc = -1;
        goto out;
    }

    rc = ssh_channel_write(c, args->payload.buf, args->payload.len);
    if (rc != (int)args->payload.len) {
        pkderr("ssh_channel_write partial (%d != %zd)\n", rc, args->payload.len);
    }

    rc = ssh_channel_request_send_exit_status(c, 0);
    if (rc != SSH_OK) {
        pkderr("ssh_channel_request_send_exit_status: %s\n",
                        ssh_get_error(s));
        goto out;
    }

    rc = ssh_channel_send_eof(c);
    if (rc != SSH_OK) {
        pkderr("ssh_channel_send_eof: %s\n", ssh_get_error(s));
        goto out;
    }

    rc = ssh_channel_close(c);
    if (rc != SSH_OK) {
        pkderr("ssh_channel_close: %s\n", ssh_get_error(s));
        goto out;
    }

    while ((ctx.keep_going != 0) &&
           (pkd_state.eof_received == 0) &&
           (pkd_state.close_received == 0)) {
        rc = ssh_event_dopoll(e, 1000 /* milliseconds */);
        if (rc == SSH_ERROR) {
            /* log, but don't consider this fatal */
            pkdout("ssh_event_dopoll for eof + close: %s\n", ssh_get_error(s));
            rc = 0;
            break;
        } else {
            rc = 0;
        }
    }

    while ((ctx.keep_going != 0) &&
           (ssh_is_connected(s))) {
        rc = ssh_event_dopoll(e, 1000 /* milliseconds */);
        if (rc == SSH_ERROR) {
            /* log, but don't consider this fatal */
            pkdout("ssh_event_dopoll for session connection: %s\n", ssh_get_error(s));
            rc = 0;
            break;
        } else {
            rc = 0;
        }
    }
    goto out;

outclose:
    close(fd);
out:
    if (c != NULL) {
        ssh_channel_free(c);
    }
    if (e != NULL) {
        ssh_event_remove_session(e, s);
        ssh_event_free(e);
    }
    if (s != NULL) {
        ssh_disconnect(s);
        ssh_free(s);
    }
    if (b != NULL) {
        ssh_bind_free(b);
    }
    return rc;
}

/*
 * main loop ------------------------------------------------------------
 */

static void *pkd_main(void *args) {
    int rc = -1;
    struct pkd_daemon_args *a = (struct pkd_daemon_args *) args;

    struct sigaction act = { .sa_handler = pkd_sighandler, };

    pkd_state.server_fd = -1;
    pkd_state.req_exec_received = 0;
    pkd_state.close_received = 0;
    pkd_state.eof_received = 0;

    /* SIGUSR1 is used to interrupt 'pkd_accept_fd'. */
    rc = sigaction(SIGUSR1, &act, NULL);
    if (rc != 0) {
        pkderr("sigaction: %d\n", rc);
        goto out;
    }

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    rc = pkd_init_libssh();
    if (rc != 0) {
        pkderr("pkd_init_libssh: %d\n", rc);
        goto out;
    }

    rc = pkd_init_server_fd(1234);
    if (rc != 0) {
        pkderr("pkd_init_server_fd: %d\n", rc);
        goto out;
    }

    ctx.pkd_ready = 1;

    while (ctx.keep_going != 0) {
        int fd = pkd_accept_fd();
        if (fd < 0) {
            if (ctx.keep_going != 0) {
                pkderr("pkd_accept_fd");
                rc = -1;
            } else {
                rc = 0;
            }
            break;
        }

        rc = pkd_exec_hello(fd, a);
        if (rc != 0) {
            pkderr("pkd_exec_hello: %d\n", rc);
            break;
        }
    }

    if (pkd_state.server_fd != -1) {
        close(pkd_state.server_fd);
    }
    pkd_state.server_fd = -1;
out:
    ctx.rc = rc;

    return NULL;
}

/*
 * pkd start and stop used by setup/teardown test scaffolding -----------
 */

int pkd_start(struct pkd_daemon_args *args) {
    int rc = 0;

    pkdout_enabled = args->opts.log_stdout;
    pkderr_enabled = args->opts.log_stderr;

    /* Initialize the pkd context. */
    ctx.rc = -1;
    ctx.keep_going = 1;
    ctx.pkd_ready = 0;
    rc = pthread_create(&ctx.tid, NULL, &pkd_main, args);
    assert_int_equal(rc, 0);

    /* Busy-spin until pkd thread is ready. */
    while (ctx.pkd_ready == 0);

    return rc;
}

void pkd_stop(struct pkd_result *out) {
    int rc = 0;

    ctx.keep_going = 0;
    close(pkd_state.server_fd);

    rc = pthread_kill(ctx.tid, SIGUSR1);
    assert_int_equal(rc, 0);

    rc = pthread_join(ctx.tid, NULL);
    assert_int_equal(rc, 0);

    assert_non_null(out);
    out->ok = (ctx.rc == 0);

    return;
}
