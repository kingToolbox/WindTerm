#include "config.h"

#define LIBSSH_STATIC
#include <libssh/priv.h>
#include <libssh/callbacks.h>
#include <pthread.h>
#include <errno.h>
#include "torture.h"

#ifdef HAVE_LIBGCRYPT
#define NUM_LOOPS 1000
#else
/* openssl is much faster */
#define NUM_LOOPS 20000
#endif
#define NUM_THREADS 100

static int setup(void **state) {
    int rc;

    (void) state;

    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    rc = ssh_init();
    if (rc != SSH_OK) {
        return -1;
    }

    return 0;
}

static int teardown(void **state) {
    (void) state;

    ssh_finalize();

    return 0;
}

static void *torture_rand_thread(void *threadid) {
    char buffer[12];
    int i;
    int ok;

    (void) threadid;

    buffer[0] = buffer[1] = buffer[10] = buffer[11] = 'X';
    for(i = 0; i < NUM_LOOPS; ++i) {
        ok = ssh_get_random(&buffer[2], i % 8 + 1, 0);
        assert_true(ok);
    }

    pthread_exit(NULL);
}

static void torture_rand_threading(void **state) {
    pthread_t threads[NUM_THREADS];
    int i;
    int err;

    (void) state;

    for(i = 0; i < NUM_THREADS; ++i) {
        err = pthread_create(&threads[i], NULL, torture_rand_thread, NULL);
        assert_int_equal(err, 0);
    }
    for(i = 0; i < NUM_THREADS; ++i) {
        err=pthread_join(threads[i], NULL);
        assert_int_equal(err, 0);
    }
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_rand_threading, setup, teardown),
    };

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);

    return rc;
}
