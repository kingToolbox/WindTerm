/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/libssh.h"

#include <pthread.h>

#define NUM_THREADS 20

static int run_on_threads(void *(*func)(void *))
{
    pthread_t threads[NUM_THREADS];
    int rc;
    int i;

    for (i = 0; i < NUM_THREADS; ++i) {
        rc = pthread_create(&threads[i], NULL, func, NULL);
        assert_int_equal(rc, 0);
    }

    for (i = 0; i < NUM_THREADS; ++i) {
        void *p = NULL;
        uint64_t *result;

        rc = pthread_join(threads[i], &p);
        assert_int_equal(rc, 0);

        result = (uint64_t *)p;
        assert_null(result);
    }

    return rc;
}

static void *thread_ssh_init(UNUSED_PARAM(void *threadid))
{
    int rc;

    (void) threadid;

    rc = ssh_init();
    assert_int_equal(rc, SSH_OK);

    rc = ssh_finalize();
    assert_int_equal(rc, SSH_OK);

    pthread_exit(NULL);
}

static void torture_ssh_init(UNUSED_PARAM(void **state))
{
    int rc;

    rc = run_on_threads(thread_ssh_init);
    assert_int_equal(rc, 0);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_ssh_init),
    };

    /*
     * If the library is statically linked, ssh_init() is not called
     * automatically
     */
    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
