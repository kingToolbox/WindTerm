#include "config.h"

#define LIBSSH_STATIC
#include <libssh/priv.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "channels.c"

static void torture_channel_select(void **state)
{
    fd_set readfds;
    int fd;
    int rc;
    int i;

    (void)state; /* unused */

    ZERO_STRUCT(readfds);

    fd = open("/dev/null", 0);
    assert_true(fd > 2);

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    for (i = 0; i < 10; i++) {
        ssh_channel cin[1] = { NULL, };
        ssh_channel cout[1] = { NULL, };
        struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 };

        rc = ssh_select(cin, cout, fd + 1, &readfds, &tv);
        assert_int_equal(rc, SSH_OK);
    }

    close(fd);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_channel_select),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
