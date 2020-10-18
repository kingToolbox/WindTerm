#define LIBSSH_STATIC

#include "config.h"

#include "torture.h"
#include "sftp.c"

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#define MAX_XFER_BUF_SIZE 16384

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);

    return 0;
}

static int sshd_teardown(void **state) {
    torture_teardown_sshd_server(state);

    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = torture_ssh_session(s,
                                         TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    s->ssh.tsftp = torture_sftp_session(s->ssh.session);
    assert_non_null(s->ssh.tsftp);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    torture_rmdirs(s->ssh.tsftp->testdir);
    torture_sftp_close(s->ssh.tsftp);
    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_sftp_benchmark_write_read(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;
    sftp_session sftp = t->sftp;
    ssh_session session = s->ssh.session;
    sftp_file file = NULL;
    struct stat sb = {
        .st_size = 0,
    };
    uint8_t buf_16k[MAX_XFER_BUF_SIZE];
    char local_path[1024] = {0};
    ssize_t bwritten, nread;
    size_t i;
    int rc;

    memset(buf_16k, 'X', sizeof(buf_16k));

    snprintf(local_path, sizeof(local_path), "%s/128M.dat", t->testdir);

    file = sftp_open(sftp, local_path, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    assert_non_null(file);

    /* Write 128M */
    for (i = 0; i < 0x2000; i++) {
        bwritten = sftp_write(file, buf_16k, sizeof(buf_16k));
        assert_int_equal(bwritten, sizeof(buf_16k));
    }

    rc = sftp_close(file);
    assert_ssh_return_code(session, rc);

    /* Check that 128M has been written */
    rc = stat(local_path, &sb);
    assert_int_equal(sb.st_size, 0x8000000);

    file = sftp_open(sftp, local_path, O_RDONLY, 0);
    assert_non_null(file);

    for (;;) {
        nread = sftp_read(file, buf_16k, sizeof(buf_16k));
        if (nread == 0) {
            break; /* EOF */
        }
        assert_int_equal(nread, sizeof(buf_16k));
    }

    rc = sftp_close(file);
    assert_ssh_return_code(session, rc);

    unlink(local_path);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_sftp_benchmark_write_read,
                                        session_setup,
                                        session_teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
