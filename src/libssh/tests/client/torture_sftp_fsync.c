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

static void torture_sftp_fsync(void **state) {
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;

    char libssh_tmp_file[] = "/tmp/libssh_sftp_test_XXXXXX";
    char buf[MAX_XFER_BUF_SIZE] = {0};
    char buf_verify[MAX_XFER_BUF_SIZE] = {0};
    size_t count;
    size_t bytesread;
    ssize_t byteswritten;
    int fd;
    sftp_file file;
    mode_t mask;
    int rc;
    FILE *fp;
    struct stat sb;

    mask = umask(S_IRWXO | S_IRWXG);
    fd = mkstemp(libssh_tmp_file);
    umask(mask);
    assert_return_code(fd, errno);
    close(fd);
    unlink(libssh_tmp_file);

    file = sftp_open(t->sftp, libssh_tmp_file, O_WRONLY | O_CREAT, 0600);
    assert_non_null(file);

    rc = lstat(libssh_tmp_file, &sb);
    assert_return_code(rc, errno);

    snprintf(buf, sizeof(buf), "libssh fsync test\n");
    count = strlen(buf) + 1;

    byteswritten = sftp_write(file, buf, count);
    assert_int_equal(byteswritten, count);

    rc = sftp_fsync(file);
    assert_return_code(rc, errno);

    fp = fopen(libssh_tmp_file, "r");
    assert_non_null(fp);

    rc = fstat(fileno(fp), &sb);
    assert_return_code(rc, errno);

    bytesread = fread(buf_verify, sizeof(buf_verify), 1, fp);
    if (bytesread == 0) {
        if (!feof(fp)) {
            assert_int_equal(bytesread, count);
        }
    }
    assert_string_equal(buf, buf_verify);

    sftp_close(file);
    fclose(fp);
    unlink(libssh_tmp_file);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_sftp_fsync,
                                        session_setup,
                                        session_teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
