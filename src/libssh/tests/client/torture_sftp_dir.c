#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "sftp.c"

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

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

static void torture_sftp_mkdir(void **state) {
    struct torture_state *s = *state;

    struct torture_sftp *t = s->ssh.tsftp;
    char tmpdir[128] = {0};
    int rc;

    assert_non_null(t);

    snprintf(tmpdir, sizeof(tmpdir) - 1, "%s/mkdir_test", t->testdir);

    rc = sftp_mkdir(t->sftp, tmpdir, 0755);
    if(rc != SSH_OK)
        fprintf(stderr,"error:%s\n",ssh_get_error(t->sftp->session));
    assert_true(rc == 0);

    /* check if it really has been created */
    assert_true(torture_isdir(tmpdir));

    rc = sftp_rmdir(t->sftp, tmpdir);
    assert_true(rc == 0);

    /* check if it has been deleted */
    assert_false(torture_isdir(tmpdir));
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_sftp_mkdir,
                                        session_setup,
                                        session_teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();

    return rc;
}
