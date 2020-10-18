#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/libssh.h>
#include "libssh/priv.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>

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
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_USER, TORTURE_SSH_USER_ALICE);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

#ifdef NC_EXECUTABLE
static void torture_options_set_proxycommand(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    const char *address = torture_server_address(AF_INET);
    int port = torture_server_port();
    char command[255] = {0};
    struct stat sb;
    int rc;
    socket_t fd;

    rc = stat(NC_EXECUTABLE, &sb);
    if (rc != 0 || (sb.st_mode & S_IXOTH) == 0) {
        SSH_LOG(SSH_LOG_WARNING, "Could not find " NC_EXECUTABLE ": Skipping the test");
        skip();
    }

    rc = snprintf(command, sizeof(command), NC_EXECUTABLE " %s %d", address, port);
    assert_true((size_t)rc < sizeof(command));

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, command);
    assert_int_equal(rc, 0);
    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
    fd = ssh_get_fd(session);
    assert_true(fd != SSH_INVALID_SOCKET);
    rc = fcntl(fd, F_GETFL);
    assert_int_equal(rc & O_RDWR, O_RDWR);
}

#else /* NC_EXECUTABLE */

static void torture_options_set_proxycommand(void **state)
{
    (void) state;
    skip();
}

#endif /* NC_EXECUTABLE */

static void torture_options_set_proxycommand_notexist(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "this_command_does_not_exist");
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);
}

static void torture_options_set_proxycommand_ssh(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    const char *address = torture_server_address(AF_INET);
    char command[255] = {0};
    int rc;
    socket_t fd;

    rc = snprintf(command, sizeof(command),
                  "ssh -oStrictHostKeyChecking=no -W [%%h]:%%p alice@%s",
                  address);
    assert_true((size_t)rc < sizeof(command));

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, command);
    assert_int_equal(rc, 0);
    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
    fd = ssh_get_fd(session);
    assert_true(fd != SSH_INVALID_SOCKET);
    rc = fcntl(fd, F_GETFL);
    assert_int_equal(rc & O_RDWR, O_RDWR);
}

static void torture_options_set_proxycommand_ssh_stderr(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    const char *address = torture_server_address(AF_INET);
    char command[255] = {0};
    int rc;
    socket_t fd;

    /* The -vvv switches produce the desired output on the standard error */
    rc = snprintf(command, sizeof(command),
                  "ssh -vvv -oStrictHostKeyChecking=no -W [%%h]:%%p alice@%s",
                  address);
    assert_true((size_t)rc < sizeof(command));

    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, command);
    assert_int_equal(rc, 0);
    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
    fd = ssh_get_fd(session);
    assert_true(fd != SSH_INVALID_SOCKET);
    rc = fcntl(fd, F_GETFL);
    assert_int_equal(rc & O_RDWR, O_RDWR);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_options_set_proxycommand,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_proxycommand_notexist,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_proxycommand_ssh,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_options_set_proxycommand_ssh_stderr,
                                        session_setup,
                                        session_teardown),
    };


    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
