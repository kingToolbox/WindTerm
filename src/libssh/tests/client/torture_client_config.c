#include "config.h"

#define LIBSSH_STATIC

#include <pwd.h>
#include <errno.h>
#include "torture.h"
#include "libssh/session.h"
#include "libssh/misc.h"

#define LIBSSH_SSH_CONFIG "libssh_config"

#define TORTURE_CONFIG_USER "test-user"

#define CIPHERS "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"
#define CIPHERS2 "aes256-cbc,aes128-ctr"

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);

    return 0;
}

static int sshd_teardown(void **state) {
    torture_teardown_sshd_server(state);

    return 0;
}

static int setup_config_files(void **state)
{
    struct torture_state *s = *state;
    int verbosity;
    struct passwd *pwd;
    char *filename = NULL;
    int rc;

    /* Work under the bob's UID to be able to load his configuration file */
    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    filename = ssh_path_expand_tilde("~/.ssh/config");
    torture_write_file(filename, "Ciphers "CIPHERS"\nTestBogus1\nUser "TORTURE_CONFIG_USER);
    free(filename);

    torture_write_file(LIBSSH_SSH_CONFIG, "Ciphers "CIPHERS2"\nTestBogus2\n");

    verbosity = torture_libssh_verbosity();
    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);

    return 0;
}

static int teardown(void **state)
{
    struct torture_state *s = *state;
    char *filename;

    filename = ssh_path_expand_tilde("~/.ssh/config");
    if (filename != NULL) {
        if (strlen(filename) > 0) {
            unlink(filename);
        }
        SAFE_FREE(filename);
    }

    unlink(LIBSSH_SSH_CONFIG);

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

/* This tests makes sure that parsing both system-wide and per-user
 * configuration files retains OpenSSH semantics (the per-user overrides
 * the system-wide values).
 * This function ssh_options_parse_config() has hardcoded path to the
 * system-wide configuration file so this might not test anything at all
 * if this system-wide file does not overwrite this option.
 */
static void torture_client_config_system(void **state)
{
    struct torture_state *s = *state;
    int ret = 0;

    char *fips_ciphers = NULL;

    if (ssh_fips_mode()) {
        fips_ciphers = ssh_keep_fips_algos(SSH_CRYPT_C_S, CIPHERS);
        assert_non_null(fips_ciphers);
    }

    /* The first tests assumes there is system-wide configuration file
     * setting Ciphers to some non-default value. We do not have any control
     * of that in this test case.
     */
    ret = ssh_options_parse_config(s->ssh.session, NULL);
    assert_ssh_return_code(s->ssh.session, ret);

    assert_non_null(s->ssh.session->opts.wanted_methods[SSH_CRYPT_C_S]);
    assert_non_null(s->ssh.session->opts.wanted_methods[SSH_CRYPT_S_C]);
    if (ssh_fips_mode()) {
        assert_string_equal(s->ssh.session->opts.wanted_methods[SSH_CRYPT_C_S],
                            fips_ciphers);
        assert_string_equal(s->ssh.session->opts.wanted_methods[SSH_CRYPT_S_C],
                            fips_ciphers);
    } else {
        assert_string_equal(s->ssh.session->opts.wanted_methods[SSH_CRYPT_C_S],
                            CIPHERS);
        assert_string_equal(s->ssh.session->opts.wanted_methods[SSH_CRYPT_S_C],
                            CIPHERS);
    }

    /* Make sure the configuration was processed and user modified */
    assert_string_equal(s->ssh.session->opts.username, TORTURE_CONFIG_USER);

    SAFE_FREE(fips_ciphers);
}

/* This tests makes sure that parsing both system-wide and per-user
 * configuration files retains OpenSSH semantics (the per-user overrides
 * the system-wide values).
 * The function ssh_options_parse_config() has hardcoded path to the
 * system-wide configuraion file so we try to emmulate the behavior by parsing
 * the files separately in the same order.
 */
static void torture_client_config_emulate(void **state)
{
    struct torture_state *s = *state;
    char *filename = NULL;
    int ret = 0;

    char *fips_ciphers = NULL;

    if (ssh_fips_mode()) {
        fips_ciphers = ssh_keep_fips_algos(SSH_CRYPT_C_S, CIPHERS);
        assert_non_null(fips_ciphers);
    }

    /* The first tests assumes there is system-wide configuration file
     * setting Ciphers to some non-default value. We do not have any control
     * of that in this test case
     */
    filename = ssh_path_expand_tilde("~/.ssh/config");
    ret = ssh_options_parse_config(s->ssh.session, filename);
    free(filename);
    assert_ssh_return_code(s->ssh.session, ret);

    ret = ssh_options_parse_config(s->ssh.session, LIBSSH_SSH_CONFIG);
    assert_ssh_return_code(s->ssh.session, ret);

    assert_non_null(s->ssh.session->opts.wanted_methods[SSH_CRYPT_C_S]);
    assert_non_null(s->ssh.session->opts.wanted_methods[SSH_CRYPT_S_C]);
    if (ssh_fips_mode()) {
        assert_string_equal(s->ssh.session->opts.wanted_methods[SSH_CRYPT_C_S],
                            fips_ciphers);
        assert_string_equal(s->ssh.session->opts.wanted_methods[SSH_CRYPT_S_C],
                            fips_ciphers);
    } else {
        assert_string_equal(s->ssh.session->opts.wanted_methods[SSH_CRYPT_C_S],
                            CIPHERS);
        assert_string_equal(s->ssh.session->opts.wanted_methods[SSH_CRYPT_S_C],
                            CIPHERS);
    }
    /* Make sure the configuration was processed and user modified */
    assert_string_equal(s->ssh.session->opts.username, TORTURE_CONFIG_USER);

    SAFE_FREE(fips_ciphers);
}

/* This verifies that configuration files are parsed by default.
 */
static void torture_client_config_autoparse(void **state)
{
    struct torture_state *s = *state;
    int ret = 0;

    ret = ssh_connect(s->ssh.session);
    assert_ssh_return_code(s->ssh.session, ret);

    /* Make sure the configuration was processed and user modified */
    assert_string_equal(s->ssh.session->opts.username, TORTURE_CONFIG_USER);
}

/* This verifies that we are able to suppress parsing of the configuration files
 * on connect using an option.
 */
static void torture_client_config_suppress(void **state)
{
    struct torture_state *s = *state;
    bool b = false;
    int ret = 0;

    ret = ssh_options_set(s->ssh.session, SSH_OPTIONS_PROCESS_CONFIG, &b);
    assert_ssh_return_code(s->ssh.session, ret);

    ret = ssh_connect(s->ssh.session);
    assert_ssh_return_code(s->ssh.session, ret);

    /* Make sure the configuration was not processed and user modified */
    assert_string_equal(s->ssh.session->opts.username, "bob");
}


int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_client_config_system,
                                        setup_config_files,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_client_config_emulate,
                                        setup_config_files,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_client_config_autoparse,
                                        setup_config_files,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_client_config_suppress,
                                        setup_config_files,
                                        teardown),
    };


    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();
    return rc;
}
