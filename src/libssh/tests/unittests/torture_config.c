#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/options.h"
#include "libssh/session.h"
#include "libssh/config_parser.h"
#include "match.c"

extern LIBSSH_THREAD int ssh_log_level;

#define LIBSSH_TESTCONFIG1 "libssh_testconfig1.tmp"
#define LIBSSH_TESTCONFIG2 "libssh_testconfig2.tmp"
#define LIBSSH_TESTCONFIG3 "libssh_testconfig3.tmp"
#define LIBSSH_TESTCONFIG4 "libssh_testconfig4.tmp"
#define LIBSSH_TESTCONFIG5 "libssh_testconfig5.tmp"
#define LIBSSH_TESTCONFIG6 "libssh_testconfig6.tmp"
#define LIBSSH_TESTCONFIG7 "libssh_testconfig7.tmp"
#define LIBSSH_TESTCONFIG8 "libssh_testconfig8.tmp"
#define LIBSSH_TESTCONFIG9 "libssh_testconfig9.tmp"
#define LIBSSH_TESTCONFIG10 "libssh_testconfig10.tmp"
#define LIBSSH_TESTCONFIG11 "libssh_testconfig11.tmp"
#define LIBSSH_TESTCONFIG12 "libssh_testconfig12.tmp"
#define LIBSSH_TESTCONFIGGLOB "libssh_testc*[36].tmp"
#define LIBSSH_TEST_PUBKEYACCEPTEDKEYTYPES "libssh_test_PubkeyAcceptedKeyTypes.tmp"

#define USERNAME "testuser"
#define PROXYCMD "ssh -q -W %h:%p gateway.example.com"
#define ID_FILE "/etc/xxx"
#define KEXALGORITHMS "ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha1"
#define HOSTKEYALGORITHMS "ssh-ed25519,ecdsa-sha2-nistp521,ssh-rsa"
#define PUBKEYACCEPTEDTYPES "rsa-sha2-512,ssh-rsa,ecdsa-sha2-nistp521"
#define MACS "hmac-sha1,hmac-sha2-256,hmac-sha2-512,hmac-sha1-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"
#define USER_KNOWN_HOSTS "%d/my_known_hosts"
#define GLOBAL_KNOWN_HOSTS "/etc/ssh/my_ssh_known_hosts"
#define BIND_ADDRESS "::1"



static int setup_config_files(void **state)
{
    ssh_session session;
    int verbosity;

    unlink(LIBSSH_TESTCONFIG1);
    unlink(LIBSSH_TESTCONFIG2);
    unlink(LIBSSH_TESTCONFIG3);
    unlink(LIBSSH_TESTCONFIG4);
    unlink(LIBSSH_TESTCONFIG5);
    unlink(LIBSSH_TESTCONFIG6);
    unlink(LIBSSH_TESTCONFIG7);
    unlink(LIBSSH_TESTCONFIG8);
    unlink(LIBSSH_TESTCONFIG9);
    unlink(LIBSSH_TESTCONFIG10);
    unlink(LIBSSH_TESTCONFIG11);
    unlink(LIBSSH_TESTCONFIG12);
    unlink(LIBSSH_TEST_PUBKEYACCEPTEDKEYTYPES);

    torture_write_file(LIBSSH_TESTCONFIG1,
                       "User "USERNAME"\nInclude "LIBSSH_TESTCONFIG2"\n\n");
    torture_write_file(LIBSSH_TESTCONFIG2,
                       "Include "LIBSSH_TESTCONFIG3"\n"
                       "ProxyCommand "PROXYCMD"\n\n");
    torture_write_file(LIBSSH_TESTCONFIG3,
                       "\n\nIdentityFile "ID_FILE"\n"
                       "\n\nKexAlgorithms "KEXALGORITHMS"\n"
                       "\n\nHostKeyAlgorithms "HOSTKEYALGORITHMS"\n"
                       "\n\nPubkeyAcceptedTypes "PUBKEYACCEPTEDTYPES"\n"
                       "\n\nMACs "MACS"\n");

    /* Multiple Port settings -> parsing returns early. */
    torture_write_file(LIBSSH_TESTCONFIG4,
                       "Port 123\nPort 456\n");

    /* Testing glob include */
    torture_write_file(LIBSSH_TESTCONFIG5,
                        "User "USERNAME"\nInclude "LIBSSH_TESTCONFIGGLOB"\n\n");

    torture_write_file(LIBSSH_TESTCONFIG6,
                        "ProxyCommand "PROXYCMD"\n\n");

    /* new options */
    torture_write_file(LIBSSH_TESTCONFIG7,
                        "\tBindAddress "BIND_ADDRESS"\n"
                        "\tConnectTimeout 30\n"
                        "\tLogLevel DEBUG3\n"
                        "\tGlobalKnownHostsFile "GLOBAL_KNOWN_HOSTS"\n"
                        "\tCompression yes\n"
                        "\tStrictHostkeyChecking no\n"
                        "\tGSSAPIDelegateCredentials yes\n"
                        "\tGSSAPIServerIdentity example.com\n"
                        "\tGSSAPIClientIdentity home.sweet\n"
                        "\tUserKnownHostsFile "USER_KNOWN_HOSTS"\n");

    /* authentication methods */
    torture_write_file(LIBSSH_TESTCONFIG8,
                        "Host gss\n"
                        "\tGSSAPIAuthentication yes\n"
                        "Host kbd\n"
                        "\tKbdInteractiveAuthentication yes\n"
                        "Host pass\n"
                        "\tPasswordAuthentication yes\n"
                        "Host pubkey\n"
                        "\tPubkeyAuthentication yes\n"
                        "Host nogss\n"
                        "\tGSSAPIAuthentication no\n"
                        "Host nokbd\n"
                        "\tKbdInteractiveAuthentication no\n"
                        "Host nopass\n"
                        "\tPasswordAuthentication no\n"
                        "Host nopubkey\n"
                        "\tPubkeyAuthentication no\n");

    /* unsupported options and corner cases */
    torture_write_file(LIBSSH_TESTCONFIG9,
                        "\n" /* empty line */
                        "# comment line\n"
                        "  # comment line not starting with hash\n"
                        "UnknownConfigurationOption yes\n"
                        "GSSAPIKexAlgorithms yes\n"
                        "ControlMaster auto\n" /* SOC_NA */
                        "VisualHostkey yes\n" /* SOC_UNSUPPORTED */
                        "");

    /* Match keyword */
    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match host example\n"
                       "\tHostName example.com\n"
                       "Match host example1,example2\n"
                       "\tHostName exampleN\n"
                       "Match user guest\n"
                       "\tHostName guest.com\n"
                       "Match user tester host testhost\n"
                       "\tHostName testhost.com\n"
                       "Match !user tester host testhost\n"
                       "\tHostName nonuser-testhost.com\n"
                       "Match all\n"
                       "\tHostName all-matched.com\n"
                       /* Unsupported options */
                       "Match originalhost example\n"
                       "\tHostName original-example.com\n"
                       "Match localuser guest\n"
                       "\tHostName local-guest.com\n"
                       "");

    /* ProxyJump */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host simple\n"
                       "\tProxyJump jumpbox\n"
                       "Host user\n"
                       "\tProxyJump user@jumpbox\n"
                       "Host port\n"
                       "\tProxyJump jumpbox:2222\n"
                       "Host two-step\n"
                       "\tProxyJump u1@first:222,u2@second:33\n"
                       "Host none\n"
                       "\tProxyJump none\n"
                       "Host only-command\n"
                       "\tProxyCommand "PROXYCMD"\n"
                       "\tProxyJump jumpbox\n"
                       "Host only-jump\n"
                       "\tProxyJump jumpbox\n"
                       "\tProxyCommand "PROXYCMD"\n"
                       "Host ipv6\n"
                       "\tProxyJump [2620:52:0::fed]\n"
                       "");

    /* RekeyLimit combinations */
    torture_write_file(LIBSSH_TESTCONFIG12,
                       "Host default\n"
                       "\tRekeyLimit default none\n"
                       "Host data1\n"
                       "\tRekeyLimit 42G\n"
                       "Host data2\n"
                       "\tRekeyLimit 31M\n"
                       "Host data3\n"
                       "\tRekeyLimit 521K\n"
                       "Host time1\n"
                       "\tRekeyLimit default 3D\n"
                       "Host time2\n"
                       "\tRekeyLimit default 2h\n"
                       "Host time3\n"
                       "\tRekeyLimit default 160m\n"
                       "Host time4\n"
                       "\tRekeyLimit default 9600\n"
                       "");

    torture_write_file(LIBSSH_TEST_PUBKEYACCEPTEDKEYTYPES,
                       "PubkeyAcceptedKeyTypes "PUBKEYACCEPTEDTYPES"\n");

    session = ssh_new();

    verbosity = torture_libssh_verbosity();
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    *state = session;

    return 0;
}

static int teardown(void **state)
{
    unlink(LIBSSH_TESTCONFIG1);
    unlink(LIBSSH_TESTCONFIG2);
    unlink(LIBSSH_TESTCONFIG3);
    unlink(LIBSSH_TESTCONFIG4);
    unlink(LIBSSH_TESTCONFIG5);
    unlink(LIBSSH_TESTCONFIG6);
    unlink(LIBSSH_TESTCONFIG7);
    unlink(LIBSSH_TESTCONFIG8);
    unlink(LIBSSH_TESTCONFIG9);
    unlink(LIBSSH_TESTCONFIG10);
    unlink(LIBSSH_TESTCONFIG11);
    unlink(LIBSSH_TESTCONFIG12);
    unlink(LIBSSH_TEST_PUBKEYACCEPTEDKEYTYPES);

    ssh_free(*state);

    return 0;
}

/**
 * @brief tests ssh_config_parse_file with Include directives
 */
static void torture_config_from_file(void **state) {
    ssh_session session = *state;
    int ret;
    char *v = NULL;
    char *fips_algos = NULL;

    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG1);
    assert_true(ret == 0);

    /* Test the variable presence */

    ret = ssh_options_get(session, SSH_OPTIONS_PROXYCOMMAND, &v);
    assert_true(ret == 0);
    assert_non_null(v);

    assert_string_equal(v, PROXYCMD);
    SSH_STRING_FREE_CHAR(v);

    ret = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &v);
    assert_true(ret == 0);
    assert_non_null(v);

    assert_string_equal(v, ID_FILE);
    SSH_STRING_FREE_CHAR(v);

    ret = ssh_options_get(session, SSH_OPTIONS_USER, &v);
    assert_true(ret == 0);
    assert_non_null(v);

    assert_string_equal(v, USERNAME);
    SSH_STRING_FREE_CHAR(v);

    if (ssh_fips_mode()) {
        fips_algos = ssh_keep_fips_algos(SSH_KEX, KEXALGORITHMS);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.wanted_methods[SSH_KEX], fips_algos);
        SAFE_FREE(fips_algos);
        fips_algos = ssh_keep_fips_algos(SSH_HOSTKEYS, HOSTKEYALGORITHMS);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS], fips_algos);
        SAFE_FREE(fips_algos);
        fips_algos = ssh_keep_fips_algos(SSH_HOSTKEYS, PUBKEYACCEPTEDTYPES);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.pubkey_accepted_types, fips_algos);
        SAFE_FREE(fips_algos);
        fips_algos = ssh_keep_fips_algos(SSH_MAC_C_S, MACS);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.wanted_methods[SSH_MAC_C_S], fips_algos);
        SAFE_FREE(fips_algos);
        fips_algos = ssh_keep_fips_algos(SSH_MAC_S_C, MACS);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C], fips_algos);
        SAFE_FREE(fips_algos);
    } else {
        assert_non_null(session->opts.wanted_methods[SSH_KEX]);
        assert_string_equal(session->opts.wanted_methods[SSH_KEX], KEXALGORITHMS);
        assert_non_null(session->opts.wanted_methods[SSH_HOSTKEYS]);
        assert_string_equal(session->opts.wanted_methods[SSH_HOSTKEYS], HOSTKEYALGORITHMS);
        assert_non_null(session->opts.pubkey_accepted_types);
        assert_string_equal(session->opts.pubkey_accepted_types, PUBKEYACCEPTEDTYPES);
        assert_non_null(session->opts.wanted_methods[SSH_MAC_S_C]);
        assert_string_equal(session->opts.wanted_methods[SSH_MAC_C_S], MACS);
        assert_non_null(session->opts.wanted_methods[SSH_MAC_S_C]);
        assert_string_equal(session->opts.wanted_methods[SSH_MAC_S_C], MACS);
    }
}

/**
 * @brief tests ssh_config_parse_file with multiple Port settings.
 */
static void torture_config_double_ports(void **state) {
    ssh_session session = *state;
    int ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG4);
    assert_true(ret == 0);
}

static void torture_config_glob(void **state) {
    ssh_session session = *state;
    int ret;
#if defined(HAVE_GLOB) && defined(HAVE_GLOB_GL_FLAGS_MEMBER)
    char *v;
#endif /* HAVE_GLOB && HAVE_GLOB_GL_FLAGS_MEMBER */

    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG5);
    assert_true(ret == 0); /* non-existing files should not error */

    /* Test the variable presence */

#if defined(HAVE_GLOB) && defined(HAVE_GLOB_GL_FLAGS_MEMBER)
    ret = ssh_options_get(session, SSH_OPTIONS_PROXYCOMMAND, &v);
    assert_true(ret == 0);
    assert_non_null(v);

    assert_string_equal(v, PROXYCMD);
    SSH_STRING_FREE_CHAR(v);

    ret = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &v);
    assert_true(ret == 0);
    assert_non_null(v);

    assert_string_equal(v, ID_FILE);
    SSH_STRING_FREE_CHAR(v);
#endif /* HAVE_GLOB && HAVE_GLOB_GL_FLAGS_MEMBER */
}

/**
 * @brief Verify the new options are passed from configuration
 */
static void torture_config_new(void **state)
{
    ssh_session session = *state;
    int ret = 0;

    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG7);
    assert_true(ret == 0);

    assert_string_equal(session->opts.knownhosts, USER_KNOWN_HOSTS);
    assert_string_equal(session->opts.global_knownhosts, GLOBAL_KNOWN_HOSTS);
    assert_int_equal(session->opts.timeout, 30);
    assert_string_equal(session->opts.bindaddr, BIND_ADDRESS);
#ifdef WITH_ZLIB
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_C_S],
                        "zlib@openssh.com,zlib");
    assert_string_equal(session->opts.wanted_methods[SSH_COMP_S_C],
                        "zlib@openssh.com,zlib");
#else
    assert_null(session->opts.wanted_methods[SSH_COMP_C_S]);
    assert_null(session->opts.wanted_methods[SSH_COMP_S_C]);
#endif /* WITH_ZLIB */
    assert_int_equal(session->opts.StrictHostKeyChecking, 0);
    assert_int_equal(session->opts.gss_delegate_creds, 1);
    assert_string_equal(session->opts.gss_server_identity, "example.com");
    assert_string_equal(session->opts.gss_client_identity, "home.sweet");

    assert_int_equal(ssh_get_log_level(), SSH_LOG_TRACE);
    assert_int_equal(session->common.log_verbosity, SSH_LOG_TRACE);
}

/**
 * @brief Verify the authentication methods from configuration are effective
 */
static void torture_config_auth_methods(void **state) {
    ssh_session session = *state;
    int ret = 0;

    /* gradually disable all the methods based on different hosts */
    ssh_options_set(session, SSH_OPTIONS_HOST, "nogss");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_false(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);
    assert_true(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "nokbd");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_false(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "nopass");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_false(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "nopubkey");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_false(session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH);

    /* no method should be left enabled */
    assert_int_equal(session->opts.flags, 0);

    /* gradually enable them again */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "gss");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_true(session->opts.flags & SSH_OPT_FLAG_GSSAPI_AUTH);
    assert_false(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "kbd");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_true(session->opts.flags & SSH_OPT_FLAG_KBDINT_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "pass");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_true(session->opts.flags & SSH_OPT_FLAG_PASSWORD_AUTH);

    ssh_options_set(session, SSH_OPTIONS_HOST, "pubkey");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG8);
    assert_true(ret == 0);
    assert_true(session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH);
}

/**
 * @brief Verify the configuration parser does not choke on unknown
 * or unsupported configuration options
 */
static void torture_config_unknown(void **state) {
    ssh_session session = *state;
    int ret = 0;

    /* test corner cases */
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG9);
    assert_true(ret == 0);
    ret = ssh_config_parse_file(session, "/etc/ssh/ssh_config");
    assert_true(ret == 0);
    ret = ssh_config_parse_file(session, GLOBAL_CLIENT_CONFIG);
    assert_true(ret == 0);
}


/**
 * @brief Verify the configuration parser accepts Match keyword with
 * full OpenSSH syntax.
 */
static void torture_config_match(void **state)
{
    ssh_session session = *state;
    char *localuser = NULL;
    char config[1024];
    int ret = 0;

    /* Without any settings we should get all-matched.com hostname */
    ssh_options_set(session, SSH_OPTIONS_HOST, "unmatched");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "all-matched.com");

    /* Hostname example does simple hostname matching */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "example.com");

    /* We can match also both hosts from a comma separated list */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example1");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "exampleN");

    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "example2");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "exampleN");

    /* We can match by user */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_USER, "guest");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "guest.com");

    /* We can combine two options on a single line to match both of them */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_USER, "tester");
    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "testhost.com");

    /* We can also negate conditions */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_USER, "not-tester");
    ssh_options_set(session, SSH_OPTIONS_HOST, "testhost");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "nonuser-testhost.com");

    /* Match final is not completely supported, but should do quite much the
     * same as "match all". The trailing "all" is not mandatory. */
    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match final all\n"
                       "\tHostName final-all.com\n"
                       "");
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "final-all.com");

    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match final\n"
                       "\tHostName final.com\n"
                       "");
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "final.com");

    /* Match canonical is not completely supported, but should do quite much the
     * same as "match all". The trailing "all" is not mandatory. */
    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match canonical all\n"
                       "\tHostName canonical-all.com\n"
                       "");
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "canonical-all.com");

    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match canonical all\n"
                       "\tHostName canonical.com\n"
                       "");
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "canonical.com");

    localuser = ssh_get_local_username();
    assert_non_null(localuser);
    snprintf(config, sizeof(config),
             "Match localuser %s\n"
             "\tHostName otherhost\n"
             "", localuser);
    free(localuser);
    torture_write_file(LIBSSH_TESTCONFIG10, config);
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.host, "otherhost");

    /* Try to create some invalid configurations */
    /* Missing argument to Match*/
    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match\n"
                       "\tHost missing.com\n"
                       "");
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing argument to unsupported option originalhost */
    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match originalhost\n"
                       "\tHost originalhost.com\n"
                       "");
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing argument to option localuser */
    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match localuser\n"
                       "\tUser localuser2\n"
                       "");
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing argument to option user */
    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match user\n"
                       "\tUser user2\n"
                       "");
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing argument to option host */
    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match host\n"
                       "\tUser host2\n"
                       "");
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing argument to unsupported option exec */
    torture_write_file(LIBSSH_TESTCONFIG10,
                       "Match exec\n"
                       "\tUser exec\n"
                       "");
    torture_reset_config(session);
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG10);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);
}

/**
 * @brief Verify we can parse ProxyJump configuration option
 */
static void torture_config_proxyjump(void **state) {
    ssh_session session = *state;
    int ret = 0;

    /* Simplest version with just a hostname */
    ssh_options_set(session, SSH_OPTIONS_HOST, "simple");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.ProxyCommand, "ssh -W [%h]:%p jumpbox");

    /* With username */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "user");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -l user -W [%h]:%p jumpbox");

    /* With port */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "port");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -p 2222 -W [%h]:%p jumpbox");

    /* Two step jump */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "two-step");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -l u1 -p 222 -J u2@second:33 -W [%h]:%p first");

    /* none */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "none");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code(session, ret);
    assert_true(session->opts.ProxyCommand == NULL);

    /* If also ProxyCommand is specifed, the first is applied */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "only-command");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.ProxyCommand, PROXYCMD);

    /* If also ProxyCommand is specifed, the first is applied */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "only-jump");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -W [%h]:%p jumpbox");

    /* IPv6 address */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "ipv6");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code(session, ret);
    assert_string_equal(session->opts.ProxyCommand,
                        "ssh -W [%h]:%p 2620:52:0::fed");

    /* Try to create some invalid configurations */
    /* Non-numeric port */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host bad-port\n"
                       "\tProxyJump jumpbox:22bad22\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "bad-port");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Too many @ */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host bad-hostname\n"
                       "\tProxyJump user@principal.com@jumpbox:22\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "bad-hostname");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Braces mismatch in hostname */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host mismatch\n"
                       "\tProxyJump [::1\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "mismatch");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Bad host-port separator */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host beef\n"
                       "\tProxyJump [dead::beef]::22\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "beef");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing hostname */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host no-host\n"
                       "\tProxyJump user@:22\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-host");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing user */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host no-user\n"
                       "\tProxyJump @host:22\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-user");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing port */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host no-port\n"
                       "\tProxyJump host:\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-port");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Non-numeric port in second jump */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host bad-port-2\n"
                       "\tProxyJump localhost,jumpbox:22bad22\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "bad-port-2");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Too many @ in second jump */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host bad-hostname\n"
                       "\tProxyJump localhost,user@principal.com@jumpbox:22\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "bad-hostname");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Braces mismatch in second jump */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host mismatch\n"
                       "\tProxyJump localhost,[::1:20\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "mismatch");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Bad host-port separator in second jump */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host beef\n"
                       "\tProxyJump localhost,[dead::beef]::22\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "beef");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing hostname in second jump */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host no-host\n"
                       "\tProxyJump localhost,user@:22\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-host");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing user in second jump */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host no-user\n"
                       "\tProxyJump localhost,@host:22\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-user");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);

    /* Missing port in second jump */
    torture_write_file(LIBSSH_TESTCONFIG11,
                       "Host no-port\n"
                       "\tProxyJump localhost,host:\n"
                       "");
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "no-port");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG11);
    assert_ssh_return_code_equal(session, ret, SSH_ERROR);
}

/**
 * @brief Verify the configuration parser handles all the possible
 * versions of RekeyLimit configuration option.
 */
static void torture_config_rekey(void **state)
{
    ssh_session session = *state;
    int ret = 0;

    /* Default values */
    ssh_options_set(session, SSH_OPTIONS_HOST, "default");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG12);
    assert_ssh_return_code(session, ret);
    assert_int_equal(session->opts.rekey_data, 0);
    assert_int_equal(session->opts.rekey_time, 0);

    /* 42 GB */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "data1");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG12);
    assert_ssh_return_code(session, ret);
    assert_int_equal(session->opts.rekey_data, (uint64_t) 42 * 1024 * 1024 * 1024);
    assert_int_equal(session->opts.rekey_time, 0);

    /* 41 MB */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "data2");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG12);
    assert_ssh_return_code(session, ret);
    assert_int_equal(session->opts.rekey_data, 31 * 1024 * 1024);
    assert_int_equal(session->opts.rekey_time, 0);

    /* 521 KB */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "data3");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG12);
    assert_ssh_return_code(session, ret);
    assert_int_equal(session->opts.rekey_data, 521 * 1024);
    assert_int_equal(session->opts.rekey_time, 0);

    /* default 3D */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "time1");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG12);
    assert_ssh_return_code(session, ret);
    assert_int_equal(session->opts.rekey_data, 0);
    assert_int_equal(session->opts.rekey_time, 3 * 24 * 60 * 60 * 1000);

    /* default 2h */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "time2");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG12);
    assert_ssh_return_code(session, ret);
    assert_int_equal(session->opts.rekey_data, 0);
    assert_int_equal(session->opts.rekey_time, 2 * 60 * 60 * 1000);

    /* default 160m */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "time3");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG12);
    assert_ssh_return_code(session, ret);
    assert_int_equal(session->opts.rekey_data, 0);
    assert_int_equal(session->opts.rekey_time, 160 * 60 * 1000);

    /* default 9600 [s] */
    torture_reset_config(session);
    ssh_options_set(session, SSH_OPTIONS_HOST, "time4");
    ret = ssh_config_parse_file(session, LIBSSH_TESTCONFIG12);
    assert_ssh_return_code(session, ret);
    assert_int_equal(session->opts.rekey_data, 0);
    assert_int_equal(session->opts.rekey_time, 9600 * 1000);

}

/**
 * @brief test ssh_config_parse_file with PubkeyAcceptedKeyTypes
 */
static void torture_config_pubkeyacceptedkeytypes(void **state)
{
    ssh_session session = *state;
    int rc;
    char *fips_algos;

    rc = ssh_config_parse_file(session, LIBSSH_TEST_PUBKEYACCEPTEDKEYTYPES);
    assert_int_equal(rc, SSH_OK);

    if (ssh_fips_mode()) {
        fips_algos = ssh_keep_fips_algos(SSH_HOSTKEYS, PUBKEYACCEPTEDTYPES);
        assert_non_null(fips_algos);
        assert_string_equal(session->opts.pubkey_accepted_types, fips_algos);
        SAFE_FREE(fips_algos);
    } else {
        assert_string_equal(session->opts.pubkey_accepted_types, PUBKEYACCEPTEDTYPES);
    }
}

/* match_pattern() sanity tests
 */
static void torture_config_match_pattern(void **state)
{
    int rv = 0;

    (void) state;

    /* Simple test "a" matches "a" */
    rv = match_pattern("a", "a", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);

    /* Simple test "a" does not match "b" */
    rv = match_pattern("a", "b", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 0);

    /* NULL arguments are correctly handled */
    rv = match_pattern("a", NULL, MAX_MATCH_RECURSION);
    assert_int_equal(rv, 0);
    rv = match_pattern(NULL, "a", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 0);

    /* Simple wildcard ? is handled in pattern */
    rv = match_pattern("a", "?", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);
    rv = match_pattern("aa", "?", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 0);
    rv = match_pattern("?", "a", MAX_MATCH_RECURSION); /* Wildcard in search string */
    assert_int_equal(rv, 0);
    rv = match_pattern("?", "?", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);

    /* Simple wildcard * is handled in pattern */
    rv = match_pattern("a", "*", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);
    rv = match_pattern("aa", "*", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);
    rv = match_pattern("*", "a", MAX_MATCH_RECURSION); /* Wildcard in search string */
    assert_int_equal(rv, 0);
    rv = match_pattern("*", "*", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);

    /* More complicated patterns */
    rv = match_pattern("a", "*a", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);
    rv = match_pattern("a", "a*", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);
    rv = match_pattern("abababc", "*abc", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);
    rv = match_pattern("ababababca", "*abc", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 0);
    rv = match_pattern("ababababca", "*abc*", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);

    /* Multiple wildcards in row */
    rv = match_pattern("aa", "??", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);
    rv = match_pattern("bba", "??a", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);
    rv = match_pattern("aaa", "**a", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 1);
    rv = match_pattern("bbb", "**a", MAX_MATCH_RECURSION);
    assert_int_equal(rv, 0);

    /* Consecutive asterisks do not make sense and do not need to recurse */
    rv = match_pattern("hostname", "**********pattern", 5);
    assert_int_equal(rv, 0);
    rv = match_pattern("hostname", "pattern**********", 5);
    assert_int_equal(rv, 0);
    rv = match_pattern("pattern", "***********pattern", 5);
    assert_int_equal(rv, 1);
    rv = match_pattern("pattern", "pattern***********", 5);
    assert_int_equal(rv, 1);

    /* Limit the maximum recursion */
    rv = match_pattern("hostname", "*p*a*t*t*e*r*n*", 5);
    assert_int_equal(rv, 0);
    rv = match_pattern("pattern", "*p*a*t*t*e*r*n*", 5); /* Too much recursion */
    assert_int_equal(rv, 0);

}


int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_config_from_file),
        cmocka_unit_test(torture_config_double_ports),
        cmocka_unit_test(torture_config_glob),
        cmocka_unit_test(torture_config_new),
        cmocka_unit_test(torture_config_auth_methods),
        cmocka_unit_test(torture_config_unknown),
        cmocka_unit_test(torture_config_match),
        cmocka_unit_test(torture_config_proxyjump),
        cmocka_unit_test(torture_config_rekey),
        cmocka_unit_test(torture_config_pubkeyacceptedkeytypes),
        cmocka_unit_test(torture_config_match_pattern),
    };


    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, setup_config_files, teardown);
    ssh_finalize();
    return rc;
}
