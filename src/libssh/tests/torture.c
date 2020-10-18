/*
 * torture.c - torture library for testing libssh
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008-2009 by Andreas Schneider <asn@cryptomilk.org>
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
#include "tests_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#ifndef _WIN32
# include <dirent.h>
# include <errno.h>
# include <sys/socket.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#elif (defined _WIN32) || (defined _WIN64)
#include <direct.h>
#include <io.h>
#define read _read
#define open _open
#define write _write
#define close _close
#define chdir _chdir
#endif

#include "torture.h"
#include "torture_key.h"
#include "libssh/misc.h"

#define TORTURE_SSHD_SRV_IPV4 "127.0.0.10"
/* socket wrapper IPv6 prefix  fd00::5357:5fxx */
#define TORTURE_SSHD_SRV_IPV6 "fd00::5357:5f0a"
#define TORTURE_SSHD_SRV_PORT 22

#define TORTURE_SOCKET_DIR "/tmp/test_socket_wrapper_XXXXXX"
#define TORTURE_SSHD_PIDFILE "sshd/sshd.pid"
#define TORTURE_SSHD_CONFIG "sshd/sshd_config"
#define TORTURE_PCAP_FILE "socket_trace.pcap"

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

static const char torture_rsa_certauth_pub[]=
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCnA2n5vHzZbs/GvRkGloJNV1CXHI"
        "S5Xnrm05HusUJSWyPq3I1iCMHdYA7oezHa9GCFYbIenaYPy+G6USQRjYQz8SvAZo06"
        "SFNeJSsa1kAIqxzdPT9kBrRrYK39PZQPsYVfRPqZBdmc+jwrfz97IFEJyXMI47FoTG"
        "kgEq7eu3z2px/tdIZ34I5Hr5DDBxicZi4jluyRUJHfSPoBxyhF7OkPX4bYkrc691je"
        "IQDxubl650WYLHgFfad0xTzBIFE6XUb55Dp5AgRdevSoso1Pe0IKFxxMVpP664LCbY"
        "K06Lv6kcotfFlpvUtR1yx8jToGcSoq5sSzTwvXSHCQQ9ZA1hvF "
        "torture_certauth_key";

static int verbosity = 0;
static const char *pattern = NULL;

#ifndef _WIN32

static int _torture_auth_kbdint(ssh_session session,
                               const char *password) {
    const char *prompt;
    char echo;
    int err;

    if (session == NULL || password == NULL) {
        return SSH_AUTH_ERROR;
    }

    err = ssh_userauth_kbdint(session, NULL, NULL);
    if (err == SSH_AUTH_ERROR) {
        return err;
    }

    if (ssh_userauth_kbdint_getnprompts(session) != 1) {
        return SSH_AUTH_ERROR;
    }

    prompt = ssh_userauth_kbdint_getprompt(session, 0, &echo);
    if (prompt == NULL) {
        return SSH_AUTH_ERROR;
    }

    if (ssh_userauth_kbdint_setanswer(session, 0, password) < 0) {
        return SSH_AUTH_ERROR;
    }
    err = ssh_userauth_kbdint(session, NULL, NULL);
    if (err == SSH_AUTH_INFO) {
        if (ssh_userauth_kbdint_getnprompts(session) != 0) {
            return SSH_AUTH_ERROR;
        }
        err = ssh_userauth_kbdint(session, NULL, NULL);
    }

    return err;
}

int torture_rmdirs(const char *path) {
    DIR *d;
    struct dirent *dp;
    struct stat sb;
    char *fname;

    if ((d = opendir(path)) != NULL) {
        while(stat(path, &sb) == 0) {
            /* if we can remove the directory we're done */
            if (rmdir(path) == 0) {
                break;
            }
            switch (errno) {
                case ENOTEMPTY:
                case EEXIST:
                case EBADF:
                    break; /* continue */
                default:
                    closedir(d);
                    return 0;
            }

            while ((dp = readdir(d)) != NULL) {
                size_t len;
                /* skip '.' and '..' */
                if (dp->d_name[0] == '.' &&
                        (dp->d_name[1] == '\0' ||
                         (dp->d_name[1] == '.' && dp->d_name[2] == '\0'))) {
                    continue;
                }

                len = strlen(path) + strlen(dp->d_name) + 2;
                fname = malloc(len);
                if (fname == NULL) {
                    closedir(d);
                    return -1;
                }
                snprintf(fname, len, "%s/%s", path, dp->d_name);

                /* stat the file */
                if (lstat(fname, &sb) != -1) {
                    if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode)) {
                        if (rmdir(fname) < 0) { /* can't be deleted */
                            if (errno == EACCES) {
                                closedir(d);
                                SAFE_FREE(fname);
                                return -1;
                            }
                            torture_rmdirs(fname);
                        }
                    } else {
                        unlink(fname);
                    }
                } /* lstat */
                SAFE_FREE(fname);
            } /* readdir */

            rewinddir(d);
        }
    } else {
        return -1;
    }

    closedir(d);
    return 0;
}

int torture_isdir(const char *path) {
    struct stat sb;

    if (lstat (path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        return 1;
    }

    return 0;
}

static pid_t
torture_read_pidfile(const char *pidfile)
{
    char buf[8] = {0};
    long int tmp;
    pid_t ret;
    ssize_t rc;
    int fd;

    fd = open(pidfile, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    rc = read(fd, buf, sizeof(buf));
    close(fd);
    if (rc <= 0) {
        return -1;
    }

    buf[sizeof(buf) - 1] = '\0';

    tmp = strtol(buf, NULL, 10);
    if (tmp == 0 || errno == ERANGE) {
        return -1;
    }
    ret = (pid_t)tmp;
    /* Check if we are out of pid_t range on this system */
    if ((long)ret != tmp) {
        return -1;
    }

    return ret;
}

int torture_terminate_process(const char *pidfile)
{
    ssize_t rc;
    pid_t pid;
    int is_running = 1;
    int count;

    /* read the pidfile */
    pid = torture_read_pidfile(pidfile);
    assert_int_not_equal(pid, -1);

    for (count = 0; count < 10; count++) {
        /* Make sure the daemon goes away! */
        kill(pid, SIGTERM);

        /* 10 ms */
        usleep(10 * 1000);

        rc = kill(pid, 0);
        if (rc != 0) {
            is_running = 0;
            break;
        }
    }

    if (is_running) {
        fprintf(stderr,
                "WARNING: The process with pid %u is still running!\n", pid);
    }

    return 0;
}

ssh_session torture_ssh_session(struct torture_state *s,
                                const char *host,
                                const unsigned int *port,
                                const char *user,
                                const char *password) {
    ssh_session session;
    int method;
    int rc;

    bool process_config = false;

    if (host == NULL) {
        return NULL;
    }

    session = ssh_new();
    if (session == NULL) {
        return NULL;
    }

#ifdef WITH_PCAP
    if (s != NULL && s->plain_pcap != NULL) {
        ssh_set_pcap_file(session, s->plain_pcap);
    }
#endif /* WITH_PCAP */

    if (ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity) < 0) {
        goto failed;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
        goto failed;
    }

    if (port != NULL) {
      if (ssh_options_set(session, SSH_OPTIONS_PORT, port) < 0) {
        goto failed;
      }
    }

    if (user != NULL) {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
            goto failed;
        }
    }

    if (ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG,
                        &process_config) < 0) {
        goto failed;
    }

    if (ssh_connect(session)) {
        goto failed;
    }

    /* We are in testing mode, so consinder the hostkey as verified ;) */

    /* This request should return a SSH_REQUEST_DENIED error */
    rc = ssh_userauth_none(session, NULL);
    if (rc == SSH_ERROR) {
        goto failed;
    }
    method = ssh_userauth_list(session, NULL);
    if (method == 0) {
        goto failed;
    }

    if (password != NULL) {
        if (method & SSH_AUTH_METHOD_PASSWORD) {
            rc = ssh_userauth_password(session, NULL, password);
        } else if (method & SSH_AUTH_METHOD_INTERACTIVE) {
            rc = _torture_auth_kbdint(session, password);
        }
    } else {
        rc = ssh_userauth_publickey_auto(session, NULL, NULL);
        if (rc == SSH_AUTH_ERROR) {
            goto failed;
        }
    }
    if (rc != SSH_AUTH_SUCCESS) {
        goto failed;
    }

    return session;
failed:
    if (ssh_is_connected(session)) {
        ssh_disconnect(session);
    }
    ssh_free(session);

    return NULL;
}

#ifdef WITH_SERVER

ssh_bind torture_ssh_bind(const char *addr,
                          const unsigned int port,
                          enum ssh_keytypes_e key_type,
                          const char *private_key_file) {
    int rc;
    ssh_bind sshbind = NULL;
    enum ssh_bind_options_e opts = -1;

    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        goto out;
    }

    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, addr);
    if (rc != 0) {
        goto out_free;
    }

    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    if (rc != 0) {
        goto out_free;
    }

    switch (key_type) {
#ifdef HAVE_DSA
        case SSH_KEYTYPE_DSS:
            opts = SSH_BIND_OPTIONS_DSAKEY;
            break;
#endif /* HAVE_DSA */
        case SSH_KEYTYPE_RSA:
            opts = SSH_BIND_OPTIONS_RSAKEY;
            break;
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
            opts = SSH_BIND_OPTIONS_ECDSAKEY;
            break;
        default:
            goto out_free;
    }

    rc = ssh_bind_options_set(sshbind, opts, private_key_file);
    if (rc != 0) {
        goto out_free;
    }

    rc = ssh_bind_listen(sshbind);
    if (rc != SSH_OK) {
        goto out_free;
    }

    goto out;
 out_free:
    ssh_bind_free(sshbind);
    sshbind = NULL;
 out:
    return sshbind;
}

#endif /* WITH_SERVER */

#ifdef WITH_SFTP

struct torture_sftp *torture_sftp_session(ssh_session session) {
    struct torture_sftp *t;
    char template[] = "/tmp/ssh_torture_XXXXXX";
    char *p;
    int rc;

    if (session == NULL) {
        return NULL;
    }

    t = malloc(sizeof(struct torture_sftp));
    if (t == NULL) {
        return NULL;
    }

    t->ssh = session;
    t->sftp = sftp_new(session);
    if (t->sftp == NULL) {
        goto failed;
    }

    rc = sftp_init(t->sftp);
    if (rc < 0) {
        goto failed;
    }

    p = mkdtemp(template);
    if (p == NULL) {
        goto failed;
    }
    /* useful if TESTUSER is not the local user */
    chmod(template,0777);
    t->testdir = strdup(p);
    if (t->testdir == NULL) {
        goto failed;
    }

    return t;
failed:
    if (t->sftp != NULL) {
        sftp_free(t->sftp);
    }
    ssh_disconnect(t->ssh);
    ssh_free(t->ssh);
    free(t);

    return NULL;
}

void torture_sftp_close(struct torture_sftp *t) {
    if (t == NULL) {
        return;
    }

    if (t->sftp != NULL) {
        sftp_free(t->sftp);
    }

    free(t->testdir);
    free(t);
}
#endif /* WITH_SFTP */

int torture_server_port(void)
{
    char *env = getenv("TORTURE_SERVER_PORT");

    if (env != NULL && env[0] != '\0' && strlen(env) < 6) {
        int port = atoi(env);

        if (port > 0 && port < 65536) {
            return port;
        }
    }

    return TORTURE_SSHD_SRV_PORT;
}

const char *torture_server_address(int family)
{
    switch (family) {
    case AF_INET: {
        const char *ip4 = getenv("TORTURE_SERVER_ADDRESS_IPV4");

        if (ip4 != NULL && ip4[0] != '\0') {
            return ip4;
        }

        return TORTURE_SSHD_SRV_IPV4;
    }
    case AF_INET6: {
        const char *ip6 = getenv("TORTURE_SERVER_ADDRESS_IPV6");

        if (ip6 != NULL && ip6[0] != '\0') {
            return ip6;
        }

        return TORTURE_SSHD_SRV_IPV6;
    }
    default:
        return NULL;
    }

    return NULL;
}

void torture_setup_socket_dir(void **state)
{
    struct torture_state *s;
    const char *p;
    size_t len;
    char *env = NULL;
    int rc;

    s = calloc(1, sizeof(struct torture_state));
    assert_non_null(s);

#ifdef WITH_PCAP
    env = getenv("TORTURE_PLAIN_PCAP_FILE");
    if (env != NULL && env[0] != '\0') {
        s->plain_pcap = ssh_pcap_file_new();
        assert_non_null(s->plain_pcap);

        rc = ssh_pcap_file_open(s->plain_pcap, env);
        assert_int_equal(rc, SSH_OK);
    }
#endif /* WITH_PCAP */

    s->socket_dir = torture_make_temp_dir(TORTURE_SOCKET_DIR);
    assert_non_null(s->socket_dir);

    p = s->socket_dir;

    /* pcap file */
    len = strlen(p) + 1 + strlen(TORTURE_PCAP_FILE) + 1;

    s->pcap_file = malloc(len);
    assert_non_null(s->pcap_file);

    snprintf(s->pcap_file, len, "%s/%s", p, TORTURE_PCAP_FILE);

    /* pid file */
    len = strlen(p) + 1 + strlen(TORTURE_SSHD_PIDFILE) + 1;

    s->srv_pidfile = malloc(len);
    assert_non_null(s->srv_pidfile);

    snprintf(s->srv_pidfile, len, "%s/%s", p, TORTURE_SSHD_PIDFILE);

    /* config file */
    len = strlen(p) + 1 + strlen(TORTURE_SSHD_CONFIG) + 1;

    s->srv_config = malloc(len);
    assert_non_null(s->srv_config);

    snprintf(s->srv_config, len, "%s/%s", p, TORTURE_SSHD_CONFIG);

    setenv("SOCKET_WRAPPER_DIR", p, 1);
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "170", 1);
    env = getenv("TORTURE_GENERATE_PCAP");
    if (env != NULL && env[0] == '1') {
        setenv("SOCKET_WRAPPER_PCAP_FILE", s->pcap_file, 1);
    }

    *state = s;
}

static void torture_setup_create_sshd_config(void **state, bool pam)
{
    struct torture_state *s = *state;
    char ed25519_hostkey[1024] = {0};
#ifdef HAVE_DSA
    char dsa_hostkey[1024];
#endif /* HAVE_DSA */
    char rsa_hostkey[1024];
    char ecdsa_hostkey[1024];
    char trusted_ca_pubkey[1024];
    char sshd_config[4096];
    char sshd_path[1024];
    const char *additional_config = NULL;
    struct stat sb;
    const char *sftp_server_locations[] = {
        "/usr/lib/ssh/sftp-server",
        "/usr/libexec/ssh/sftp-server", /* Tumbleweed 20200829 */
        "/usr/libexec/sftp-server",
        "/usr/libexec/openssh/sftp-server",
        "/usr/lib/openssh/sftp-server",     /* Debian */
    };
    const char config_string[]=
             "Port 22\n"
             "ListenAddress 127.0.0.10\n"
             "%s %s\n" /* ed25519 HostKey */
#ifdef HAVE_DSA
             "%s %s\n" /* DSA HostKey */
#endif /* HAVE_DSA */
             "%s %s\n" /* RSA HostKey */
             "%s %s\n" /* ECDSA HostKey */
             "\n"
             "TrustedUserCAKeys %s\n"
             "\n"
             "LogLevel DEBUG3\n"
             "Subsystem sftp %s -l DEBUG2\n"
             "\n"
             "PasswordAuthentication yes\n"
             "PubkeyAuthentication yes\n"
             "\n"
             "StrictModes no\n"
             "\n"
             "%s" /* Here comes UsePam */
             "\n"
             /* add all supported algorithms */
             "HostKeyAlgorithms " OPENSSH_KEYS "\n"
#if OPENSSH_VERSION_MAJOR == 8 && OPENSSH_VERSION_MINOR >= 2
             "CASignatureAlgorithms " OPENSSH_KEYS "\n"
#endif
             "Ciphers " OPENSSH_CIPHERS "\n"
             "KexAlgorithms " OPENSSH_KEX "\n"
             "MACs " OPENSSH_MACS "\n"
             "\n"
             "AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES\n"
             "AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT\n"
             "AcceptEnv LC_IDENTIFICATION LC_ALL LC_LIBSSH\n"
             "\n"
             "PidFile %s\n"
             "%s\n"; /* The space for test-specific options */
    /* FIPS config */
    const char fips_config_string[]=
             "Port 22\n"
             "ListenAddress 127.0.0.10\n"
             "%s %s\n" /* RSA HostKey */
             "%s %s\n" /* ECDSA HostKey */
             "\n"
             "TrustedUserCAKeys %s\n" /* Trusted CA */
             "\n"
             "LogLevel DEBUG3\n"
             "Subsystem sftp %s -l DEBUG2\n" /* SFTP server */
             "\n"
             "PasswordAuthentication yes\n"
             "PubkeyAuthentication yes\n"
             "\n"
             "StrictModes no\n"
             "\n"
             "%s" /* UsePam */
             "\n"
             "Ciphers "
                "aes256-gcm@openssh.com,aes256-ctr,aes256-cbc,"
                "aes128-gcm@openssh.com,aes128-ctr,aes128-cbc"
             "\n"
             "MACs "
                "hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,"
                "hmac-sha2-512-etm@openssh.com,hmac-sha2-256,"
                "hmac-sha1,hmac-sha2-512"
             "\n"
             "GSSAPIKeyExchange no\n"
             "KexAlgorithms "
                "ecdh-sha2-nistp256,ecdh-sha2-nistp384,"
                "ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,"
                "diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,"
                "diffie-hellman-group18-sha512"
             "\n"
             "PubkeyAcceptedKeyTypes "
                "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,"
                "ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,"
                "ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,"
                "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,"
                "ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com"
             "\n"
             "AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES\n"
             "AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT\n"
             "AcceptEnv LC_IDENTIFICATION LC_ALL LC_LIBSSH\n"
             "\n"
             "PidFile %s\n" /* PID file */
             "%s\n"; /* The space for test-specific options */
    const char usepam_yes[] =
             "UsePAM yes\n"
             "KbdInteractiveAuthentication yes\n";
    const char usepam_no[] =
             "UsePAM no\n"
             "KbdInteractiveAuthentication no\n";
    size_t sftp_sl_size = ARRAY_SIZE(sftp_server_locations);
    const char *sftp_server, *usepam;
    size_t i;
    bool written = false;
    int rc;

    s->srv_pam = pam;
    if (pam) {
        usepam = usepam_yes;
    } else {
        usepam = usepam_no;
    }

    assert_non_null(s->socket_dir);

    snprintf(sshd_path,
             sizeof(sshd_path),
             "%s/sshd",
             s->socket_dir);

    rc = lstat(sshd_path, &sb);
    if (rc == 0 ) { /* The directory is already in place */
        written = true;
    }

    if (!written) {
        rc = mkdir(sshd_path, 0755);
        assert_return_code(rc, errno);
    }

    snprintf(ed25519_hostkey,
             sizeof(ed25519_hostkey),
             "%s/sshd/ssh_host_ed25519_key",
             s->socket_dir);

#ifdef HAVE_DSA
    snprintf(dsa_hostkey,
             sizeof(dsa_hostkey),
             "%s/sshd/ssh_host_dsa_key",
             s->socket_dir);
#endif /* HAVE_DSA */

    snprintf(rsa_hostkey,
             sizeof(rsa_hostkey),
             "%s/sshd/ssh_host_rsa_key",
             s->socket_dir);

    snprintf(ecdsa_hostkey,
             sizeof(ecdsa_hostkey),
             "%s/sshd/ssh_host_ecdsa_key",
             s->socket_dir);

    snprintf(trusted_ca_pubkey,
             sizeof(trusted_ca_pubkey),
             "%s/sshd/user_ca.pub",
             s->socket_dir);

    if (!written) {
        torture_write_file(ed25519_hostkey,
                           torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0));
#ifdef HAVE_DSA
        torture_write_file(dsa_hostkey,
                           torture_get_testkey(SSH_KEYTYPE_DSS, 0));
#endif /* HAVE_DSA */
        torture_write_file(rsa_hostkey,
                           torture_get_testkey(SSH_KEYTYPE_RSA, 0));
        torture_write_file(ecdsa_hostkey,
                           torture_get_testkey(SSH_KEYTYPE_ECDSA_P521, 0));
        torture_write_file(trusted_ca_pubkey, torture_rsa_certauth_pub);
    }

    sftp_server = getenv("TORTURE_SFTP_SERVER");
    if (sftp_server == NULL) {
        for (i = 0; i < sftp_sl_size; i++) {
            sftp_server = sftp_server_locations[i];
            rc = lstat(sftp_server, &sb);
            if (rc == 0) {
                break;
            }
        }
    }
    assert_non_null(sftp_server);

    additional_config = (s->srv_additional_config != NULL ?
                         s->srv_additional_config : "");

    if (ssh_fips_mode()) {
        snprintf(sshd_config, sizeof(sshd_config),
                fips_config_string,
                "HostKey", rsa_hostkey,
                "HostKey", ecdsa_hostkey,
                trusted_ca_pubkey,
                sftp_server,
                usepam,
                s->srv_pidfile,
                additional_config);
    } else {
        snprintf(sshd_config, sizeof(sshd_config),
                config_string,
                "HostKey", ed25519_hostkey,
#ifdef HAVE_DSA
                "HostKey", dsa_hostkey,
#endif /* HAVE_DSA */
                "HostKey", rsa_hostkey,
                "HostKey", ecdsa_hostkey,
                trusted_ca_pubkey,
                sftp_server,
                usepam,
                s->srv_pidfile,
                additional_config);
    }

    torture_write_file(s->srv_config, sshd_config);
}

static int torture_wait_for_daemon(unsigned int seconds)
{
    struct ssh_timestamp start;
    int rc;

    ssh_timestamp_init(&start);

    while (!ssh_timeout_elapsed(&start, seconds * 1000)) {
        rc = system(SSH_PING_EXECUTABLE " " TORTURE_SSH_SERVER);
        if (rc == 0) {
            return 0;
        }
        /* Wait 200 ms before retrying */
        usleep(200 * 1000);
    }
    return 1;
}

void torture_setup_sshd_server(void **state, bool pam)
{
    struct torture_state *s;
    char sshd_start_cmd[1024];
    int rc;

    torture_setup_socket_dir(state);
    torture_setup_create_sshd_config(state, pam);

    /* Set the default interface for the server */
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "10", 1);
    setenv("PAM_WRAPPER", "1", 1);

    s = *state;

    snprintf(sshd_start_cmd, sizeof(sshd_start_cmd),
             SSHD_EXECUTABLE " -r -f %s -E %s/sshd/daemon.log 2> %s/sshd/cwrap.log",
             s->srv_config, s->socket_dir, s->socket_dir);

    rc = system(sshd_start_cmd);
    assert_return_code(rc, errno);

    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "21", 1);
    unsetenv("PAM_WRAPPER");

    /* Wait until the sshd is ready to accept connections */
    rc = torture_wait_for_daemon(5);
    assert_int_equal(rc, 0);
}

void torture_teardown_socket_dir(void **state)
{
    struct torture_state *s = *state;
    char *env = getenv("TORTURE_SKIP_CLEANUP");
    int rc;

    if (env != NULL && env[0] == '1') {
        fprintf(stderr, "[ TORTURE  ] >>> Skipping cleanup of %s\n", s->socket_dir);
    } else {
        rc = torture_rmdirs(s->socket_dir);
        if (rc < 0) {
            fprintf(stderr,
                    "torture_rmdirs(%s) failed: %s",
                    s->socket_dir,
                    strerror(errno));
        }
    }
#ifdef WITH_PCAP
    if (s->plain_pcap != NULL) {
        ssh_pcap_file_free(s->plain_pcap);
    }
    s->plain_pcap = NULL;
#endif /* WITH_PCAP */

    free(s->srv_config);
    free(s->socket_dir);
    free(s->pcap_file);
    free(s->srv_pidfile);
    free(s->srv_additional_config);
    free(s);
}

static int
torture_reload_sshd_server(void **state)
{
    struct torture_state *s = *state;
    pid_t pid;
    int rc;

    /* read the pidfile */
    pid = torture_read_pidfile(s->srv_pidfile);
    assert_int_not_equal(pid, -1);

    kill(pid, SIGHUP);

    /* 10 ms */
    usleep(10 * 1000);

    rc = kill(pid, 0);
    if (rc != 0) {
        fprintf(stderr,
                "ERROR: SSHD process %u died during reload!\n", pid);
        return SSH_ERROR;
    }

    /* Wait until the sshd is ready to accept connections */
    rc = torture_wait_for_daemon(5);
    assert_int_equal(rc, 0);
    return SSH_OK;
}

/* @brief: Updates SSHD server configuration with more options and
 *         reloads the server to apply them.
 * Note, that this still uses the default configuration options specified
 * in this file and overwrites options previously specified by this function.
 */
int
torture_update_sshd_config(void **state, const char *config)
{
    struct torture_state *s = *state;
    int rc;

    /* Store the configuration in internal structure */
    SAFE_FREE(s->srv_additional_config);
    s->srv_additional_config = strdup(config);
    assert_non_null(s->srv_additional_config);

    /* Rewrite the configuration file */
    torture_setup_create_sshd_config(state, s->srv_pam);

    /* Reload the server */
    rc = torture_reload_sshd_server(state);
    assert_int_equal(rc, SSH_OK);

    return SSH_OK;
}


void torture_teardown_sshd_server(void **state)
{
    struct torture_state *s = *state;
    int rc;

    rc = torture_terminate_process(s->srv_pidfile);
    if (rc != 0) {
        fprintf(stderr, "XXXXXX Failed to terminate sshd\n");
    }

    torture_teardown_socket_dir(state);
}

char *torture_make_temp_dir(const char *template)
{
    char *new_dir = NULL;
    char *template_copy = NULL;

    if (template == NULL) {
        goto end;
    }

    template_copy = strdup(template);
    if (template_copy == NULL) {
        goto end;
    }

    new_dir = mkdtemp(template_copy);
    if (new_dir == NULL) {
        SAFE_FREE(template_copy);
    }

end:
    return template_copy;
}

char *torture_create_temp_file(const char *template)
{
    char *new_file = NULL;
    FILE *fp = NULL;
    mode_t mask;
    int fd;

    new_file = strdup(template);
    if (new_file == NULL) {
        goto end;
    }

    mask = umask(S_IRWXO | S_IRWXG);
    fd = mkstemp(new_file);
    umask(mask);
    if (fd == -1) {
        goto end;
    }

    fp = fdopen(fd, "w");
    if (fp == NULL) {
        SAFE_FREE(new_file);
        close(fd);
        goto end;
    }

    fclose(fp);

end:
    return new_file;
}

char *torture_get_current_working_dir(void)
{

    char *cwd = NULL;
    char *result = NULL;

    cwd = (char *)malloc(PATH_MAX + 1);
    if (cwd == NULL) {
        goto end;
    }

    result = getcwd(cwd, PATH_MAX);

    if (result == NULL) {
        SAFE_FREE(cwd);
        goto end;
    }

end:
    return cwd;
}

#else /* _WIN32 */

char *torture_make_temp_dir(const char *template)
{
    DWORD rc = 0;
    char tmp_dir_path[MAX_PATH];
    char tmp_file_name[MAX_PATH];
    char *prefix = NULL;
    char *path = NULL;
    char *prefix_end = NULL;
    char *slash = NULL;

    BOOL created;

    if (template == NULL) {
        goto end;
    }

    prefix = strdup(template);
    if (prefix == NULL) {
        goto end;
    }

    /* Replace slashes with backslashes */
    slash = strchr(prefix, '/');
    for (; slash != NULL; slash = strchr(prefix, '/')) {
        *slash = '\\';
    }

    prefix_end = strstr(prefix, "XXXXXX");
    if (prefix_end != NULL) {
        *prefix_end = '\0';
    }

    rc = GetTempPathA(MAX_PATH, tmp_dir_path);
    if ((rc > MAX_PATH) || (rc == 0)) {
        goto free_prefix;
    }

    rc = GetTempFileNameA(tmp_dir_path, TEXT(prefix), 0, tmp_file_name);
    if (rc == 0) {
        goto free_prefix;
    }

    path = strdup(tmp_file_name);
    if (path == NULL) {
        goto free_prefix;
    }

    /* GetTempFileNameA() creates a temporary file; we need to remove it */
    rc = DeleteFileA(path);
    if (rc == 0) {
        rc = -1;
        SAFE_FREE(path);
        goto free_prefix;
    }

    created = CreateDirectoryA(path, NULL);
    if (!created) {
        SAFE_FREE(path);
    }

free_prefix:
    SAFE_FREE(prefix);
end:
    return path;
}

static int recursive_rm_dir_content(const char *path)
{
    WIN32_FIND_DATA file_data;
    HANDLE file_handle;
    DWORD attributes;

    DWORD last_error = 0;

    char file_path[MAX_PATH];

    int rc = 0;
    BOOL removed;

    strcpy(file_path, path);
    strcat(file_path, "\\*");

    file_handle = FindFirstFile(file_path, &file_data);

    if (file_handle == INVALID_HANDLE_VALUE) {
        last_error = GetLastError();

        /* Empty directory */
        if (last_error == ERROR_FILE_NOT_FOUND) {
            rc = 0;
        }
        else {
            /*TODO print error message?*/
            rc = last_error;
        }
        goto end;
    }
    else {
        do {
            rc = strcmp(file_data.cFileName, ".");
            if (rc == 0) {
                continue;
            }

            rc = strcmp(file_data.cFileName, "..");
            if (rc == 0) {
                continue;
            }

            /* Create full file path */
            strcpy(file_path, path);
            strcat(file_path, "\\");
            strcat(file_path, file_data.cFileName);

            attributes = GetFileAttributes(file_path);
            if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
                rc = recursive_rm_dir_content((const char *)file_path);
                if (rc != 0) {
                    goto end;
                }

                removed = RemoveDirectoryA(file_path);

                if (!removed) {
                    last_error = GetLastError();

                    /*TODO print error message?*/

                    rc = last_error;
                    goto end;
                }
            }
            else {
                rc = remove(file_path);
                if (rc) {
                    goto end;
                }
            }

        } while(FindNextFile(file_handle, &file_data));

        FindClose(file_handle);
    }

end:
    return rc;
}

int torture_rmdirs(const char *path)
{
    int rc = 0;
    BOOL removed;

    rc = recursive_rm_dir_content(path);
    if (rc) {
        return rc;
    }

    removed = RemoveDirectoryA(path);
    if (!removed) {
        rc = -1;
    }

    return rc;
}

int torture_isdir(const char *path)
{

    DWORD attributes = 0;

    attributes = GetFileAttributes(path);
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        return 1;
    }

    return 0;
}

char *torture_create_temp_file(const char *template)
{
    DWORD rc = 0;
    char tmp_dir_path[MAX_PATH];
    char tmp_file_name[MAX_PATH];
    char *prefix = NULL;
    char *path = NULL;
    char *prefix_end = NULL;
    char *slash = NULL;

    if (template == NULL) {
        goto end;
    }

    prefix = strdup(template);
    if (prefix == NULL) {
        goto end;
    }

    /* Replace slashes with backslashes */
    slash = strchr(prefix, '/');
    for (; slash != NULL; slash = strchr(prefix, '/')) {
        *slash = '\\';
    }

    prefix_end = strstr(prefix, "XXXXXX");
    if (prefix_end != NULL) {
        *prefix_end = '\0';
    }

    rc = GetTempPathA(MAX_PATH, tmp_dir_path);
    if ((rc > MAX_PATH) || (rc == 0)) {
        goto free_prefix;
    }

    /* Remark: this function creates the file */
    rc = GetTempFileNameA(tmp_dir_path, TEXT(prefix), 0, tmp_file_name);
    if (rc == 0) {
        goto free_prefix;
    }

    path = strdup(tmp_file_name);

free_prefix:
    SAFE_FREE(prefix);
end:
    return path;
}

char *torture_get_current_working_dir(void)
{
    char *cwd = NULL;
    char *result = NULL;

    cwd = (char *)malloc(_MAX_PATH + 1);
    if (cwd == NULL) {
        goto end;
    }

    result = _getcwd(cwd, _MAX_PATH);

    if (result == NULL) {
        SAFE_FREE(cwd);
        goto end;
    }

end:
    return cwd;
}

#endif /* _WIN32 */

int torture_change_dir(char *path)
{
    int rc = 0;

    if (path == NULL) {
        rc = -1;
        goto end;
    }

    rc = chdir(path);

end:
    return rc;
}

int torture_libssh_verbosity(void){
  return verbosity;
}

void _torture_filter_tests(struct CMUnitTest *tests, size_t ntests)
{
    (void) tests;
    (void) ntests;

    return;
}

void torture_write_file(const char *filename, const char *data){
    int fd;
    int rc;

    assert_non_null(filename);
    assert_true(filename[0] != '\0');
    assert_non_null(data);

    fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0600);
    assert_true(fd >= 0);

    rc = write(fd, data, strlen(data));
    assert_int_equal(rc, strlen(data));

    close(fd);
}

void torture_reset_config(ssh_session session)
{
    memset(session->opts.options_seen, 0, sizeof(session->opts.options_seen));
}

int main(int argc, char **argv) {
    struct argument_s arguments;
    char *env = getenv("LIBSSH_VERBOSITY");

    arguments.verbose=0;
    arguments.pattern=NULL;
    torture_cmdline_parse(argc, argv, &arguments);
    verbosity=arguments.verbose;
    pattern=arguments.pattern;

    if (verbosity == 0 && env != NULL && env[0] != '\0') {
        if (env[0] > '0' && env[0] < '9') {
            verbosity = atoi(env);
        }
    }

#if defined HAVE_CMOCKA_SET_TEST_FILTER
    cmocka_set_test_filter(pattern);
#endif

    return torture_run_tests();
}
