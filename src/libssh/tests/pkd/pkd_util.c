/*
 * pkd_util.c -- pkd utilities
 *
 * (c) 2014, 2018 Jon Simons <jon@jonsimons.org>
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "pkd_client.h"
#include "pkd_util.h"

/**
 * @brief runs system(3); exits if that is interrupted with SIGINT/QUIT
 * @returns 0 upon success, non-zero otherwise
 */
int system_checked(const char *cmd) {
    int rc = system(cmd);

    if (WIFSIGNALED(rc) &&
        ((WTERMSIG(rc) == SIGINT) || (WTERMSIG(rc) == SIGQUIT))) {
        exit(1);
    }

    if (rc == -1) {
        return -1;
    }

    return WEXITSTATUS(rc);
}

static int bin_exists(const char *binary) {
    char bin[1024] = { 0 };
    snprintf(&bin[0], sizeof(bin), "type %s 1>/dev/null 2>/dev/null", binary);
    return (system_checked(bin) == 0);
}

static int is_openssh_client_new_enough(void) {
    int rc = -1;
    FILE *fp = NULL;
    char version_buff[1024] = { 0 };
    char *version;

    static int version_ok = 0;
    unsigned long int major = 0;
    char *tmp = NULL;

    if (version_ok) {
        return version_ok;
    }

    fp = popen("ssh -V 2>&1", "r");
    if (fp == NULL) {
        fprintf(stderr, "failed to get OpenSSH client version\n");
        goto done;
    }

    do {
        if (fgets(&version_buff[0], sizeof(version_buff), fp) == NULL) {
            fprintf(stderr, "failed to get OpenSSH client version string\n");
            goto errfgets;
        }
        version = strstr(version_buff, "OpenSSH");
    } while(version == NULL);

    /* "OpenSSH_<major>.<minor><SP>..." */
    if (strlen(version) < 11) {
        goto errversion;
    }

    /* Extract major. */
    major = strtoul(version + 8, &tmp, 10);
    if ((tmp == (version + 8)) ||
        ((errno == ERANGE) && (major == ULONG_MAX)) ||
        ((errno != 0) && (major == 0)) ||
        ((major < 1) || (major > 100))) {
        fprintf(stderr, "failed to parse OpenSSH client version, "
                        "errno %d\n", errno);
        goto errversion;
    }

    if (major < 7) {
        fprintf(stderr, "error: minimum OpenSSH client version "
                        "required is 7, found: %ld\n", major);
        goto errversion;
    }

    version_ok = 1;

errversion:
errfgets:
    rc = pclose(fp);
    if (rc != 0) {
        fprintf(stderr, "failed to get OpenSSH client version: %d\n", rc);
    }
done:
    return version_ok;
}

int is_openssh_client_enabled(void) {
    return (bin_exists(OPENSSH_BINARY) &&
            bin_exists(OPENSSH_KEYGEN) &&
            is_openssh_client_new_enough());
}

int is_dropbear_client_enabled(void) {
    return (bin_exists(DROPBEAR_BINARY) && bin_exists(DROPBEAR_KEYGEN));
}
