/*
 * pkd_daemon.h -- tests use this interface to start, stop pkd
 *                 instances and get results
 *
 * (c) 2014 Jon Simons
 */

#ifndef __PKD_DAEMON_H__
#define __PKD_DAEMON_H__

#include "config.h"

enum pkd_hostkey_type_e {
    PKD_RSA,
#ifdef HAVE_DSA
    PKD_DSA,
#endif
    PKD_ED25519,
    PKD_ECDSA
};

struct pkd_daemon_args {
    enum pkd_hostkey_type_e type;
    const char *hostkeypath;

    struct {
        const uint8_t *buf;
        size_t len;
    } payload;

    uint64_t rekey_data_limit;

    struct {
        int list;

        int log_stdout;
        int log_stderr;
        int libssh_log_level;

        const char *testname;
        const char *testmatch;
        unsigned int iterations;

        struct {
            char *mkdtemp_str;
        } socket_wrapper;
    } opts;
};

struct pkd_result {
    int ok;
};

int pkd_start(struct pkd_daemon_args *args);
void pkd_stop(struct pkd_result *out);

#endif /* __PKD_DAEMON_H__ */
