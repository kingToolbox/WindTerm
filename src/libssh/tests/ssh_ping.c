/* ssh_ping.c */
/*
Copyright 2018 Red Hat, Inc

Author: Jakub Jelen <jjelen@redhat.com>

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

#include <stdio.h>
#include <stdlib.h>
#include <libssh/libssh.h>

int main(int argc, char **argv)
{
    const char *banner = NULL;
    ssh_session session = NULL;
    int rc = 1;

    if (argc < 1 || argv[1] == NULL) {
        fprintf(stderr, "Error: Need an argument (hostname)\n");
        goto out;
    }

    session = ssh_new();
    if (session == NULL) {
        goto out;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, argv[1]);
    if (rc < 0) {
        goto out;
    }

    /* The automatic username is not available under uid wrapper */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, "ping");
    if (rc < 0) {
        goto out;
    }

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Connection failed : %s\n", ssh_get_error(session));
        goto out;
    }

    banner = ssh_get_serverbanner(session);
    if (banner == NULL) {
        fprintf(stderr, "Did not receive SSH banner\n");
        goto out;
    }

    printf("OK: %s\n", banner);
    rc = 0;

out:
    ssh_free(session);
    return rc;
}

