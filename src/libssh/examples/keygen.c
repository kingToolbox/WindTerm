/* keygen.c
 * Sample implementation of ssh-keygen using libssh
 */

/*
Copyright 2019 Red Hat, Inc.

Author: Jakub Jelen <jjelen@redhat.com>

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
 */

#include <libssh/libssh.h>
#include <stdio.h>

int main(void)
{
    ssh_key key = NULL;
    int rv;

    /* Generate a new ED25519 private key file */
    rv = ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &key);
    if (rv != SSH_OK) {
        fprintf(stderr, "Failed to generate private key");
	return -1;
    }

    /* Write it to a file testkey in the current dirrectory */
    rv = ssh_pki_export_privkey_file(key, NULL, NULL, NULL, "testkey");
    if (rv != SSH_OK) {
        fprintf(stderr, "Failed to write private key file");
	return -1;
    }

    return 0;
}
