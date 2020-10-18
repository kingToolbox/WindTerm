/*
 * knownhosts.c
 * This file contains an example of how verify the identity of a
 * SSH server using libssh
 */

/*
Copyright 2003-2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libssh/priv.h"
#include <libssh/libssh.h>
#include "examples_common.h"

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    char buf[10];
    unsigned char *hash = NULL;
    size_t hlen;
    ssh_key srv_pubkey;
    int rc;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA256,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    state = ssh_session_is_known_server(session);

    switch(state) {
    case SSH_KNOWN_HOSTS_CHANGED:
        fprintf(stderr,"Host key for server changed : server's one is now :\n");
        ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
        ssh_clean_pubkey_hash(&hash);
        fprintf(stderr,"For security reason, connection will be stopped\n");
        return -1;
    case SSH_KNOWN_HOSTS_OTHER:
        fprintf(stderr,"The host key for this server was not found but an other type of key exists.\n");
        fprintf(stderr,"An attacker might change the default server key to confuse your client"
                "into thinking the key does not exist\n"
                "We advise you to rerun the client with -d or -r for more safety.\n");
        return -1;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
        fprintf(stderr,"Could not find known host file. If you accept the host key here,\n");
        fprintf(stderr,"the file will be automatically created.\n");
        /* fallback to SSH_SERVER_NOT_KNOWN behavior */
        FALL_THROUGH;
    case SSH_SERVER_NOT_KNOWN:
        fprintf(stderr,
                "The server is unknown. Do you trust the host key (yes/no)?\n");
        ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);

        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            ssh_clean_pubkey_hash(&hash);
            return -1;
        }
        if(strncasecmp(buf,"yes",3)!=0){
            ssh_clean_pubkey_hash(&hash);
            return -1;
        }
        fprintf(stderr,"This new key will be written on disk for further usage. do you agree ?\n");
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            ssh_clean_pubkey_hash(&hash);
            return -1;
        }
        if(strncasecmp(buf,"yes",3)==0){
            rc = ssh_session_update_known_hosts(session);
            if (rc != SSH_OK) {
                ssh_clean_pubkey_hash(&hash);
                fprintf(stderr, "error %s\n", strerror(errno));
                return -1;
            }
        }

        break;
    case SSH_KNOWN_HOSTS_ERROR:
        ssh_clean_pubkey_hash(&hash);
        fprintf(stderr,"%s",ssh_get_error(session));
        return -1;
    case SSH_KNOWN_HOSTS_OK:
        break; /* ok */
    }

    ssh_clean_pubkey_hash(&hash);

    return 0;
}
