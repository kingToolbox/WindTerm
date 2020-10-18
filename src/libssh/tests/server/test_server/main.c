/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Red Hat, Inc.
 *
 * Author: Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
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
#include "test_server.h"
#include "default_cb.h"

#include <libssh/priv.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#ifdef HAVE_ARGP_H
#include <argp.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

struct arguments_st {
    char *address;
    char *port;

    char *ecdsa_key;
    char *dsa_key;
    char *ed25519_key;
    char *rsa_key;
    char *host_key;

    char *verbosity;
    char *auth_methods;
    bool with_pcap;

    char *pcap_file;

    char *username;
    char *password;

    char *config_file;
    bool with_global_config;
};

static void free_arguments(struct arguments_st *arguments)
{
    if (arguments == NULL) {
        goto end;
    }

    SAFE_FREE(arguments->address);
    SAFE_FREE(arguments->port);

    SAFE_FREE(arguments->ecdsa_key);
    SAFE_FREE(arguments->dsa_key);
    SAFE_FREE(arguments->ed25519_key);
    SAFE_FREE(arguments->rsa_key);
    SAFE_FREE(arguments->host_key);

    SAFE_FREE(arguments->verbosity);
    SAFE_FREE(arguments->auth_methods);
    SAFE_FREE(arguments->pcap_file);

    SAFE_FREE(arguments->username);
    SAFE_FREE(arguments->password);
    SAFE_FREE(arguments->config_file);

end:
    return;
}

#ifdef HAVE_ARGP_H

static void print_auth_methods(int auth_methods)
{
    printf("auth_methods = \n");
    if (auth_methods & SSH_AUTH_METHOD_NONE) {
        printf("\tSSH_AUTH_METHOD_NONE\n");
    }
    if (auth_methods & SSH_AUTH_METHOD_PASSWORD) {
        printf("\tSSH_AUTH_METHOD_PASSWORD\n");
    }
    if (auth_methods & SSH_AUTH_METHOD_PUBLICKEY) {
        printf("\tSSH_AUTH_METHOD_PUBLICKEY\n");
    }
    if (auth_methods & SSH_AUTH_METHOD_HOSTBASED) {
        printf("\tSSH_AUTH_METHOD_HOSTBASED\n");
    }
    if (auth_methods & SSH_AUTH_METHOD_INTERACTIVE) {
        printf("\tSSH_AUTH_METHOD_INTERACTIVE\n");
    }
    if (auth_methods & SSH_AUTH_METHOD_GSSAPI_MIC) {
        printf("\tSSH_AUTH_METHOD_GSSAPI_MIC\n");
    }
}

static void print_verbosity(int verbosity)
{
    printf("verbosity = ");
    switch(verbosity) {
    case SSH_LOG_NOLOG:
        printf("NO LOG\n");
        break;
    case SSH_LOG_WARNING:
        printf("WARNING\n");
        break;
    case SSH_LOG_PROTOCOL:
        printf("PROTOCOL\n");
        break;
    case SSH_LOG_PACKET:
        printf("PACKET\n");
        break;
    case SSH_LOG_FUNCTIONS:
        printf("FUNCTIONS\n");
        break;
    default:
        printf("UNKNOWN\n");;
        break;
    }
}

static void print_server_state(struct server_state_st *state)
{
    if (state) {
        printf("===================| STATE |=====================\n");
        printf("address = %s\n",
                state->address? state->address: "NULL");
        printf("port = %d\n",
                state->port? state->port: 0);
        printf("=================================================\n");
        printf("ecdsa_key = %s\n",
                state->ecdsa_key? state->ecdsa_key: "NULL");
        printf("dsa_key = %s\n",
                state->dsa_key? state->dsa_key: "NULL");
        printf("ed25519_key = %s\n",
                state->ed25519_key? state->ed25519_key: "NULL");
        printf("rsa_key = %s\n",
                state->rsa_key? state->rsa_key: "NULL");
        printf("host_key = %s\n",
                state->host_key? state->host_key: "NULL");
        printf("=================================================\n");
        print_auth_methods(state->auth_methods);
        print_verbosity(state->verbosity);
        printf("with_pcap = %s\n",
                state->with_pcap? "TRUE": "FALSE");
        printf("pcap_file = %s\n",
                state->pcap_file? state->pcap_file: "NULL");
        printf("=================================================\n");
        printf("username = %s\n",
                state->expected_username? state->expected_username: "NULL");
        printf("password = %s\n",
                state->expected_password? state->expected_password: "NULL");
        printf("=================================================\n");
        printf("with_global_config = %s\n",
                state->parse_global_config? "TRUE": "FALSE");
        printf("config_file = %s\n",
                state->config_file? state->config_file: "NULL");
        printf("=================================================\n");
    }
}

static int init_server_state(struct server_state_st *state,
                             struct arguments_st *arguments)
{
    int rc = 0;

    if (state == NULL) {
        rc = SSH_ERROR;
        goto end;
    }

    /* Initialize server state. The "arguments structure" */
    if (arguments->address) {
        state->address = arguments->address;
        arguments->address = NULL;
    } else {
        state->address = strdup(SSHD_DEFAULT_ADDRESS);
        if (state->address == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = SSH_ERROR;
            goto end;
        }
    }

    if (arguments->port) {
        state->port = atoi(arguments->port);
    } else {
        state->port = SSHD_DEFAULT_PORT;
    }

    if (arguments->ecdsa_key) {
        state->ecdsa_key = arguments->ecdsa_key;
        arguments->ecdsa_key = NULL;
    } else {
        state->ecdsa_key = NULL;
    }

    if (arguments->dsa_key) {
        state->dsa_key = arguments->dsa_key;
        arguments->dsa_key = NULL;
    } else {
        state->dsa_key = NULL;
    }

    if (arguments->ed25519_key) {
        state->ed25519_key = arguments->ed25519_key;
        arguments->ed25519_key = NULL;
    } else {
        state->ed25519_key = NULL;
    }

    if (arguments->rsa_key) {
        state->rsa_key = arguments->rsa_key;
        arguments->rsa_key = NULL;
    } else {
        state->rsa_key = NULL;
    }

    if (arguments->host_key) {
        state->host_key = arguments->host_key;
        arguments->host_key = NULL;
    } else {
        state->host_key = NULL;
    }

    if (arguments->username) {
        state->expected_username = arguments->username;
        arguments->username = NULL;
    } else {
        state->expected_username = strdup(SSHD_DEFAULT_USER);
        if (state->expected_username == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = SSH_ERROR;
            goto end;
        }
    }

    if (arguments->password) {
        state->expected_password = arguments->password;
        arguments->password = NULL;
    } else {
        state->expected_password = strdup(SSHD_DEFAULT_PASSWORD);
        if (state->expected_password == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = SSH_ERROR;
            goto end;
        }
    }

    if (arguments->verbosity) {
        state->verbosity = atoi(arguments->verbosity);
    } else {
        state->verbosity = 0;
    }

    if (arguments->auth_methods) {
        state->auth_methods = atoi(arguments->auth_methods);
    } else {
        state->auth_methods = SSH_AUTH_METHOD_PASSWORD |
                              SSH_AUTH_METHOD_PUBLICKEY;
    }

    state->with_pcap = arguments->with_pcap;

    if (arguments->pcap_file) {
        state->pcap_file = arguments->pcap_file;
        arguments->pcap_file = NULL;
    } else {
        if (arguments->with_pcap) {
            state->pcap_file = strdup(SSHD_DEFAULT_PCAP_FILE);
            if (state->pcap_file == NULL) {
                fprintf(stderr, "Out of memory\n");
                rc = SSH_ERROR;
                goto end;
            }
        } else {
            state->pcap_file = NULL;
        }
    }

    state->parse_global_config = arguments->with_global_config;

    if (arguments->config_file) {
        state->config_file = arguments->config_file;
        arguments->config_file = NULL;
    }

    /* TODO make configurable */
    state->max_tries = 3;
    state->error = 0;


    if (state) {
        print_server_state(state);
    }

    /* TODO make callbacks configurable through command line ? */
    /* Set callbacks to be used */
    state->handle_session = default_handle_session_cb;

    /* Check required parameters */
    if (state->address == NULL) {
        rc = SSH_ERROR;
        goto end;
    }

end:
    if (rc != 0) {
        free_server_state(state);
    }

    return rc;
}

const char *argp_program_version = "libssh test server "
SSH_STRINGIFY(LIBSSH_VERSION);
const char *argp_program_bug_address = "<libssh@libssh.org>";

/* Program documentation. */
static char doc[] = "libssh -- a Secure Shell protocol implementation";

/* A description of the arguments we accept. */
static char args_doc[] = "BINDADDR";

/* The options we understand. */
static struct argp_option options[] = {
    {
        .name  = "port",
        .key   = 'p',
        .arg   = "PORT",
        .flags = 0,
        .doc   = "Set the port to bind.",
        .group = 0
    },
    {
        .name  = "ecdsakey",
        .key   = 'c',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the ECDSA key.",
        .group = 0
    },
    {
        .name  = "dsakey",
        .key   = 'd',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the DSA key.",
        .group = 0
    },
    {
        .name  = "ed25519key",
        .key   = 'e',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the ed25519 key.",
        .group = 0
    },
    {
        .name  = "rsakey",
        .key   = 'r',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the RSA key.",
        .group = 0
    },
    {
        .name  = "hostkey",
        .key   = 'k',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the host key.",
        .group = 0
    },
    {
        .name  = "pcapfile",
        .key   = 'f',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the pcap output file.",
        .group = 0
    },
    {
        .name  = "auth-methods",
        .key   = 'a',
        .arg   = "METHODS",
        .flags = 0,
        .doc   = "Set supported authentication methods.",
        .group = 0
    },
    {
        .name  = "user",
        .key   = 'u',
        .arg   = "USERNAME",
        .flags = 0,
        .doc   = "Set expected username.",
        .group = 0
    },
    {
        .name  = "verbosity",
        .key   = 'v',
        .arg   = "VERBOSITY",
        .flags = 0,
        .doc   = "Set output verbosity [0-4].",
        .group = 0
    },
    {
        .name  = "with-pcap",
        .key   = 'w',
        .arg   = NULL,
        .flags = 0,
        .doc   = "Use PCAP.",
        .group = 0
    },
    {
        .name  = "without-global-config",
        .key   = 'g',
        .arg   = NULL,
        .flags = 0,
        .doc   = "Do not use system-wide configuration file.",
        .group = 0
    },
    {
        .name  = "config",
        .key   = 'C',
        .arg   = "CONFIG_FILE",
        .flags = 0,
        .doc   = "Use this server configuration file.",
        .group = 0
    },
    { .name = NULL }
};

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
    /* Get the input argument from argp_parse, which we
     * know is a pointer to our arguments structure.
     */
    struct arguments_st *arguments = state->input;
    error_t rc = 0;

    if (arguments == NULL) {
        fprintf(stderr, "NULL pointer to arguments structure provided\n");
        rc = EINVAL;
        goto end;
    }

    switch (key) {
    case 'c':
        arguments->ecdsa_key = strdup(arg);
        if (arguments->ecdsa_key == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case 'd':
        arguments->dsa_key = strdup(arg);
        if (arguments->dsa_key == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case 'e':
        arguments->ed25519_key = strdup(arg);
        if (arguments->ed25519_key == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case 'f':
        arguments->pcap_file = strdup(arg);
        if (arguments->pcap_file == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case 'k':
        arguments->host_key = strdup(arg);
        if (arguments->host_key == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case 'a':
        arguments->auth_methods = strdup(arg);
        if (arguments->auth_methods == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case 'p':
        arguments->port = strdup(arg);
        if (arguments->port == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case 'r':
        arguments->rsa_key = strdup(arg);
        if (arguments->rsa_key == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case 'u':
        arguments->username = strdup(arg);
        if (arguments->username == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case 'v':
        arguments->verbosity = strdup(arg);
        if (arguments->verbosity == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case 'w':
        arguments->with_pcap = true;
        break;
    case 'g':
        arguments->with_global_config = false;
        break;
    case 'C':
        arguments->config_file = strdup(arg);
        if (arguments->config_file == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case ARGP_KEY_ARG:
        if (state->arg_num >= 1) {
            /* Too many arguments. */
            printf("Too many arguments\n");
            argp_usage(state);
        }
        arguments->address = strdup(arg);
        if (arguments->address == NULL) {
            fprintf(stderr, "Out of memory\n");
            rc = ENOMEM;
            goto end;
        }
        break;
    case ARGP_KEY_END:
        if (state->arg_num < 1) {
            printf("Too few arguments\n");
            /* Not enough arguments. */
            argp_usage(state);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

end:
    return rc;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

#endif /* HAVE_ARGP_H */

int main(UNUSED_PARAM(int argc), UNUSED_PARAM(char **argv))
{
    int rc;

    struct arguments_st arguments = {
        .address = NULL,
        .with_global_config = true,
    };
    struct server_state_st state = {
        .address = NULL,
    };

#ifdef HAVE_ARGP_H
    argp_parse (&argp, argc, argv, 0, 0, &arguments);
#endif

    /* Initialize the state using default or given parameters */
    rc = init_server_state(&state, &arguments);
    if (rc != 0) {
        goto free_arguments;
    }

    /* Free the arguments used to initialize the state before fork */
    free_arguments(&arguments);

    /* Run the server */
    rc = run_server(&state);
    if (rc != 0) {
        goto free_state;
    }

free_state:
    free_server_state(&state);
free_arguments:
    free_arguments(&arguments);
    return rc;
}
