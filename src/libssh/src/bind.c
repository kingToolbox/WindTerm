/*
 * bind.c : all ssh_bind functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2004-2005 by Aris Adamantiadis
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libssh/priv.h"
#include "libssh/bind.h"
#include "libssh/libssh.h"
#include "libssh/server.h"
#include "libssh/pki.h"
#include "libssh/buffer.h"
#include "libssh/socket.h"
#include "libssh/session.h"
#include "libssh/token.h"

/**
 * @addtogroup libssh_server
 *
 * @{
 */


#ifdef _WIN32
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/*
 * <wspiapi.h> is necessary for getaddrinfo before Windows XP, but it isn't
 * available on some platforms like MinGW.
 */
#ifdef HAVE_WSPIAPI_H
# include <wspiapi.h>
#endif

#define SOCKOPT_TYPE_ARG4 char

#else /* _WIN32 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#define SOCKOPT_TYPE_ARG4 int

#endif /* _WIN32 */

static socket_t bind_socket(ssh_bind sshbind, const char *hostname,
    int port) {
    char port_c[6];
    struct addrinfo *ai;
    struct addrinfo hints;
    int opt = 1;
    socket_t s;
    int rc;

    ZERO_STRUCT(hints);

    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_c, 6, "%d", port);
    rc = getaddrinfo(hostname, port_c, &hints, &ai);
    if (rc != 0) {
        ssh_set_error(sshbind,
                      SSH_FATAL,
                      "Resolving %s: %s", hostname, gai_strerror(rc));
        return -1;
    }

    s = socket (ai->ai_family,
                           ai->ai_socktype,
                           ai->ai_protocol);
    if (s == SSH_INVALID_SOCKET) {
        ssh_set_error(sshbind, SSH_FATAL, "%s", strerror(errno));
        freeaddrinfo (ai);
        return -1;
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                   (char *)&opt, sizeof(opt)) < 0) {
        ssh_set_error(sshbind,
                      SSH_FATAL,
                      "Setting socket options failed: %s",
                      strerror(errno));
        freeaddrinfo (ai);
        CLOSE_SOCKET(s);
        return -1;
    }

    if (bind(s, ai->ai_addr, ai->ai_addrlen) != 0) {
        ssh_set_error(sshbind,
                      SSH_FATAL,
                      "Binding to %s:%d: %s",
                      hostname,
                      port,
                      strerror(errno));
        freeaddrinfo (ai);
        CLOSE_SOCKET(s);
        return -1;
    }

    freeaddrinfo (ai);
    return s;
}

ssh_bind ssh_bind_new(void) {
    ssh_bind ptr;

    ptr = calloc(1, sizeof(struct ssh_bind_struct));
    if (ptr == NULL) {
        return NULL;
    }
    ptr->bindfd = SSH_INVALID_SOCKET;
    ptr->bindport = 22;
    ptr->common.log_verbosity = 0;

    return ptr;
}

static int ssh_bind_import_keys(ssh_bind sshbind) {
  int rc;

  if (sshbind->ecdsakey == NULL &&
      sshbind->dsakey == NULL &&
      sshbind->rsakey == NULL &&
      sshbind->ed25519key == NULL) {
      ssh_set_error(sshbind, SSH_FATAL,
                    "ECDSA, ED25519, DSA, or RSA host key file must be set");
      return SSH_ERROR;
  }

#ifdef HAVE_ECC
  if (sshbind->ecdsa == NULL && sshbind->ecdsakey != NULL) {
      rc = ssh_pki_import_privkey_file(sshbind->ecdsakey,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &sshbind->ecdsa);
      if (rc == SSH_ERROR || rc == SSH_EOF) {
          ssh_set_error(sshbind, SSH_FATAL,
                  "Failed to import private ECDSA host key");
          return SSH_ERROR;
      }

      if (!is_ecdsa_key_type(ssh_key_type(sshbind->ecdsa))) {
          ssh_set_error(sshbind, SSH_FATAL,
                  "The ECDSA host key has the wrong type");
          ssh_key_free(sshbind->ecdsa);
          sshbind->ecdsa = NULL;
          return SSH_ERROR;
      }
  }
#endif

#ifdef HAVE_DSA
  if (sshbind->dsa == NULL && sshbind->dsakey != NULL) {
      rc = ssh_pki_import_privkey_file(sshbind->dsakey,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &sshbind->dsa);
      if (rc == SSH_ERROR || rc == SSH_EOF) {
          ssh_set_error(sshbind, SSH_FATAL,
                  "Failed to import private DSA host key");
          return SSH_ERROR;
      }

      if (ssh_key_type(sshbind->dsa) != SSH_KEYTYPE_DSS) {
          ssh_set_error(sshbind, SSH_FATAL,
                  "The DSA host key has the wrong type: %d",
                  ssh_key_type(sshbind->dsa));
          ssh_key_free(sshbind->dsa);
          sshbind->dsa = NULL;
          return SSH_ERROR;
      }
  }
#endif

  if (sshbind->rsa == NULL && sshbind->rsakey != NULL) {
      rc = ssh_pki_import_privkey_file(sshbind->rsakey,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &sshbind->rsa);
      if (rc == SSH_ERROR || rc == SSH_EOF) {
          ssh_set_error(sshbind, SSH_FATAL,
                  "Failed to import private RSA host key");
          return SSH_ERROR;
      }

      if (ssh_key_type(sshbind->rsa) != SSH_KEYTYPE_RSA) {
          ssh_set_error(sshbind, SSH_FATAL,
                  "The RSA host key has the wrong type");
          ssh_key_free(sshbind->rsa);
          sshbind->rsa = NULL;
          return SSH_ERROR;
      }
  }

  if (sshbind->ed25519 == NULL && sshbind->ed25519key != NULL) {
      rc = ssh_pki_import_privkey_file(sshbind->ed25519key,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &sshbind->ed25519);
      if (rc == SSH_ERROR || rc == SSH_EOF) {
          ssh_set_error(sshbind, SSH_FATAL,
                  "Failed to import private ED25519 host key");
          return SSH_ERROR;
      }

      if (ssh_key_type(sshbind->ed25519) != SSH_KEYTYPE_ED25519) {
          ssh_set_error(sshbind, SSH_FATAL,
                  "The ED25519 host key has the wrong type");
          ssh_key_free(sshbind->ed25519);
          sshbind->ed25519 = NULL;
          return SSH_ERROR;
      }
  }

  return SSH_OK;
}

int ssh_bind_listen(ssh_bind sshbind) {
  const char *host;
  socket_t fd;
  int rc;

  if (sshbind->rsa == NULL &&
      sshbind->dsa == NULL &&
      sshbind->ecdsa == NULL &&
      sshbind->ed25519 == NULL) {
      rc = ssh_bind_import_keys(sshbind);
      if (rc != SSH_OK) {
          return SSH_ERROR;
      }
  }

  if (sshbind->bindfd == SSH_INVALID_SOCKET) {
      host = sshbind->bindaddr;
      if (host == NULL) {
          host = "0.0.0.0";
      }

      fd = bind_socket(sshbind, host, sshbind->bindport);
      if (fd == SSH_INVALID_SOCKET) {
          ssh_key_free(sshbind->dsa);
          sshbind->dsa = NULL;
          ssh_key_free(sshbind->rsa);
          sshbind->rsa = NULL;
          /* XXX should this clear also other structures that were allocated */
          return -1;
      }

      if (listen(fd, 10) < 0) {
          ssh_set_error(sshbind, SSH_FATAL,
                  "Listening to socket %d: %s",
                  fd, strerror(errno));
          CLOSE_SOCKET(fd);
          ssh_key_free(sshbind->dsa);
          sshbind->dsa = NULL;
          ssh_key_free(sshbind->rsa);
          sshbind->rsa = NULL;
          /* XXX should this clear also other structures that were allocated */
          return -1;
      }

      sshbind->bindfd = fd;
  } else {
      SSH_LOG(SSH_LOG_INFO, "Using app-provided bind socket");
  }
  return 0;
}

int ssh_bind_set_callbacks(ssh_bind sshbind, ssh_bind_callbacks callbacks,
    void *userdata){
  if (sshbind == NULL) {
    return SSH_ERROR;
  }
  if (callbacks == NULL) {
    ssh_set_error_invalid(sshbind);
    return SSH_ERROR;
  }
  if(callbacks->size <= 0 || callbacks->size > 1024 * sizeof(void *)){
    ssh_set_error(sshbind,SSH_FATAL,
        "Invalid callback passed in (badly initialized)");
    return SSH_ERROR;
  }
  sshbind->bind_callbacks = callbacks;
  sshbind->bind_callbacks_userdata=userdata;
  return 0;
}

/** @internal
 * @brief callback being called by poll when an event happens
 *
 */
static int ssh_bind_poll_callback(ssh_poll_handle sshpoll,
    socket_t fd, int revents, void *user){
  ssh_bind sshbind=(ssh_bind)user;
  (void)sshpoll;
  (void)fd;

  if(revents & POLLIN){
    /* new incoming connection */
    if(ssh_callbacks_exists(sshbind->bind_callbacks,incoming_connection)){
      sshbind->bind_callbacks->incoming_connection(sshbind,
          sshbind->bind_callbacks_userdata);
    }
  }
  return 0;
}

/** @internal
 * @brief returns the current poll handle, or create it
 * @param sshbind the ssh_bind object
 * @returns a ssh_poll handle suitable for operation
 */
ssh_poll_handle ssh_bind_get_poll(ssh_bind sshbind)
{
    short events = POLLIN;

    if (sshbind->poll) {
        return sshbind->poll;
    }

#ifdef POLLRDHUP
    events |= POLLRDHUP;
#endif /* POLLRDHUP */

    sshbind->poll = ssh_poll_new(sshbind->bindfd,
                                 events,
                                 ssh_bind_poll_callback,
                                 sshbind);

    return sshbind->poll;
}

void ssh_bind_set_blocking(ssh_bind sshbind, int blocking) {
  sshbind->blocking = blocking ? 1 : 0;
}

socket_t ssh_bind_get_fd(ssh_bind sshbind) {
  return sshbind->bindfd;
}

void ssh_bind_set_fd(ssh_bind sshbind, socket_t fd) {
  sshbind->bindfd = fd;
}

void ssh_bind_fd_toaccept(ssh_bind sshbind) {
  sshbind->toaccept = 1;
}

void ssh_bind_free(ssh_bind sshbind){
  int i;

  if (sshbind == NULL) {
    return;
  }

  if (sshbind->bindfd >= 0) {
      CLOSE_SOCKET(sshbind->bindfd);
  }
  sshbind->bindfd = SSH_INVALID_SOCKET;

  /* options */
  SAFE_FREE(sshbind->banner);
  SAFE_FREE(sshbind->bindaddr);
  SAFE_FREE(sshbind->config_dir);
  SAFE_FREE(sshbind->pubkey_accepted_key_types);

  SAFE_FREE(sshbind->dsakey);
  SAFE_FREE(sshbind->rsakey);
  SAFE_FREE(sshbind->ecdsakey);
  SAFE_FREE(sshbind->ed25519key);

  ssh_key_free(sshbind->dsa);
  sshbind->dsa = NULL;
  ssh_key_free(sshbind->rsa);
  sshbind->rsa = NULL;
  ssh_key_free(sshbind->ecdsa);
  sshbind->ecdsa = NULL;
  ssh_key_free(sshbind->ed25519);
  sshbind->ed25519 = NULL;

  for (i = 0; i < SSH_KEX_METHODS; i++) {
    if (sshbind->wanted_methods[i]) {
      SAFE_FREE(sshbind->wanted_methods[i]);
    }
  }

  SAFE_FREE(sshbind);
}

int ssh_bind_accept_fd(ssh_bind sshbind, ssh_session session, socket_t fd){
    int i, rc;

    if (sshbind == NULL) {
        return SSH_ERROR;
    }

    if (session == NULL){
        ssh_set_error(sshbind, SSH_FATAL,"session is null");
        return SSH_ERROR;
    }

    /* Apply global bind configurations, if it hasn't been applied before */
    rc = ssh_bind_options_parse_config(sshbind, NULL);
    if (rc != 0) {
        ssh_set_error(sshbind, SSH_FATAL,"Could not parse global config");
        return SSH_ERROR;
    }

    session->server = 1;

    /* Copy options from bind to session */
    for (i = 0; i < SSH_KEX_METHODS; i++) {
      if (sshbind->wanted_methods[i]) {
        session->opts.wanted_methods[i] = strdup(sshbind->wanted_methods[i]);
        if (session->opts.wanted_methods[i] == NULL) {
          return SSH_ERROR;
        }
      }
    }

    if (sshbind->bindaddr == NULL)
      session->opts.bindaddr = NULL;
    else {
      SAFE_FREE(session->opts.bindaddr);
      session->opts.bindaddr = strdup(sshbind->bindaddr);
      if (session->opts.bindaddr == NULL) {
        return SSH_ERROR;
      }
    }

    if (sshbind->pubkey_accepted_key_types != NULL) {
        if (session->opts.pubkey_accepted_types == NULL) {
            session->opts.pubkey_accepted_types = strdup(sshbind->pubkey_accepted_key_types);
            if (session->opts.pubkey_accepted_types == NULL) {
                ssh_set_error_oom(sshbind);
                return SSH_ERROR;
            }
        } else {
            char *p;
            /* If something was set to the session prior to calling this
             * function, keep only what is allowed by the options set in
             * sshbind */
            p = ssh_find_all_matching(sshbind->pubkey_accepted_key_types,
                                      session->opts.pubkey_accepted_types);
            if (p == NULL) {
                return SSH_ERROR;
            }

            SAFE_FREE(session->opts.pubkey_accepted_types);
            session->opts.pubkey_accepted_types = p;
        }
    }

    session->common.log_verbosity = sshbind->common.log_verbosity;
    if(sshbind->banner != NULL)
    	session->opts.custombanner = strdup(sshbind->banner);
    ssh_socket_free(session->socket);
    session->socket = ssh_socket_new(session);
    if (session->socket == NULL) {
      /* perhaps it may be better to copy the error from session to sshbind */
      ssh_set_error_oom(sshbind);
      return SSH_ERROR;
    }
    ssh_socket_set_fd(session->socket, fd);
    ssh_socket_get_poll_handle(session->socket);

    /* We must try to import any keys that could be imported in case
     * we are not using ssh_bind_listen (which is the other place
     * where keys can be imported) on this ssh_bind and are instead
     * only using ssh_bind_accept_fd to manage sockets ourselves.
     */
    if (sshbind->rsa == NULL &&
        sshbind->dsa == NULL &&
        sshbind->ecdsa == NULL &&
        sshbind->ed25519 == NULL) {
        rc = ssh_bind_import_keys(sshbind);
        if (rc != SSH_OK) {
            return SSH_ERROR;
        }
    }

#ifdef HAVE_ECC
    if (sshbind->ecdsa) {
        session->srv.ecdsa_key = ssh_key_dup(sshbind->ecdsa);
        if (session->srv.ecdsa_key == NULL) {
          ssh_set_error_oom(sshbind);
          return SSH_ERROR;
        }
    }
#endif
#ifdef HAVE_DSA
    if (sshbind->dsa) {
        session->srv.dsa_key = ssh_key_dup(sshbind->dsa);
        if (session->srv.dsa_key == NULL) {
          ssh_set_error_oom(sshbind);
          return SSH_ERROR;
        }
    }
#endif
    if (sshbind->rsa) {
        session->srv.rsa_key = ssh_key_dup(sshbind->rsa);
        if (session->srv.rsa_key == NULL) {
          ssh_set_error_oom(sshbind);
          return SSH_ERROR;
        }
    }
    if (sshbind->ed25519 != NULL) {
        session->srv.ed25519_key = ssh_key_dup(sshbind->ed25519);
        if (session->srv.ed25519_key == NULL){
            ssh_set_error_oom(sshbind);
            return SSH_ERROR;
        }
    }

    /* force PRNG to change state in case we fork after ssh_bind_accept */
    ssh_reseed();
    return SSH_OK;
}

int ssh_bind_accept(ssh_bind sshbind, ssh_session session) {
  socket_t fd = SSH_INVALID_SOCKET;
  int rc;
  if (sshbind->bindfd == SSH_INVALID_SOCKET) {
    ssh_set_error(sshbind, SSH_FATAL,
        "Can't accept new clients on a not bound socket.");
    return SSH_ERROR;
  }

  if (session == NULL){
      ssh_set_error(sshbind, SSH_FATAL,"session is null");
      return SSH_ERROR;
  }

  fd = accept(sshbind->bindfd, NULL, NULL);
  if (fd == SSH_INVALID_SOCKET) {
    ssh_set_error(sshbind, SSH_FATAL,
        "Accepting a new connection: %s",
        strerror(errno));
    return SSH_ERROR;
  }
  rc = ssh_bind_accept_fd(sshbind, session, fd);

  if(rc == SSH_ERROR){
      CLOSE_SOCKET(fd);
      ssh_socket_free(session->socket);
  }
  return rc;
}


/**
 * @}
 */
