/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

/** functions in that file are wrappers to the newly named functions. All
 * of them are depreciated, but these wrapper will avoid breaking backward
 * compatibility
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>

#include <libssh/priv.h>
#include <libssh/session.h>
#include <libssh/server.h>
#include <libssh/buffer.h>
#include <libssh/dh.h>
#include <libssh/pki.h>
#include "libssh/pki_priv.h"
#include <libssh/misc.h>
#include <libssh/keys.h>
#include "libssh/options.h"

/* AUTH FUNCTIONS */
int ssh_auth_list(ssh_session session) {
  return ssh_userauth_list(session, NULL);
}

int ssh_userauth_offer_pubkey(ssh_session session, const char *username,
    int type, ssh_string publickey)
{
    ssh_key key;
    int rc;

    (void) type; /* unused */

    rc = ssh_pki_import_pubkey_blob(publickey, &key);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Failed to convert public key");
        return SSH_AUTH_ERROR;
    }

    rc = ssh_userauth_try_publickey(session, username, key);
    ssh_key_free(key);

    return rc;
}

int ssh_userauth_pubkey(ssh_session session,
                        const char *username,
                        ssh_string publickey,
                        ssh_private_key privatekey)
{
    ssh_key key;
    int rc;

    (void) publickey; /* unused */

    key = ssh_key_new();
    if (key == NULL) {
        return SSH_AUTH_ERROR;
    }

    key->type = privatekey->type;
    key->type_c = ssh_key_type_to_char(key->type);
    key->flags = SSH_KEY_FLAG_PRIVATE|SSH_KEY_FLAG_PUBLIC;
    key->dsa = privatekey->dsa_priv;
    key->rsa = privatekey->rsa_priv;

    rc = ssh_userauth_publickey(session, username, key);
    key->dsa = NULL;
    key->rsa = NULL;
    ssh_key_free(key);

    return rc;
}

int ssh_userauth_autopubkey(ssh_session session, const char *passphrase) {
    return ssh_userauth_publickey_auto(session, NULL, passphrase);
}

int ssh_userauth_privatekey_file(ssh_session session,
                                 const char *username,
                                 const char *filename,
                                 const char *passphrase) {
  char *pubkeyfile = NULL;
  ssh_string pubkey = NULL;
  ssh_private_key privkey = NULL;
  int type = 0;
  int rc = SSH_AUTH_ERROR;
  size_t klen = strlen(filename) + 4 + 1;

  pubkeyfile = malloc(klen);
  if (pubkeyfile == NULL) {
    ssh_set_error_oom(session);

    return SSH_AUTH_ERROR;
  }
  snprintf(pubkeyfile, klen, "%s.pub", filename);

  pubkey = publickey_from_file(session, pubkeyfile, &type);
  if (pubkey == NULL) {
    SSH_LOG(SSH_LOG_RARE, "Public key file %s not found. Trying to generate it.", pubkeyfile);
    /* auto-detect the key type with type=0 */
    privkey = privatekey_from_file(session, filename, 0, passphrase);
  } else {
    SSH_LOG(SSH_LOG_RARE, "Public key file %s loaded.", pubkeyfile);
    privkey = privatekey_from_file(session, filename, type, passphrase);
  }
  if (privkey == NULL) {
    goto error;
  }
  /* ssh_userauth_pubkey is responsible for taking care of null-pubkey */
  rc = ssh_userauth_pubkey(session, username, pubkey, privkey);
  privatekey_free(privkey);

error:
  SAFE_FREE(pubkeyfile);
  ssh_string_free(pubkey);

  return rc;
}

/* BUFFER FUNCTIONS */

void buffer_free(ssh_buffer buffer){
  ssh_buffer_free(buffer);
}
void *buffer_get(ssh_buffer buffer){
  return ssh_buffer_get(buffer);
}
uint32_t buffer_get_len(ssh_buffer buffer){
  return ssh_buffer_get_len(buffer);
}
ssh_buffer buffer_new(void){
  return ssh_buffer_new();
}

ssh_channel channel_accept_x11(ssh_channel channel, int timeout_ms){
  return ssh_channel_accept_x11(channel, timeout_ms);
}

int channel_change_pty_size(ssh_channel channel,int cols,int rows){
  return ssh_channel_change_pty_size(channel,cols,rows);
}

ssh_channel channel_forward_accept(ssh_session session, int timeout_ms){
  return ssh_channel_accept_forward(session, timeout_ms, NULL);
}

int channel_close(ssh_channel channel){
  return ssh_channel_close(channel);
}

int channel_forward_cancel(ssh_session session, const char *address, int port){
  return ssh_channel_cancel_forward(session, address, port);
}

int channel_forward_listen(ssh_session session, const char *address,
    int port, int *bound_port){
  return ssh_channel_listen_forward(session, address, port, bound_port);
}

void channel_free(ssh_channel channel){
  ssh_channel_free(channel);
}

int channel_get_exit_status(ssh_channel channel){
  return ssh_channel_get_exit_status(channel);
}

ssh_session channel_get_session(ssh_channel channel){
  return ssh_channel_get_session(channel);
}

int channel_is_closed(ssh_channel channel){
  return ssh_channel_is_closed(channel);
}

int channel_is_eof(ssh_channel channel){
  return ssh_channel_is_eof(channel);
}

int channel_is_open(ssh_channel channel){
  return ssh_channel_is_open(channel);
}

ssh_channel channel_new(ssh_session session){
  return ssh_channel_new(session);
}

int channel_open_forward(ssh_channel channel, const char *remotehost,
    int remoteport, const char *sourcehost, int localport){
  return ssh_channel_open_forward(channel, remotehost, remoteport,
      sourcehost,localport);
}

int channel_open_session(ssh_channel channel){
  return ssh_channel_open_session(channel);
}

int channel_poll(ssh_channel channel, int is_stderr){
  return ssh_channel_poll(channel, is_stderr);
}

int channel_read(ssh_channel channel, void *dest, uint32_t count, int is_stderr){
  return ssh_channel_read(channel, dest, count, is_stderr);
}

/*
 * This function will completely be depreciated. The old implementation was not
 * renamed.
 * int channel_read_buffer(ssh_channel channel, ssh_buffer buffer, uint32_t count,
 *   int is_stderr);
 */

int channel_read_nonblocking(ssh_channel channel, void *dest, uint32_t count,
    int is_stderr){
  return ssh_channel_read_nonblocking(channel, dest, count, is_stderr);
}

int channel_request_env(ssh_channel channel, const char *name, const char *value){
  return ssh_channel_request_env(channel, name, value);
}

int channel_request_exec(ssh_channel channel, const char *cmd){
  return ssh_channel_request_exec(channel, cmd);
}

int channel_request_pty(ssh_channel channel){
  return ssh_channel_request_pty(channel);
}

int channel_request_pty_size(ssh_channel channel, const char *term,
    int cols, int rows){
  return ssh_channel_request_pty_size(channel, term, cols, rows);
}

int channel_request_shell(ssh_channel channel){
  return ssh_channel_request_shell(channel);
}

int channel_request_send_signal(ssh_channel channel, const char *signum){
  return ssh_channel_request_send_signal(channel, signum);
}

int channel_request_sftp(ssh_channel channel){
  return ssh_channel_request_sftp(channel);
}

int channel_request_subsystem(ssh_channel channel, const char *subsystem){
  return ssh_channel_request_subsystem(channel, subsystem);
}

int channel_request_x11(ssh_channel channel, int single_connection, const char *protocol,
    const char *cookie, int screen_number){
  return ssh_channel_request_x11(channel, single_connection, protocol, cookie,
      screen_number);
}

int channel_send_eof(ssh_channel channel){
  return ssh_channel_send_eof(channel);
}

int channel_select(ssh_channel *readchans, ssh_channel *writechans, ssh_channel *exceptchans, struct
    timeval * timeout){
  return ssh_channel_select(readchans, writechans, exceptchans, timeout);
}

void channel_set_blocking(ssh_channel channel, int blocking){
  ssh_channel_set_blocking(channel, blocking);
}

int channel_write(ssh_channel channel, const void *data, uint32_t len){
  return ssh_channel_write(channel, data, len);
}

/*
 * These functions have to be wrapped around the pki.c functions.

void privatekey_free(ssh_private_key prv);
ssh_private_key privatekey_from_file(ssh_session session, const char *filename,
    int type, const char *passphrase);
int ssh_publickey_to_file(ssh_session session, const char *file,
    ssh_string pubkey, int type);
ssh_string publickey_to_string(ssh_public_key key);
 *
 */

void string_burn(ssh_string str){
  ssh_string_burn(str);
}

ssh_string string_copy(ssh_string str){
  return ssh_string_copy(str);
}

void *string_data(ssh_string str){
  return ssh_string_data(str);
}

int string_fill(ssh_string str, const void *data, size_t len){
  return ssh_string_fill(str,data,len);
}

void string_free(ssh_string str){
  ssh_string_free(str);
}

ssh_string string_from_char(const char *what){
  return ssh_string_from_char(what);
}

size_t string_len(ssh_string str){
  return ssh_string_len(str);
}

ssh_string string_new(size_t size){
  return ssh_string_new(size);
}

char *string_to_char(ssh_string str){
  return ssh_string_to_char(str);
}

/* OLD PKI FUNCTIONS */

void publickey_free(ssh_public_key key) {
  if (key == NULL) {
    return;
  }

  switch(key->type) {
    case SSH_KEYTYPE_DSS:
#ifdef HAVE_LIBGCRYPT
      gcry_sexp_release(key->dsa_pub);
#elif defined HAVE_LIBCRYPTO
      DSA_free(key->dsa_pub);
#endif
      break;
    case SSH_KEYTYPE_RSA:
#ifdef HAVE_LIBGCRYPT
      gcry_sexp_release(key->rsa_pub);
#elif defined HAVE_LIBCRYPTO
      RSA_free(key->rsa_pub);
#elif defined HAVE_LIBMBEDCRYPTO
      mbedtls_pk_free(key->rsa_pub);
      SAFE_FREE(key->rsa_pub);
#endif
      break;
    default:
      break;
  }
  SAFE_FREE(key);
}

ssh_public_key publickey_from_privatekey(ssh_private_key prv) {
    struct ssh_public_key_struct *p;
    ssh_key privkey;
    ssh_key pubkey;
    int rc;

    privkey = ssh_key_new();
    if (privkey == NULL) {
        return NULL;
    }

    privkey->type = prv->type;
    privkey->type_c = ssh_key_type_to_char(privkey->type);
    privkey->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;
    privkey->dsa = prv->dsa_priv;
    privkey->rsa = prv->rsa_priv;

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    privkey->dsa = NULL;
    privkey->rsa = NULL;
    ssh_key_free(privkey);
    if (rc < 0) {
        return NULL;
    }

    p = ssh_pki_convert_key_to_publickey(pubkey);
    ssh_key_free(pubkey);

    return p;
}

ssh_private_key privatekey_from_file(ssh_session session,
                                     const char *filename,
                                     int type,
                                     const char *passphrase) {
    ssh_auth_callback auth_fn = NULL;
    void *auth_data = NULL;
    ssh_private_key privkey;
    ssh_key key;
    int rc;

    (void) type; /* unused */

    if (session->common.callbacks) {
        auth_fn = session->common.callbacks->auth_function;
        auth_data = session->common.callbacks->userdata;
    }


    rc = ssh_pki_import_privkey_file(filename,
                                     passphrase,
                                     auth_fn,
                                     auth_data,
                                     &key);
    if (rc == SSH_ERROR) {
        return NULL;
    }

    privkey = malloc(sizeof(struct ssh_private_key_struct));
    if (privkey == NULL) {
        ssh_key_free(key);
        return NULL;
    }

    privkey->type = key->type;
    privkey->dsa_priv = key->dsa;
    privkey->rsa_priv = key->rsa;

    key->dsa = NULL;
    key->rsa = NULL;

    ssh_key_free(key);

    return privkey;
}

enum ssh_keytypes_e ssh_privatekey_type(ssh_private_key privatekey){
  if (privatekey==NULL)
    return SSH_KEYTYPE_UNKNOWN;
  return privatekey->type;
}

void privatekey_free(ssh_private_key prv) {
  if (prv == NULL) {
    return;
  }

#ifdef HAVE_LIBGCRYPT
  gcry_sexp_release(prv->dsa_priv);
  gcry_sexp_release(prv->rsa_priv);
#elif defined HAVE_LIBCRYPTO
  DSA_free(prv->dsa_priv);
  RSA_free(prv->rsa_priv);
#elif defined HAVE_LIBMBEDCRYPTO
  mbedtls_pk_free(prv->rsa_priv);
  SAFE_FREE(prv->rsa_priv);
#endif
  memset(prv, 0, sizeof(struct ssh_private_key_struct));
  SAFE_FREE(prv);
}

ssh_string publickey_from_file(ssh_session session, const char *filename,
    int *type) {
    ssh_key key;
    ssh_string key_str = NULL;
    int rc;

    (void) session; /* unused */

    rc = ssh_pki_import_pubkey_file(filename, &key);
    if (rc < 0) {
        return NULL;
    }

    rc = ssh_pki_export_pubkey_blob(key, &key_str);
    if (rc < 0) {
        ssh_key_free(key);
        return NULL;
    }

    if (type) {
        *type = key->type;
    }
    ssh_key_free(key);

    return key_str;
}

const char *ssh_type_to_char(int type) {
    return ssh_key_type_to_char(type);
}

int ssh_type_from_name(const char *name) {
    return ssh_key_type_from_name(name);
}

ssh_public_key publickey_from_string(ssh_session session, ssh_string pubkey_s) {
    struct ssh_public_key_struct *pubkey;
    ssh_key key;
    int rc;

    (void) session; /* unused */

    rc = ssh_pki_import_pubkey_blob(pubkey_s, &key);
    if (rc < 0) {
        return NULL;
    }

    pubkey = malloc(sizeof(struct ssh_public_key_struct));
    if (pubkey == NULL) {
        ssh_key_free(key);
        return NULL;
    }

    pubkey->type = key->type;
    pubkey->type_c = key->type_c;

    pubkey->dsa_pub = key->dsa;
    key->dsa = NULL;
    pubkey->rsa_pub = key->rsa;
    key->rsa = NULL;

    ssh_key_free(key);

    return pubkey;
}

ssh_string publickey_to_string(ssh_public_key pubkey) {
    ssh_key key;
    ssh_string key_blob;
    int rc;

    if (pubkey == NULL) {
        return NULL;
    }

    key = ssh_key_new();
    if (key == NULL) {
        return NULL;
    }

    key->type = pubkey->type;
    key->type_c = pubkey->type_c;

    key->dsa = pubkey->dsa_pub;
    key->rsa = pubkey->rsa_pub;

    rc = ssh_pki_export_pubkey_blob(key, &key_blob);
    if (rc < 0) {
        key_blob = NULL;
    }

    key->dsa = NULL;
    key->rsa = NULL;
    ssh_key_free(key);

    return key_blob;
}

int ssh_publickey_to_file(ssh_session session,
                          const char *file,
                          ssh_string pubkey,
                          int type)
{
    FILE *fp;
    char *user;
    char buffer[1024];
    char host[256];
    unsigned char *pubkey_64;
    size_t len;
    int rc;
    if(session==NULL)
        return SSH_ERROR;
    if(file==NULL || pubkey==NULL){
        ssh_set_error(session, SSH_FATAL, "Invalid parameters");
        return SSH_ERROR;
    }
    pubkey_64 = bin_to_base64(ssh_string_data(pubkey), ssh_string_len(pubkey));
    if (pubkey_64 == NULL) {
        return SSH_ERROR;
    }

    user = ssh_get_local_username();
    if (user == NULL) {
        SAFE_FREE(pubkey_64);
        return SSH_ERROR;
    }

    rc = gethostname(host, sizeof(host));
    if (rc < 0) {
        SAFE_FREE(user);
        SAFE_FREE(pubkey_64);
        return SSH_ERROR;
    }

    snprintf(buffer, sizeof(buffer), "%s %s %s@%s\n",
            ssh_type_to_char(type),
            pubkey_64,
            user,
            host);

    SAFE_FREE(pubkey_64);
    SAFE_FREE(user);

    SSH_LOG(SSH_LOG_RARE, "Trying to write public key file: %s", file);
    SSH_LOG(SSH_LOG_PACKET, "public key file content: %s", buffer);

    fp = fopen(file, "w+");
    if (fp == NULL) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                "Error opening %s: %s", file, strerror(errno));
        return SSH_ERROR;
    }

    len = strlen(buffer);
    if (fwrite(buffer, len, 1, fp) != 1 || ferror(fp)) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                "Unable to write to %s", file);
        fclose(fp);
        unlink(file);
        return SSH_ERROR;
    }

    fclose(fp);
    return SSH_OK;
}

int ssh_try_publickey_from_file(ssh_session session,
                                const char *keyfile,
                                ssh_string *publickey,
                                int *type) {
    char *pubkey_file;
    size_t len;
    ssh_string pubkey_string;
    int pubkey_type;

    if (session == NULL || keyfile == NULL || publickey == NULL || type == NULL) {
        return -1;
    }

    if (session->opts.sshdir == NULL) {
        if (ssh_options_apply(session) < 0) {
            return -1;
        }
    }

    SSH_LOG(SSH_LOG_PACKET, "Trying to open privatekey %s", keyfile);
    if (!ssh_file_readaccess_ok(keyfile)) {
        SSH_LOG(SSH_LOG_PACKET, "Failed to open privatekey %s", keyfile);
        return -1;
    }

    len = strlen(keyfile) + 5;
    pubkey_file = malloc(len);
    if (pubkey_file == NULL) {
        return -1;
    }
    snprintf(pubkey_file, len, "%s.pub", keyfile);

    SSH_LOG(SSH_LOG_PACKET, "Trying to open publickey %s",
            pubkey_file);
    if (!ssh_file_readaccess_ok(pubkey_file)) {
        SSH_LOG(SSH_LOG_PACKET, "Failed to open publickey %s",
                pubkey_file);
        SAFE_FREE(pubkey_file);
        return 1;
    }

    SSH_LOG(SSH_LOG_PACKET, "Success opening public and private key");

    /*
     * We are sure both the private and public key file is readable. We return
     * the public as a string, and the private filename as an argument
     */
    pubkey_string = publickey_from_file(session, pubkey_file, &pubkey_type);
    if (pubkey_string == NULL) {
        SSH_LOG(SSH_LOG_PACKET,
                "Wasn't able to open public key file %s: %s",
                pubkey_file,
                ssh_get_error(session));
        SAFE_FREE(pubkey_file);
        return -1;
    }

    SAFE_FREE(pubkey_file);

    *publickey = pubkey_string;
    *type = pubkey_type;

    return 0;
}

ssh_string ssh_get_pubkey(ssh_session session)
{
    ssh_string pubkey_blob = NULL;
    int rc;

    if (session == NULL ||
        session->current_crypto == NULL ||
        session->current_crypto->server_pubkey == NULL) {
        return NULL;
    }

    rc = ssh_dh_get_current_server_publickey_blob(session,
                                                  &pubkey_blob);
    if (rc != 0) {
        return NULL;
    }

    return pubkey_blob;
}

/****************************************************************************
 * SERVER SUPPORT
 ****************************************************************************/

#ifdef WITH_SERVER
int ssh_accept(ssh_session session) {
    return ssh_handle_key_exchange(session);
}

int channel_write_stderr(ssh_channel channel, const void *data, uint32_t len) {
    return ssh_channel_write(channel, data, len);
}

/** @deprecated
 * @brief Interface previously exported by error.
 */
ssh_message ssh_message_retrieve(ssh_session session, uint32_t packettype){
	(void) packettype;
	ssh_set_error(session, SSH_FATAL, "ssh_message_retrieve: obsolete libssh call");
	return NULL;
}

#endif /* WITH_SERVER */
