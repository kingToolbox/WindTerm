/* Public include file for server support */
/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @defgroup libssh_server The libssh server API
 *
 * @{
 */

#ifndef SERVER_H
#define SERVER_H

#include "libssh/libssh.h"
#define SERVERBANNER CLIENTBANNER

#ifdef __cplusplus
extern "C" {
#endif

enum ssh_bind_options_e {
  SSH_BIND_OPTIONS_BINDADDR,
  SSH_BIND_OPTIONS_BINDPORT,
  SSH_BIND_OPTIONS_BINDPORT_STR,
  SSH_BIND_OPTIONS_HOSTKEY,
  SSH_BIND_OPTIONS_DSAKEY,
  SSH_BIND_OPTIONS_RSAKEY,
  SSH_BIND_OPTIONS_BANNER,
  SSH_BIND_OPTIONS_LOG_VERBOSITY,
  SSH_BIND_OPTIONS_LOG_VERBOSITY_STR,
  SSH_BIND_OPTIONS_ECDSAKEY,
  SSH_BIND_OPTIONS_IMPORT_KEY,
  SSH_BIND_OPTIONS_KEY_EXCHANGE,
  SSH_BIND_OPTIONS_CIPHERS_C_S,
  SSH_BIND_OPTIONS_CIPHERS_S_C,
  SSH_BIND_OPTIONS_HMAC_C_S,
  SSH_BIND_OPTIONS_HMAC_S_C,
  SSH_BIND_OPTIONS_CONFIG_DIR,
  SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES,
  SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS,
  SSH_BIND_OPTIONS_PROCESS_CONFIG,
};

typedef struct ssh_bind_struct* ssh_bind;

/* Callback functions */

/**
 * @brief Incoming connection callback. This callback is called when a ssh_bind
 *        has a new incoming connection.
 * @param sshbind Current sshbind session handler
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_bind_incoming_connection_callback) (ssh_bind sshbind,
    void *userdata);

/**
 * @brief These are the callbacks exported by the ssh_bind structure.
 *
 * They are called by the server module when events appear on the network.
 */
struct ssh_bind_callbacks_struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
  size_t size;
  /** A new connection is available. */
  ssh_bind_incoming_connection_callback incoming_connection;
};
typedef struct ssh_bind_callbacks_struct *ssh_bind_callbacks;

/**
 * @brief Creates a new SSH server bind.
 *
 * @return A newly allocated ssh_bind session pointer.
 */
LIBSSH_API ssh_bind ssh_bind_new(void);

LIBSSH_API int ssh_bind_options_set(ssh_bind sshbind,
    enum ssh_bind_options_e type, const void *value);

LIBSSH_API int ssh_bind_options_parse_config(ssh_bind sshbind,
    const char *filename);

/**
 * @brief Start listening to the socket.
 *
 * @param  ssh_bind_o     The ssh server bind to use.
 *
 * @return 0 on success, < 0 on error.
 */
LIBSSH_API int ssh_bind_listen(ssh_bind ssh_bind_o);

/**
 * @brief Set the callback for this bind.
 *
 * @param[in] sshbind   The bind to set the callback on.
 *
 * @param[in] callbacks An already set up ssh_bind_callbacks instance.
 *
 * @param[in] userdata  A pointer to private data to pass to the callbacks.
 *
 * @return              SSH_OK on success, SSH_ERROR if an error occured.
 *
 * @code
 *     struct ssh_callbacks_struct cb = {
 *         .userdata = data,
 *         .auth_function = my_auth_function
 *     };
 *     ssh_callbacks_init(&cb);
 *     ssh_bind_set_callbacks(session, &cb);
 * @endcode
 */
LIBSSH_API int ssh_bind_set_callbacks(ssh_bind sshbind, ssh_bind_callbacks callbacks,
    void *userdata);

/**
 * @brief  Set the session to blocking/nonblocking mode.
 *
 * @param  ssh_bind_o     The ssh server bind to use.
 *
 * @param  blocking     Zero for nonblocking mode.
 */
LIBSSH_API void ssh_bind_set_blocking(ssh_bind ssh_bind_o, int blocking);

/**
 * @brief Recover the file descriptor from the session.
 *
 * @param  ssh_bind_o     The ssh server bind to get the fd from.
 *
 * @return The file descriptor.
 */
LIBSSH_API socket_t ssh_bind_get_fd(ssh_bind ssh_bind_o);

/**
 * @brief Set the file descriptor for a session.
 *
 * @param  ssh_bind_o     The ssh server bind to set the fd.
 *
 * @param  fd           The file descriptssh_bind B
 */
LIBSSH_API void ssh_bind_set_fd(ssh_bind ssh_bind_o, socket_t fd);

/**
 * @brief Allow the file descriptor to accept new sessions.
 *
 * @param  ssh_bind_o     The ssh server bind to use.
 */
LIBSSH_API void ssh_bind_fd_toaccept(ssh_bind ssh_bind_o);

/**
 * @brief Accept an incoming ssh connection and initialize the session.
 *
 * @param  ssh_bind_o     The ssh server bind to accept a connection.
 * @param  session			A preallocated ssh session
 * @see ssh_new
 * @return SSH_OK when a connection is established
 */
LIBSSH_API int ssh_bind_accept(ssh_bind ssh_bind_o, ssh_session session);

/**
 * @brief Accept an incoming ssh connection on the given file descriptor
 *        and initialize the session.
 *
 * @param  ssh_bind_o     The ssh server bind to accept a connection.
 * @param  session        A preallocated ssh session
 * @param  fd             A file descriptor of an already established TCP
 *                          inbound connection
 * @see ssh_new
 * @see ssh_bind_accept
 * @return SSH_OK when a connection is established
 */
LIBSSH_API int ssh_bind_accept_fd(ssh_bind ssh_bind_o, ssh_session session,
        socket_t fd);

LIBSSH_API ssh_gssapi_creds ssh_gssapi_get_creds(ssh_session session);

/**
 * @brief Handles the key exchange and set up encryption
 *
 * @param  session			A connected ssh session
 * @see ssh_bind_accept
 * @return SSH_OK if the key exchange was successful
 */
LIBSSH_API int ssh_handle_key_exchange(ssh_session session);

/**
 * @brief Initialize the set of key exchange, hostkey, ciphers, MACs, and
 *        compression algorithms for the given ssh_session.
 *
 * The selection of algorithms and keys used are determined by the
 * options that are currently set in the given ssh_session structure.
 * May only be called before the initial key exchange has begun.
 *
 * @param session  The session structure to initialize.
 *
 * @see ssh_handle_key_exchange
 * @see ssh_options_set
 *
 * @return SSH_OK if initialization succeeds.
 */

LIBSSH_API int ssh_server_init_kex(ssh_session session);

/**
 * @brief Free a ssh servers bind.
 *
 * @param  ssh_bind_o     The ssh server bind to free.
 */
LIBSSH_API void ssh_bind_free(ssh_bind ssh_bind_o);

/**
 * @brief Set the acceptable authentication methods to be sent to the client.
 *
 *
 * @param[in]  session  The server session
 *
 * @param[in]  auth_methods The authentication methods we will support, which
 *                          can be bitwise-or'd.
 *
 *                          Supported methods are:
 *
 *                          SSH_AUTH_METHOD_PASSWORD
 *                          SSH_AUTH_METHOD_PUBLICKEY
 *                          SSH_AUTH_METHOD_HOSTBASED
 *                          SSH_AUTH_METHOD_INTERACTIVE
 *                          SSH_AUTH_METHOD_GSSAPI_MIC
 */
LIBSSH_API void ssh_set_auth_methods(ssh_session session, int auth_methods);

/**********************************************************
 * SERVER MESSAGING
 **********************************************************/

/**
 * @brief Reply with a standard reject message.
 *
 * Use this function if you don't know what to respond or if you want to reject
 * a request.
 *
 * @param[in] msg       The message to use for the reply.
 *
 * @return              0 on success, -1 on error.
 *
 * @see ssh_message_get()
 */
LIBSSH_API int ssh_message_reply_default(ssh_message msg);

/**
 * @brief Get the name of the authenticated user.
 *
 * @param[in] msg       The message to get the username from.
 *
 * @return              The username or NULL if an error occured.
 *
 * @see ssh_message_get()
 * @see ssh_message_type()
 */
LIBSSH_API const char *ssh_message_auth_user(ssh_message msg);

/**
 * @brief Get the password of the authenticated user.
 *
 * @param[in] msg       The message to get the password from.
 *
 * @return              The username or NULL if an error occured.
 *
 * @see ssh_message_get()
 * @see ssh_message_type()
 */
LIBSSH_API const char *ssh_message_auth_password(ssh_message msg);

/**
 * @brief Get the publickey of the authenticated user.
 *
 * If you need the key for later user you should duplicate it.
 *
 * @param[in] msg       The message to get the public key from.
 *
 * @return              The public key or NULL.
 *
 * @see ssh_key_dup()
 * @see ssh_key_cmp()
 * @see ssh_message_get()
 * @see ssh_message_type()
 */
LIBSSH_API ssh_key ssh_message_auth_pubkey(ssh_message msg);

LIBSSH_API int ssh_message_auth_kbdint_is_response(ssh_message msg);
LIBSSH_API enum ssh_publickey_state_e ssh_message_auth_publickey_state(ssh_message msg);
LIBSSH_API int ssh_message_auth_reply_success(ssh_message msg,int partial);
LIBSSH_API int ssh_message_auth_reply_pk_ok(ssh_message msg, ssh_string algo, ssh_string pubkey);
LIBSSH_API int ssh_message_auth_reply_pk_ok_simple(ssh_message msg);

LIBSSH_API int ssh_message_auth_set_methods(ssh_message msg, int methods);

LIBSSH_API int ssh_message_auth_interactive_request(ssh_message msg,
                    const char *name, const char *instruction,
                    unsigned int num_prompts, const char **prompts, char *echo);

LIBSSH_API int ssh_message_service_reply_success(ssh_message msg);
LIBSSH_API const char *ssh_message_service_service(ssh_message msg);

LIBSSH_API int ssh_message_global_request_reply_success(ssh_message msg,
                                                        uint16_t bound_port);

LIBSSH_API void ssh_set_message_callback(ssh_session session,
    int(*ssh_bind_message_callback)(ssh_session session, ssh_message msg, void *data),
    void *data);
LIBSSH_API int ssh_execute_message_callbacks(ssh_session session);

LIBSSH_API const char *ssh_message_channel_request_open_originator(ssh_message msg);
LIBSSH_API int ssh_message_channel_request_open_originator_port(ssh_message msg);
LIBSSH_API const char *ssh_message_channel_request_open_destination(ssh_message msg);
LIBSSH_API int ssh_message_channel_request_open_destination_port(ssh_message msg);

LIBSSH_API ssh_channel ssh_message_channel_request_channel(ssh_message msg);

LIBSSH_API const char *ssh_message_channel_request_pty_term(ssh_message msg);
LIBSSH_API int ssh_message_channel_request_pty_width(ssh_message msg);
LIBSSH_API int ssh_message_channel_request_pty_height(ssh_message msg);
LIBSSH_API int ssh_message_channel_request_pty_pxwidth(ssh_message msg);
LIBSSH_API int ssh_message_channel_request_pty_pxheight(ssh_message msg);

LIBSSH_API const char *ssh_message_channel_request_env_name(ssh_message msg);
LIBSSH_API const char *ssh_message_channel_request_env_value(ssh_message msg);

LIBSSH_API const char *ssh_message_channel_request_command(ssh_message msg);

LIBSSH_API const char *ssh_message_channel_request_subsystem(ssh_message msg);

LIBSSH_API int ssh_message_channel_request_x11_single_connection(ssh_message msg);
LIBSSH_API const char *ssh_message_channel_request_x11_auth_protocol(ssh_message msg);
LIBSSH_API const char *ssh_message_channel_request_x11_auth_cookie(ssh_message msg);
LIBSSH_API int ssh_message_channel_request_x11_screen_number(ssh_message msg);

LIBSSH_API const char *ssh_message_global_request_address(ssh_message msg);
LIBSSH_API int ssh_message_global_request_port(ssh_message msg);

LIBSSH_API int ssh_channel_open_reverse_forward(ssh_channel channel, const char *remotehost,
    int remoteport, const char *sourcehost, int localport);
LIBSSH_API int ssh_channel_open_x11(ssh_channel channel, 
                                        const char *orig_addr, int orig_port);

LIBSSH_API int ssh_channel_request_send_exit_status(ssh_channel channel,
                                                int exit_status);
LIBSSH_API int ssh_channel_request_send_exit_signal(ssh_channel channel,
                                                const char *signum,
                                                int core,
                                                const char *errmsg,
                                                const char *lang);

LIBSSH_API int ssh_send_keepalive(ssh_session session);

/* deprecated functions */
SSH_DEPRECATED LIBSSH_API int ssh_accept(ssh_session session);
SSH_DEPRECATED LIBSSH_API int channel_write_stderr(ssh_channel channel,
        const void *data, uint32_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SERVER_H */

/** @} */
