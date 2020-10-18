/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 Aris Adamantiadis <aris@0xbadc0de.be>
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

/* callback.h
 * This file includes the public declarations for the libssh callback mechanism
 */

#ifndef _SSH_CALLBACK_H
#define _SSH_CALLBACK_H

#include <libssh/libssh.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup libssh_callbacks The libssh callbacks
 * @ingroup libssh
 *
 * Callback which can be replaced in libssh.
 *
 * @{
 */

/** @internal
 * @brief callback to process simple codes
 * @param code value to transmit
 * @param user Userdata to pass in callback
 */
typedef void (*ssh_callback_int) (int code, void *user);

/** @internal
 * @brief callback for data received messages.
 * @param data data retrieved from the socket or stream
 * @param len number of bytes available from this stream
 * @param user user-supplied pointer sent along with all callback messages
 * @returns number of bytes processed by the callee. The remaining bytes will
 * be sent in the next callback message, when more data is available.
 */
typedef int (*ssh_callback_data) (const void *data, size_t len, void *user);

typedef void (*ssh_callback_int_int) (int code, int errno_code, void *user);

typedef int (*ssh_message_callback) (ssh_session, ssh_message message, void *user);
typedef int (*ssh_channel_callback_int) (ssh_channel channel, int code, void *user);
typedef int (*ssh_channel_callback_data) (ssh_channel channel, int code, void *data, size_t len, void *user);

/**
 * @brief SSH log callback. All logging messages will go through this callback
 * @param session Current session handler
 * @param priority Priority of the log, the smaller being the more important
 * @param message the actual message
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_log_callback) (ssh_session session, int priority,
    const char *message, void *userdata);

/**
 * @brief SSH log callback.
 *
 * All logging messages will go through this callback.
 *
 * @param priority  Priority of the log, the smaller being the more important.
 *
 * @param function  The function name calling the the logging fucntions.
 *
 * @param message   The actual message
 *
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_logging_callback) (int priority,
                                      const char *function,
                                      const char *buffer,
                                      void *userdata);

/**
 * @brief SSH Connection status callback.
 * @param session Current session handler
 * @param status Percentage of connection status, going from 0.0 to 1.0
 * once connection is done.
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_status_callback) (ssh_session session, float status,
		void *userdata);

/**
 * @brief SSH global request callback. All global request will go through this
 * callback.
 * @param session Current session handler
 * @param message the actual message
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_global_request_callback) (ssh_session session,
                                        ssh_message message, void *userdata);

/**
 * @brief Handles an SSH new channel open X11 request. This happens when the server
 * sends back an X11 connection attempt. This is a client-side API
 * @param session current session handler
 * @param userdata Userdata to be passed to the callback function.
 * @returns a valid ssh_channel handle if the request is to be allowed
 * @returns NULL if the request should not be allowed
 * @warning The channel pointer returned by this callback must be closed by the application.
 */
typedef ssh_channel (*ssh_channel_open_request_x11_callback) (ssh_session session,
      const char * originator_address, int originator_port, void *userdata);

/**
 * @brief Handles an SSH new channel open "auth-agent" request. This happens when the server
 * sends back an "auth-agent" connection attempt. This is a client-side API
 * @param session current session handler
 * @param userdata Userdata to be passed to the callback function.
 * @returns a valid ssh_channel handle if the request is to be allowed
 * @returns NULL if the request should not be allowed
 * @warning The channel pointer returned by this callback must be closed by the application.
 */
typedef ssh_channel (*ssh_channel_open_request_auth_agent_callback) (ssh_session session,
      void *userdata);

/**
 * The structure to replace libssh functions with appropriate callbacks.
 */
struct ssh_callbacks_struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
  size_t size;
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
  /**
   * This functions will be called if e.g. a keyphrase is needed.
   */
  ssh_auth_callback auth_function;
  /**
   * This function will be called each time a loggable event happens.
   */
  ssh_log_callback log_function;
  /**
   * This function gets called during connection time to indicate the
   * percentage of connection steps completed.
   */
  void (*connect_status_function)(void *userdata, float status);
  /**
   * This function will be called each time a global request is received.
   */
  ssh_global_request_callback global_request_function;
  /** This function will be called when an incoming X11 request is received.
   */
  ssh_channel_open_request_x11_callback channel_open_request_x11_function;
  /** This function will be called when an incoming "auth-agent" request is received.
   */
  ssh_channel_open_request_auth_agent_callback channel_open_request_auth_agent_function;
};
typedef struct ssh_callbacks_struct *ssh_callbacks;

/** These are callbacks used specifically in SSH servers.
 */

/**
 * @brief SSH authentication callback.
 * @param session Current session handler
 * @param user User that wants to authenticate
 * @param password Password used for authentication
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 */
typedef int (*ssh_auth_password_callback) (ssh_session session, const char *user, const char *password,
		void *userdata);

/**
 * @brief SSH authentication callback. Tries to authenticates user with the "none" method
 * which is anonymous or passwordless.
 * @param session Current session handler
 * @param user User that wants to authenticate
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 */
typedef int (*ssh_auth_none_callback) (ssh_session session, const char *user, void *userdata);

/**
 * @brief SSH authentication callback. Tries to authenticates user with the "gssapi-with-mic" method
 * @param session Current session handler
 * @param user Username of the user (can be spoofed)
 * @param principal Authenticated principal of the user, including realm.
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 * @warning Implementations should verify that parameter user matches in some way the principal.
 * user and principal can be different. Only the latter is guaranteed to be safe.
 */
typedef int (*ssh_auth_gssapi_mic_callback) (ssh_session session, const char *user, const char *principal,
		void *userdata);

/**
 * @brief SSH authentication callback.
 * @param session Current session handler
 * @param user User that wants to authenticate
 * @param pubkey public key used for authentication
 * @param signature_state SSH_PUBLICKEY_STATE_NONE if the key is not signed (simple public key probe),
 * 							SSH_PUBLICKEY_STATE_VALID if the signature is valid. Others values should be
 * 							replied with a SSH_AUTH_DENIED.
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 */
typedef int (*ssh_auth_pubkey_callback) (ssh_session session, const char *user, struct ssh_key_struct *pubkey,
		char signature_state, void *userdata);


/**
 * @brief Handles an SSH service request
 * @param session current session handler
 * @param service name of the service (e.g. "ssh-userauth") requested
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the request is to be allowed
 * @returns -1 if the request should not be allowed
 */

typedef int (*ssh_service_request_callback) (ssh_session session, const char *service, void *userdata);

/**
 * @brief Handles an SSH new channel open session request
 * @param session current session handler
 * @param userdata Userdata to be passed to the callback function.
 * @returns a valid ssh_channel handle if the request is to be allowed
 * @returns NULL if the request should not be allowed
 * @warning The channel pointer returned by this callback must be closed by the application.
 */
typedef ssh_channel (*ssh_channel_open_request_session_callback) (ssh_session session, void *userdata);

/*
 * @brief handle the beginning of a GSSAPI authentication, server side.
 * @param session current session handler
 * @param user the username of the client
 * @param n_oid number of available oids
 * @param oids OIDs provided by the client
 * @returns an ssh_string containing the chosen OID, that's supported by both
 * client and server.
 * @warning It is not necessary to fill this callback in if libssh is linked
 * with libgssapi.
 */
typedef ssh_string (*ssh_gssapi_select_oid_callback) (ssh_session session, const char *user,
		int n_oid, ssh_string *oids, void *userdata);

/*
 * @brief handle the negociation of a security context, server side.
 * @param session current session handler
 * @param[in] input_token input token provided by client
 * @param[out] output_token output of the gssapi accept_sec_context method,
 * 				NULL after completion.
 * @returns SSH_OK if the token was generated correctly or accept_sec_context
 * returned GSS_S_COMPLETE
 * @returns SSH_ERROR in case of error
 * @warning It is not necessary to fill this callback in if libssh is linked
 * with libgssapi.
 */
typedef int (*ssh_gssapi_accept_sec_ctx_callback) (ssh_session session,
		ssh_string input_token, ssh_string *output_token, void *userdata);

/*
 * @brief Verify and authenticates a MIC, server side.
 * @param session current session handler
 * @param[in] mic input mic to be verified provided by client
 * @param[in] mic_buffer buffer of data to be signed.
 * @param[in] mic_buffer_size size of mic_buffer
 * @returns SSH_OK if the MIC was authenticated correctly
 * @returns SSH_ERROR in case of error
 * @warning It is not necessary to fill this callback in if libssh is linked
 * with libgssapi.
 */
typedef int (*ssh_gssapi_verify_mic_callback) (ssh_session session,
		ssh_string mic, void *mic_buffer, size_t mic_buffer_size, void *userdata);


/**
 * This structure can be used to implement a libssh server, with appropriate callbacks.
 */

struct ssh_server_callbacks_struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
  size_t size;
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
  /** This function gets called when a client tries to authenticate through
   * password method.
   */
  ssh_auth_password_callback auth_password_function;

  /** This function gets called when a client tries to authenticate through
   * none method.
   */
  ssh_auth_none_callback auth_none_function;

  /** This function gets called when a client tries to authenticate through
   * gssapi-mic method.
   */
  ssh_auth_gssapi_mic_callback auth_gssapi_mic_function;

  /** this function gets called when a client tries to authenticate or offer
   * a public key.
   */
  ssh_auth_pubkey_callback auth_pubkey_function;

  /** This functions gets called when a service request is issued by the
   * client
   */
  ssh_service_request_callback service_request_function;
  /** This functions gets called when a new channel request is issued by
   * the client
   */
  ssh_channel_open_request_session_callback channel_open_request_session_function;
  /** This function will be called when a new gssapi authentication is attempted.
   */
  ssh_gssapi_select_oid_callback gssapi_select_oid_function;
  /** This function will be called when a gssapi token comes in.
   */
  ssh_gssapi_accept_sec_ctx_callback gssapi_accept_sec_ctx_function;
  /* This function will be called when a MIC needs to be verified.
   */
  ssh_gssapi_verify_mic_callback gssapi_verify_mic_function;
};
typedef struct ssh_server_callbacks_struct *ssh_server_callbacks;

/**
 * @brief Set the session server callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for user authentication, new channels and requests.
 *
 * @code
 * struct ssh_server_callbacks_struct cb = {
 *   .userdata = data,
 *   .auth_password_function = my_auth_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_server_callbacks(session, &cb);
 * @endcode
 *
 * @param  session      The session to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
LIBSSH_API int ssh_set_server_callbacks(ssh_session session, ssh_server_callbacks cb);

/**
 * These are the callbacks exported by the socket structure
 * They are called by the socket module when a socket event appears
 */
struct ssh_socket_callbacks_struct {
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
	/**
	 * This function will be called each time data appears on socket. The data
	 * not consumed will appear on the next data event.
	 */
  ssh_callback_data data;
  /** This function will be called each time a controlflow state changes, i.e.
   * the socket is available for reading or writing.
   */
  ssh_callback_int controlflow;
  /** This function will be called each time an exception appears on socket. An
   * exception can be a socket problem (timeout, ...) or an end-of-file.
   */
  ssh_callback_int_int exception;
  /** This function is called when the ssh_socket_connect was used on the socket
   * on nonblocking state, and the connection successed.
   */
  ssh_callback_int_int connected;
};
typedef struct ssh_socket_callbacks_struct *ssh_socket_callbacks;

#define SSH_SOCKET_FLOW_WRITEWILLBLOCK 1
#define SSH_SOCKET_FLOW_WRITEWONTBLOCK 2

#define SSH_SOCKET_EXCEPTION_EOF 	     1
#define SSH_SOCKET_EXCEPTION_ERROR     2

#define SSH_SOCKET_CONNECTED_OK 			1
#define SSH_SOCKET_CONNECTED_ERROR 		2
#define SSH_SOCKET_CONNECTED_TIMEOUT 	3

/**
 * @brief Initializes an ssh_callbacks_struct
 * A call to this macro is mandatory when you have set a new
 * ssh_callback_struct structure. Its goal is to maintain the binary
 * compatibility with future versions of libssh as the structure
 * evolves with time.
 */
#define ssh_callbacks_init(p) do {\
	(p)->size=sizeof(*(p)); \
} while(0);

/**
 * @internal
 * @brief tests if a callback can be called without crash
 *  verifies that the struct size if big enough
 *  verifies that the callback pointer exists
 * @param p callback pointer
 * @param c callback name
 * @returns nonzero if callback can be called
 */
#define ssh_callbacks_exists(p,c) (\
  (p != NULL) && ( (char *)&((p)-> c) < (char *)(p) + (p)->size ) && \
  ((p)-> c != NULL) \
  )

/**
 * @internal
 *
 * @brief Iterate through a list of callback structures
 *
 * This tests for their validity and executes them. The userdata argument is
 * automatically passed through.
 *
 * @param list     list of callbacks
 *
 * @param cbtype   type of the callback
 *
 * @param c        callback name
 *
 * @param va_args parameters to be passed
 */
#define ssh_callbacks_execute_list(list, cbtype, c, ...)      \
    do {                                                      \
        struct ssh_iterator *i = ssh_list_get_iterator(list); \
        cbtype cb;                                            \
        while (i != NULL){                                    \
            cb = ssh_iterator_value(cbtype, i);               \
            if (ssh_callbacks_exists(cb, c))                  \
                cb-> c (__VA_ARGS__, cb->userdata);           \
            i = i->next;                                      \
        }                                                     \
    } while(0)

/**
 * @internal
 *
 * @brief iterate through a list of callback structures.
 *
 * This tests for their validity and give control back to the calling code to
 * execute them. Caller can decide to break the loop or continue executing the
 * callbacks with different parameters
 *
 * @code
 * ssh_callbacks_iterate(channel->callbacks, ssh_channel_callbacks,
 *                     channel_eof_function){
 *     rc = ssh_callbacks_iterate_exec(session, channel);
 *     if (rc != SSH_OK){
 *         break;
 *     }
 * }
 * ssh_callbacks_iterate_end();
 * @endcode
 */
#define ssh_callbacks_iterate(_cb_list, _cb_type, _cb_name)           \
    do {                                                              \
        struct ssh_iterator *_cb_i = ssh_list_get_iterator(_cb_list); \
        _cb_type _cb;                                                 \
        for (; _cb_i != NULL; _cb_i = _cb_i->next) {                  \
            _cb = ssh_iterator_value(_cb_type, _cb_i);                \
            if (ssh_callbacks_exists(_cb, _cb_name))

#define ssh_callbacks_iterate_exec(_cb_name, ...) \
                _cb->_cb_name(__VA_ARGS__, _cb->userdata)

#define ssh_callbacks_iterate_end() \
        }                           \
    } while(0)

/** @brief Prototype for a packet callback, to be called when a new packet arrives
 * @param session The current session of the packet
 * @param type packet type (see ssh2.h)
 * @param packet buffer containing the packet, excluding size, type and padding fields
 * @param user user argument to the callback
 * and are called each time a packet shows up
 * @returns SSH_PACKET_USED Packet was parsed and used
 * @returns SSH_PACKET_NOT_USED Packet was not used or understood, processing must continue
 */
typedef int (*ssh_packet_callback) (ssh_session session, uint8_t type, ssh_buffer packet, void *user);

/** return values for a ssh_packet_callback */
/** Packet was used and should not be parsed by another callback */
#define SSH_PACKET_USED 1
/** Packet was not used and should be passed to any other callback
 * available */
#define SSH_PACKET_NOT_USED 2


/** @brief This macro declares a packet callback handler
 * @code
 * SSH_PACKET_CALLBACK(mycallback){
 * ...
 * }
 * @endcode
 */
#define SSH_PACKET_CALLBACK(name) \
	int name (ssh_session session, uint8_t type, ssh_buffer packet, void *user)

struct ssh_packet_callbacks_struct {
	/** Index of the first packet type being handled */
	uint8_t start;
	/** Number of packets being handled by this callback struct */
	uint8_t n_callbacks;
	/** A pointer to n_callbacks packet callbacks */
	ssh_packet_callback *callbacks;
  /**
   * User-provided data. User is free to set anything he wants here
   */
	void *user;
};

typedef struct ssh_packet_callbacks_struct *ssh_packet_callbacks;

/**
 * @brief Set the session callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for auth, logging and status.
 *
 * @code
 * struct ssh_callbacks_struct cb = {
 *   .userdata = data,
 *   .auth_function = my_auth_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_callbacks(session, &cb);
 * @endcode
 *
 * @param  session      The session to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
LIBSSH_API int ssh_set_callbacks(ssh_session session, ssh_callbacks cb);

/**
 * @brief SSH channel data callback. Called when data is available on a channel
 * @param session Current session handler
 * @param channel the actual channel
 * @param data the data that has been read on the channel
 * @param len the length of the data
 * @param is_stderr is 0 for stdout or 1 for stderr
 * @param userdata Userdata to be passed to the callback function.
 * @returns number of bytes processed by the callee. The remaining bytes will
 * be sent in the next callback message, when more data is available.
 */
typedef int (*ssh_channel_data_callback) (ssh_session session,
                                           ssh_channel channel,
                                           void *data,
                                           uint32_t len,
                                           int is_stderr,
                                           void *userdata);

/**
 * @brief SSH channel eof callback. Called when a channel receives EOF
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_eof_callback) (ssh_session session,
                                           ssh_channel channel,
                                           void *userdata);

/**
 * @brief SSH channel close callback. Called when a channel is closed by remote peer
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_close_callback) (ssh_session session,
                                            ssh_channel channel,
                                            void *userdata);

/**
 * @brief SSH channel signal callback. Called when a channel has received a signal
 * @param session Current session handler
 * @param channel the actual channel
 * @param signal the signal name (without the SIG prefix)
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_signal_callback) (ssh_session session,
                                            ssh_channel channel,
                                            const char *signal,
                                            void *userdata);

/**
 * @brief SSH channel exit status callback. Called when a channel has received an exit status
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_exit_status_callback) (ssh_session session,
                                            ssh_channel channel,
                                            int exit_status,
                                            void *userdata);

/**
 * @brief SSH channel exit signal callback. Called when a channel has received an exit signal
 * @param session Current session handler
 * @param channel the actual channel
 * @param signal the signal name (without the SIG prefix)
 * @param core a boolean telling wether a core has been dumped or not
 * @param errmsg the description of the exception
 * @param lang the language of the description (format: RFC 3066)
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_exit_signal_callback) (ssh_session session,
                                            ssh_channel channel,
                                            const char *signal,
                                            int core,
                                            const char *errmsg,
                                            const char *lang,
                                            void *userdata);

/**
 * @brief SSH channel PTY request from a client.
 * @param channel the channel
 * @param term The type of terminal emulation
 * @param width width of the terminal, in characters
 * @param height height of the terminal, in characters
 * @param pxwidth width of the terminal, in pixels
 * @param pxheight height of the terminal, in pixels
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the pty request is accepted
 * @returns -1 if the request is denied
 */
typedef int (*ssh_channel_pty_request_callback) (ssh_session session,
                                            ssh_channel channel,
                                            const char *term,
                                            int width, int height,
                                            int pxwidth, int pwheight,
                                            void *userdata);

/**
 * @brief SSH channel Shell request from a client.
 * @param channel the channel
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the shell request is accepted
 * @returns 1 if the request is denied
 */
typedef int (*ssh_channel_shell_request_callback) (ssh_session session,
                                            ssh_channel channel,
                                            void *userdata);
/**
 * @brief SSH auth-agent-request from the client. This request is
 * sent by a client when agent forwarding is available.
 * Server is free to ignore this callback, no answer is expected.
 * @param channel the channel
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_auth_agent_req_callback) (ssh_session session,
                                            ssh_channel channel,
                                            void *userdata);

/**
 * @brief SSH X11 request from the client. This request is
 * sent by a client when X11 forwarding is requested(and available).
 * Server is free to ignore this callback, no answer is expected.
 * @param channel the channel
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_x11_req_callback) (ssh_session session,
                                            ssh_channel channel,
                                            int single_connection,
                                            const char *auth_protocol,
                                            const char *auth_cookie,
                                            uint32_t screen_number,
                                            void *userdata);
/**
 * @brief SSH channel PTY windows change (terminal size) from a client.
 * @param channel the channel
 * @param width width of the terminal, in characters
 * @param height height of the terminal, in characters
 * @param pxwidth width of the terminal, in pixels
 * @param pxheight height of the terminal, in pixels
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the pty request is accepted
 * @returns -1 if the request is denied
 */
typedef int (*ssh_channel_pty_window_change_callback) (ssh_session session,
                                            ssh_channel channel,
                                            int width, int height,
                                            int pxwidth, int pwheight,
                                            void *userdata);

/**
 * @brief SSH channel Exec request from a client.
 * @param channel the channel
 * @param command the shell command to be executed
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the exec request is accepted
 * @returns 1 if the request is denied
 */
typedef int (*ssh_channel_exec_request_callback) (ssh_session session,
                                            ssh_channel channel,
                                            const char *command,
                                            void *userdata);

/**
 * @brief SSH channel environment request from a client.
 * @param channel the channel
 * @param env_name name of the environment value to be set
 * @param env_value value of the environment value to be set
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the env request is accepted
 * @returns 1 if the request is denied
 * @warning some environment variables can be dangerous if changed (e.g.
 * 			LD_PRELOAD) and should not be fulfilled.
 */
typedef int (*ssh_channel_env_request_callback) (ssh_session session,
                                            ssh_channel channel,
                                            const char *env_name,
                                            const char *env_value,
                                            void *userdata);
/**
 * @brief SSH channel subsystem request from a client.
 * @param channel the channel
 * @param subsystem the subsystem required
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the subsystem request is accepted
 * @returns 1 if the request is denied
 */
typedef int (*ssh_channel_subsystem_request_callback) (ssh_session session,
                                            ssh_channel channel,
                                            const char *subsystem,
                                            void *userdata);

/**
 * @brief SSH channel write will not block (flow control).
 *
 * @param channel the channel
 *
 * @param[in] bytes size of the remote window in bytes. Writing as much data
 *            will not block.
 *
 * @param[in] userdata Userdata to be passed to the callback function.
 *
 * @returns 0 default return value (other return codes may be added in future).
 */
typedef int (*ssh_channel_write_wontblock_callback) (ssh_session session,
                                                     ssh_channel channel,
                                                     size_t bytes,
                                                     void *userdata);

struct ssh_channel_callbacks_struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
  size_t size;
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
  /**
   * This functions will be called when there is data available.
   */
  ssh_channel_data_callback channel_data_function;
  /**
   * This functions will be called when the channel has received an EOF.
   */
  ssh_channel_eof_callback channel_eof_function;
  /**
   * This functions will be called when the channel has been closed by remote
   */
  ssh_channel_close_callback channel_close_function;
  /**
   * This functions will be called when a signal has been received
   */
  ssh_channel_signal_callback channel_signal_function;
  /**
   * This functions will be called when an exit status has been received
   */
  ssh_channel_exit_status_callback channel_exit_status_function;
  /**
   * This functions will be called when an exit signal has been received
   */
  ssh_channel_exit_signal_callback channel_exit_signal_function;
  /**
   * This function will be called when a client requests a PTY
   */
  ssh_channel_pty_request_callback channel_pty_request_function;
  /**
   * This function will be called when a client requests a shell
   */
  ssh_channel_shell_request_callback channel_shell_request_function;
  /** This function will be called when a client requests agent
   * authentication forwarding.
   */
  ssh_channel_auth_agent_req_callback channel_auth_agent_req_function;
  /** This function will be called when a client requests X11
   * forwarding.
   */
  ssh_channel_x11_req_callback channel_x11_req_function;
  /** This function will be called when a client requests a
   * window change.
   */
  ssh_channel_pty_window_change_callback channel_pty_window_change_function;
  /** This function will be called when a client requests a
   * command execution.
   */
  ssh_channel_exec_request_callback channel_exec_request_function;
  /** This function will be called when a client requests an environment
   * variable to be set.
   */
  ssh_channel_env_request_callback channel_env_request_function;
  /** This function will be called when a client requests a subsystem
   * (like sftp).
   */
  ssh_channel_subsystem_request_callback channel_subsystem_request_function;
  /** This function will be called when the channel write is guaranteed
   * not to block.
   */
  ssh_channel_write_wontblock_callback channel_write_wontblock_function;
};

typedef struct ssh_channel_callbacks_struct *ssh_channel_callbacks;

/**
 * @brief Set the channel callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for channel data and exceptions
 *
 * @code
 * struct ssh_channel_callbacks_struct cb = {
 *   .userdata = data,
 *   .channel_data_function = my_channel_data_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_channel_callbacks(channel, &cb);
 * @endcode
 *
 * @param  channel      The channel to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 * @warning this function will not replace existing callbacks but set the
 *          new one atop of them.
 */
LIBSSH_API int ssh_set_channel_callbacks(ssh_channel channel,
                                         ssh_channel_callbacks cb);

/**
 * @brief Add channel callback functions
 *
 * This function will add channel callback functions to the channel callback
 * list.
 * Callbacks missing from a callback structure will be probed in the next
 * on the list.
 *
 * @param  channel      The channel to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_set_channel_callbacks
 */
LIBSSH_API int ssh_add_channel_callbacks(ssh_channel channel,
                                         ssh_channel_callbacks cb);

/**
 * @brief Remove a channel callback.
 *
 * The channel has been added with ssh_add_channel_callbacks or
 * ssh_set_channel_callbacks in this case.
 *
 * @param channel  The channel to remove the callback structure from.
 *
 * @param cb       The callback structure to remove
 *
 * @returns SSH_OK on success, SSH_ERROR on error.
 */
LIBSSH_API int ssh_remove_channel_callbacks(ssh_channel channel,
                                            ssh_channel_callbacks cb);

/** @} */

/** @group libssh_threads
 * @{
 */

typedef int (*ssh_thread_callback) (void **lock);

typedef unsigned long (*ssh_thread_id_callback) (void);
struct ssh_threads_callbacks_struct {
	const char *type;
  ssh_thread_callback mutex_init;
  ssh_thread_callback mutex_destroy;
  ssh_thread_callback mutex_lock;
  ssh_thread_callback mutex_unlock;
  ssh_thread_id_callback thread_id;
};

/**
 * @brief Set the thread callbacks structure.
 *
 * This is necessary if your program is using libssh in a multithreaded fashion.
 * This function must be called first, outside of any threading context (in your
 * main() function for instance), before you call ssh_init().
 *
 * @param[in] cb   A pointer to a ssh_threads_callbacks_struct structure, which
 *                 contains the different callbacks to be set.
 *
 * @returns        Always returns SSH_OK.
 *
 * @see ssh_threads_callbacks_struct
 * @see SSH_THREADS_PTHREAD
 * @bug libgcrypt 1.6 and bigger backend does not support custom callback.
 *      Using anything else than pthreads here will fail.
 */
LIBSSH_API int ssh_threads_set_callbacks(struct ssh_threads_callbacks_struct
    *cb);

/**
 * @brief Returns a pointer to the appropriate callbacks structure for the
 * environment, to be used with ssh_threads_set_callbacks.
 *
 * @returns A pointer to a ssh_threads_callbacks_struct to be used with
 * ssh_threads_set_callbacks.
 *
 * @see ssh_threads_set_callbacks
 */
LIBSSH_API struct ssh_threads_callbacks_struct *ssh_threads_get_default(void);

/**
 * @brief Returns a pointer on the pthread threads callbacks, to be used with
 * ssh_threads_set_callbacks.
 *
 * @see ssh_threads_set_callbacks
 */
LIBSSH_API struct ssh_threads_callbacks_struct *ssh_threads_get_pthread(void);

/**
 * @brief Get the noop threads callbacks structure
 *
 * This can be used with ssh_threads_set_callbacks. These callbacks do nothing
 * and are being used by default.
 *
 * @return Always returns a valid pointer to the noop callbacks structure.
 *
 * @see ssh_threads_set_callbacks
 */
LIBSSH_API struct ssh_threads_callbacks_struct *ssh_threads_get_noop(void);

/**
 * @brief Set the logging callback function.
 *
 * @param[in]  cb  The callback to set.
 *
 * @return         0 on success, < 0 on errror.
 */
LIBSSH_API int ssh_set_log_callback(ssh_logging_callback cb);

/**
 * @brief Get the pointer to the logging callback function.
 *
 * @return The pointer the the callback or NULL if none set.
 */
LIBSSH_API ssh_logging_callback ssh_get_log_callback(void);

/** @} */
#ifdef __cplusplus
}
#endif

#endif /*_SSH_CALLBACK_H */

/* @} */
