/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
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

#ifndef MESSAGES_H_
#define MESSAGES_H_

#include "config.h"

struct ssh_auth_request {
    char *username;
    int method;
    char *password;
    struct ssh_key_struct *pubkey;
    enum ssh_publickey_state_e signature_state;
    char kbdint_response;
};

struct ssh_channel_request_open {
    int type;
    uint32_t sender;
    uint32_t window;
    uint32_t packet_size;
    char *originator;
    uint16_t originator_port;
    char *destination;
    uint16_t destination_port;
};

struct ssh_service_request {
    char *service;
};

struct ssh_global_request {
    int type;
    uint8_t want_reply;
    char *bind_address;
    uint16_t bind_port;
};

struct ssh_channel_request {
    int type;
    ssh_channel channel;
    uint8_t want_reply;
    /* pty-req type specifics */
    char *TERM;
    uint32_t width;
    uint32_t height;
    uint32_t pxwidth;
    uint32_t pxheight;
    ssh_string modes;

    /* env type request */
    char *var_name;
    char *var_value;
    /* exec type request */
    char *command;
    /* subsystem */
    char *subsystem;

    /* X11 */
    uint8_t x11_single_connection;
    char *x11_auth_protocol;
    char *x11_auth_cookie;
    uint32_t x11_screen_number;
};

struct ssh_message_struct {
    ssh_session session;
    int type;
    struct ssh_auth_request auth_request;
    struct ssh_channel_request_open channel_request_open;
    struct ssh_channel_request channel_request;
    struct ssh_service_request service_request;
    struct ssh_global_request global_request;
};

SSH_PACKET_CALLBACK(ssh_packet_channel_open);
SSH_PACKET_CALLBACK(ssh_packet_global_request);

#ifdef WITH_SERVER
SSH_PACKET_CALLBACK(ssh_packet_service_request);
SSH_PACKET_CALLBACK(ssh_packet_userauth_request);
#endif /* WITH_SERVER */

int ssh_message_handle_channel_request(ssh_session session, ssh_channel channel, ssh_buffer packet,
    const char *request, uint8_t want_reply);
ssh_message ssh_message_pop_head(ssh_session session);

#endif /* MESSAGES_H_ */
