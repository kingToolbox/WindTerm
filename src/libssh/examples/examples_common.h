/*
Copyright 2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/
#ifndef EXAMPLES_COMMON_H_
#define EXAMPLES_COMMON_H_

#include <libssh/libssh.h>

/** Zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

int authenticate_console(ssh_session session);
int authenticate_kbdint(ssh_session session, const char *password);
int verify_knownhost(ssh_session session);
ssh_session connect_ssh(const char *hostname, const char *user, int verbosity);

#endif /* EXAMPLES_COMMON_H_ */
