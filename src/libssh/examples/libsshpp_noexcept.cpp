/*
Copyright 2010 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
*/

/* This file demonstrates the use of the C++ wrapper to libssh
 * specifically, without C++ exceptions
 */

#include <iostream>
#define SSH_NO_CPP_EXCEPTIONS
#include <libssh/libsshpp.hpp>

int main(int argc, const char **argv){
	ssh::Session session,s2;
	int err;
	if(argc>1)
		err=session.setOption(SSH_OPTIONS_HOST,argv[1]);
	else
		err=session.setOption(SSH_OPTIONS_HOST,"localhost");
	if(err==SSH_ERROR)
		goto error;
	err=session.connect();
	if(err==SSH_ERROR)
		goto error;
	err=session.userauthPublickeyAuto();
	if(err==SSH_ERROR)
		goto error;

	return 0;
	error:
	std::cout << "Error during connection : ";
	std::cout << session.getError() << std::endl;
	return 1;
}
