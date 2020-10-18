/*
Copyright 2010 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
*/

/* This file demonstrates the use of the C++ wrapper to libssh */

#include <iostream>
#include <string>
#include <libssh/libsshpp.hpp>

int main(int argc, const char **argv){
  ssh::Session session;
  try {
    if(argc>1)
      session.setOption(SSH_OPTIONS_HOST,argv[1]);
    else
      session.setOption(SSH_OPTIONS_HOST,"localhost");
    session.connect();
    session.userauthPublickeyAuto();
    session.disconnect();
  } catch (ssh::SshException e){
    std::cout << "Error during connection : ";
    std::cout << e.getError() << std::endl;
  }
  return 0;
}
