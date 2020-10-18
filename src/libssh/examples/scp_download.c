/* scp_download.c
 * Sample implementation of a tiny SCP downloader client
 */

/*
Copyright 2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <libssh/libssh.h>
#include "examples_common.h"

static int verbosity = 0;
static const char *createcommand =
    "rm -fr /tmp/libssh_tests && mkdir /tmp/libssh_tests && "
    "cd /tmp/libssh_tests && date > a && date > b && mkdir c && date > d";
static char *host = NULL;

static void usage(const char *argv0){
  fprintf(stderr,"Usage : %s [options] host\n"
      "sample tiny scp downloader client - libssh-%s\n"
	  "This program will create files in /tmp and try to fetch them\n",
//      "Options :\n",
//      "  -r : use RSA to verify host public key\n",
      argv0,
      ssh_version(0));
  exit(0);
}

static int opts(int argc, char **argv){
  int i;
  while((i=getopt(argc,argv,"v"))!=-1){
    switch(i){
      case 'v':
        verbosity++;
        break;
      default:
        fprintf(stderr,"unknown option %c\n",optopt);
        usage(argv[0]);
        return -1;
    }
  }
  host = argv[optind];
  if(host == NULL)
	  usage(argv[0]);
  return 0;
}

static void create_files(ssh_session session){
	ssh_channel channel=ssh_channel_new(session);
	char buffer[1];
        int rc;

	if(channel == NULL){
		fprintf(stderr,"Error creating channel: %s\n",ssh_get_error(session));
		exit(EXIT_FAILURE);
	}
	if(ssh_channel_open_session(channel) != SSH_OK){
		fprintf(stderr,"Error creating channel: %s\n",ssh_get_error(session));
		ssh_channel_free(channel);
		exit(EXIT_FAILURE);
	}
	if(ssh_channel_request_exec(channel,createcommand) != SSH_OK){
		fprintf(stderr,"Error executing command: %s\n",ssh_get_error(session));
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		exit(EXIT_FAILURE);
	}
	while(!ssh_channel_is_eof(channel)){
		rc = ssh_channel_read(channel,buffer,1,1);
                if (rc != 1) {
                    fprintf(stderr, "Error reading from channel\n");
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    return;
                }

                rc = write(1, buffer, 1);
                if (rc < 0) {
                    fprintf(stderr, "Error writing to buffer\n");
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    return;
                }
	}
	ssh_channel_close(channel);
	ssh_channel_free(channel);
}


static int fetch_files(ssh_session session){
  int size;
  char buffer[16384];
  int mode;
  char *filename;
  int r;
  ssh_scp scp=ssh_scp_new(session, SSH_SCP_READ | SSH_SCP_RECURSIVE, "/tmp/libssh_tests/*");
  if(ssh_scp_init(scp) != SSH_OK){
	  fprintf(stderr,"error initializing scp: %s\n",ssh_get_error(session));
	  ssh_scp_free(scp);
	  return -1;
  }
  printf("Trying to download 3 files (a,b,d) and 1 directory (c)\n");
  do {

	  r=ssh_scp_pull_request(scp);
	  switch(r){
	  case SSH_SCP_REQUEST_NEWFILE:
		  size=ssh_scp_request_get_size(scp);
		  filename=strdup(ssh_scp_request_get_filename(scp));
		  mode=ssh_scp_request_get_permissions(scp);
		  printf("downloading file %s, size %d, perms 0%o\n",filename,size,mode);
		  free(filename);
		  ssh_scp_accept_request(scp);
		  r=ssh_scp_read(scp,buffer,sizeof(buffer));
		  if(r==SSH_ERROR){
			  fprintf(stderr,"Error reading scp: %s\n",ssh_get_error(session));
			  ssh_scp_close(scp);
			  ssh_scp_free(scp);
			  return -1;
		  }
		  printf("done\n");
		  break;
	  case SSH_ERROR:
		  fprintf(stderr,"Error: %s\n",ssh_get_error(session));
		  ssh_scp_close(scp);
		  ssh_scp_free(scp);
		  return -1;
	  case SSH_SCP_REQUEST_WARNING:
		  fprintf(stderr,"Warning: %s\n",ssh_scp_request_get_warning(scp));
		  break;
	  case SSH_SCP_REQUEST_NEWDIR:
		  filename=strdup(ssh_scp_request_get_filename(scp));
		  mode=ssh_scp_request_get_permissions(scp);
		  printf("downloading directory %s, perms 0%o\n",filename,mode);
		  free(filename);
		  ssh_scp_accept_request(scp);
		  break;
	  case SSH_SCP_REQUEST_ENDDIR:
		  printf("End of directory\n");
		  break;
	  case SSH_SCP_REQUEST_EOF:
		  printf("End of requests\n");
		  goto end;
	  }
  } while (1);
  end:
  ssh_scp_close(scp);
  ssh_scp_free(scp);
  return 0;
}

int main(int argc, char **argv){
  ssh_session session;
  if(opts(argc,argv)<0)
    return EXIT_FAILURE;
  session=connect_ssh(host,NULL,verbosity);
  if(session == NULL)
	  return EXIT_FAILURE;
  create_files(session);
  fetch_files(session);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_finalize();
  return 0;
}
