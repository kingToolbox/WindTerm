/*
Copyright 2010 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/select.h>
#include <sys/time.h>

#include <sys/ioctl.h>
#include <errno.h>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <fcntl.h>

#include "examples_common.h"
char *host;
const char *desthost="localhost";
const char *port="22";

#ifdef WITH_PCAP
#include <libssh/pcap.h>
char *pcap_file=NULL;
#endif

static void usage(void)
{
  fprintf(stderr,"Usage : sshnetcat [user@]host forwarded_host forwarded_port\n");
  exit(1);
}

static int opts(int argc, char **argv){
    int i;
    while((i=getopt(argc,argv,"P:"))!=-1){
        switch(i){
#ifdef WITH_PCAP
        	case 'P':
        		pcap_file=optarg;
        		break;
#endif
            default:
                fprintf(stderr,"unknown option %c\n",optopt);
                usage();
        }
    }
    if(optind < argc)
        host=argv[optind++];
    if(optind < argc)
        desthost=argv[optind++];
    if(optind < argc)
        port=argv[optind++];
    if(host==NULL)
        usage();
    return 0;
}

static void select_loop(ssh_session session,ssh_channel channel){
	fd_set fds;
	struct timeval timeout;
	char buffer[4096];
	/* channels will be set to the channels to poll.
	 * outchannels will contain the result of the poll
	 */
	ssh_channel channels[2], outchannels[2];
	int lus;
	int eof=0;
	int maxfd;
	int ret;
	while(channel){
		do{
            int fd;

            ZERO_STRUCT(fds);
			FD_ZERO(&fds);
			if(!eof)
				FD_SET(0,&fds);
			timeout.tv_sec=30;
			timeout.tv_usec=0;

            fd = ssh_get_fd(session);
            if (fd == -1) {
                fprintf(stderr, "Error getting the session file descriptor: %s\n",
                                ssh_get_error(session));
                return;
            }
            FD_SET(fd, &fds);
            maxfd = fd + 1;

			channels[0]=channel; // set the first channel we want to read from
			channels[1]=NULL;
			ret=ssh_select(channels,outchannels,maxfd,&fds,&timeout);
			if(ret==EINTR)
				continue;
			if(FD_ISSET(0,&fds)){
				lus=read(0,buffer,sizeof(buffer));
				if(lus)
					ssh_channel_write(channel,buffer,lus);
				else {
					eof=1;
					ssh_channel_send_eof(channel);
				}
			}
			if(channel && ssh_channel_is_closed(channel)){
				ssh_channel_free(channel);
				channel=NULL;
				channels[0]=NULL;
			}
			if(outchannels[0]){
				while(channel && ssh_channel_is_open(channel) && ssh_channel_poll(channel,0)){
					lus = ssh_channel_read(channel,buffer,sizeof(buffer),0);
					if(lus==-1){
						fprintf(stderr, "Error reading channel: %s\n",
								ssh_get_error(session));
						return;
					}
					if(lus==0){
						ssh_channel_free(channel);
						channel=channels[0]=NULL;
					} else {
						ret = write(1, buffer, lus);
						if (ret < 0) {
							fprintf(stderr, "Error writing to stdin: %s",
								strerror(errno));
							return;
						}
					}
				}
				while(channel && ssh_channel_is_open(channel) && ssh_channel_poll(channel,1)){ /* stderr */
					lus = ssh_channel_read(channel, buffer, sizeof(buffer), 1);
					if(lus==-1){
						fprintf(stderr, "Error reading channel: %s\n",
								ssh_get_error(session));
						return;
					}
					if(lus==0){
						ssh_channel_free(channel);
						channel=channels[0]=NULL;
					} else {
						ret = write(2, buffer, lus);
						if (ret < 0) {
							fprintf(stderr, "Error writing to stderr: %s",
								strerror(errno));
							return;
						}
                    }
				}
			}
			if(channel && ssh_channel_is_closed(channel)){
				ssh_channel_free(channel);
				channel=NULL;
			}
		} while (ret==EINTR || ret==SSH_EINTR);

	}
}

static void forwarding(ssh_session session){
    ssh_channel channel;
    int r;
    channel = ssh_channel_new(session);
    r = ssh_channel_open_forward(channel, desthost, atoi(port), "localhost", 22);
    if(r<0) {
        printf("error forwarding port : %s\n",ssh_get_error(session));
        return;
    }
    select_loop(session,channel);
}

static int client(ssh_session session){
  int auth=0;
  char *banner;
  int state;

  if (ssh_options_set(session, SSH_OPTIONS_HOST ,host) < 0)
    return -1;
  ssh_options_parse_config(session, NULL);

  if(ssh_connect(session)){
      fprintf(stderr,"Connection failed : %s\n",ssh_get_error(session));
      return -1;
  }
  state=verify_knownhost(session);
  if (state != 0)
  	return -1;
  ssh_userauth_none(session, NULL);
  banner=ssh_get_issue_banner(session);
  if(banner){
      printf("%s\n",banner);
      free(banner);
  }
  auth=authenticate_console(session);
  if(auth != SSH_AUTH_SUCCESS){
  	return -1;
  }
 	forwarding(session);
  return 0;
}

#ifdef WITH_PCAP
ssh_pcap_file pcap;
void set_pcap(ssh_session session);
void set_pcap(ssh_session session){
	if(!pcap_file)
		return;
	pcap=ssh_pcap_file_new();
	if(ssh_pcap_file_open(pcap,pcap_file) == SSH_ERROR){
		printf("Error opening pcap file\n");
		ssh_pcap_file_free(pcap);
		pcap=NULL;
		return;
	}
	ssh_set_pcap_file(session,pcap);
}

void cleanup_pcap(void);
void cleanup_pcap(){
	ssh_pcap_file_free(pcap);
	pcap=NULL;
}
#endif

int main(int argc, char **argv){
    ssh_session session;

    session = ssh_new();

    if(ssh_options_getopt(session, &argc, argv)) {
      fprintf(stderr, "error parsing command line :%s\n",
          ssh_get_error(session));
      usage();
    }
    opts(argc,argv);
#ifdef WITH_PCAP
    set_pcap(session);
#endif
    client(session);

    ssh_disconnect(session);
    ssh_free(session);
#ifdef WITH_PCAP
    cleanup_pcap();
#endif

    ssh_finalize();

    return 0;
}
