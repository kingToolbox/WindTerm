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

#include "benchmarks.h"
#include <libssh/libssh.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>

#define PING_PROGRAM "/bin/ping"

/** @internal
 * @brief Calculates the RTT of the host with ICMP ping, and returns the
 * average of the calculated RTT.
 * @param[in] host hostname to ping.
 * @param[out] average average RTT in milliseconds.
 * @returns 0 on success, -1 if there is an error.
 * @warning relies on an external ping program which may not exist on
 * certain OS.
 */
int benchmarks_ping_latency (const char *host, float *average){
  const char *ptr;
  char cmd[256];
  char line[1024];
  FILE *fd;
  int found=0;

  /* strip out the hostname */
  ptr=strchr(host,'@');
  if(ptr)
    ptr++;
  else
    ptr=host;

  snprintf(cmd,sizeof(cmd),"%s -n -q -c3 %s",PING_PROGRAM, ptr);
  fd=popen(cmd,"r");
  if(fd==NULL){
    fprintf(stderr,"Error executing command : %s\n", strerror(errno));
    return -1;
  }

  while(!found && fgets(line,sizeof(line),fd)!=NULL){
    if(strstr(line,"rtt")){
      ptr=strchr(line,'=');
      if(ptr==NULL)
        goto parseerror;
      ptr=strchr(ptr,'/');
      if(ptr==NULL)
        goto parseerror;
      *average=strtof(ptr+1,NULL);
      found=1;
      break;
    }
  }
  if(!found)
    goto parseerror;
  pclose(fd);
  return 0;

parseerror:
  fprintf(stderr,"Parse error : couldn't locate average in %s",line);
  pclose(fd);
  return -1;
}

/** @internal
 * @brief initialize a timestamp to the current time.
 * @param[out] ts A timestamp_struct pointer.
 */
void timestamp_init(struct timestamp_struct *ts){
  gettimeofday(&ts->timestamp,NULL);
}

/** @internal
 * @brief return the elapsed time since now and the moment ts was initialized.
 * @param[in] ts An initialized timestamp_struct pointer.
 * @return Elapsed time in milliseconds.
 */
float elapsed_time(struct timestamp_struct *ts){
  struct timeval now;
  time_t secdiff;
  long usecdiff; /* may be negative */

  gettimeofday(&now,NULL);
  secdiff=now.tv_sec - ts->timestamp.tv_sec;
  usecdiff=now.tv_usec - ts->timestamp.tv_usec;
  //printf("%d sec diff, %d usec diff\n",secdiff, usecdiff);
  return (float) (secdiff*1000) + ((float)usecdiff)/1000;
}

/** @internal
 * @brief Calculates the RTT of the host with SSH channel operations, and
 * returns the average of the calculated RTT.
 * @param[in] session active SSH session to test.
 * @param[out] average average RTT in milliseconds.
 * @returns 0 on success, -1 if there is an error.
 */
int benchmarks_ssh_latency(ssh_session session, float *average){
  float times[3];
  struct timestamp_struct ts;
  int i;
  ssh_channel channel;
  channel=ssh_channel_new(session);
  if(channel==NULL)
    goto error;
  if(ssh_channel_open_session(channel)==SSH_ERROR)
    goto error;

  for(i=0;i<3;++i){
    timestamp_init(&ts);
    if(ssh_channel_request_env(channel,"TEST","test")==SSH_ERROR &&
        ssh_get_error_code(session)==SSH_FATAL)
      goto error;
    times[i]=elapsed_time(&ts);
  }
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  channel=NULL;
  printf("SSH request times : %f ms ; %f ms ; %f ms\n", times[0], times[1], times[2]);
  *average=(times[0]+times[1]+times[2])/3;
  return 0;
error:
  fprintf(stderr,"Error calculating SSH latency : %s\n",ssh_get_error(session));
  if(channel)
    ssh_channel_free(channel);
  return -1;
}
