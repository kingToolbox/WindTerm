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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PYTHON_PATH "/usr/bin/python"

const char python_eater[]=
"#!/usr/bin/python\n"
"import sys\n"
"print 'go'\n"
"sys.stdout.flush()\n"
"toread=XXXXXXXXXX\n"
"read=0\n"
"while(read < toread):\n"
"    buffersize=toread-read\n"
"    if(buffersize > 4096):\n"
"        buffersize=4096\n"
"    r=len(sys.stdin.read(buffersize))\n"
"    read+=r\n"
"    if(r<=0):\n"
"        print 'error'\n"
"        exit()\n"
"print 'done'\n";

static char *get_python_eater(unsigned long bytes){
  char *eater=malloc(sizeof(python_eater));
  char *ptr;
  char buf[12];

  memcpy(eater,python_eater,sizeof(python_eater));
  ptr=strstr(eater,"XXXXXXXXXX");
  if(!ptr){
    free(eater);
    return NULL;
  }
  sprintf(buf,"0x%.8lx",bytes);
  memcpy(ptr,buf,10);
  return eater;
}

/** @internal
 * @brief uploads a script (python or other) at a specific path on the
 * remote host
 * @param[in] session an active SSH session
 * @param[in] path to copy the file
 * @param[in] content of the file to copy
 * @return 0 on success, -1 on error
 */
static int upload_script(ssh_session session, const char *path,
    const char *script){
  ssh_channel channel;
  char cmd[128];
  int err;

  channel=ssh_channel_new(session);
  if(!channel)
    goto error;
  if(ssh_channel_open_session(channel) == SSH_ERROR)
    goto error;
  snprintf(cmd,sizeof(cmd),"cat > %s",path);
  if(ssh_channel_request_exec(channel,cmd) == SSH_ERROR)
    goto error;
  err=ssh_channel_write(channel,script,strlen(script));
  if(err == SSH_ERROR)
    goto error;
  if(ssh_channel_send_eof(channel) == SSH_ERROR)
    goto error;
  if(ssh_channel_close(channel) == SSH_ERROR)
    goto error;
  ssh_channel_free(channel);
  return 0;
error:
  fprintf(stderr,"Error while copying script : %s\n",ssh_get_error(session));
  return -1;
}

/** @internal
 * @brief benchmarks a raw upload (simple upload in a SSH channel) using an
 * existing SSH session.
 * @param[in] session Open SSH session
 * @param[in] args Parsed command line arguments
 * @param[out] bps The calculated bytes per second obtained via benchmark.
 * @return 0 on success, -1 on error.
 */
int benchmarks_raw_up (ssh_session session, struct argument_s *args,
    float *bps){
  unsigned long bytes;
  char *script;
  char cmd[128];
  int err;
  ssh_channel channel;
  struct timestamp_struct ts;
  float ms=0.0;
  unsigned long total=0;

  bytes = args->datasize * 1024 * 1024;
  script =get_python_eater(bytes);
  err=upload_script(session,"/tmp/eater.py",script);
  free(script);
  if(err<0)
    return err;
  channel=ssh_channel_new(session);
  if(channel == NULL)
    goto error;
  if(ssh_channel_open_session(channel)==SSH_ERROR)
    goto error;
  snprintf(cmd,sizeof(cmd),"%s /tmp/eater.py", PYTHON_PATH);
  if(ssh_channel_request_exec(channel,cmd)==SSH_ERROR)
    goto error;
  if((err=ssh_channel_read(channel,buffer,sizeof(buffer)-1,0))==SSH_ERROR)
    goto error;
  buffer[err]=0;
  if(!strstr(buffer,"go")){
    fprintf(stderr,"parse error : %s\n",buffer);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return -1;
  }
  if(args->verbose>0)
    fprintf(stdout,"Starting upload of %lu bytes now\n",bytes);
  timestamp_init(&ts);
  while(total < bytes){
    unsigned long towrite = bytes - total;
    int w;
    if(towrite > args->chunksize)
      towrite = args->chunksize;
    w=ssh_channel_write(channel,buffer,towrite);
    if(w == SSH_ERROR)
      goto error;
    total += w;
  }

  if(args->verbose>0)
    fprintf(stdout,"Finished upload, now waiting the ack\n");

  if((err=ssh_channel_read(channel,buffer,5,0))==SSH_ERROR)
      goto error;
  buffer[err]=0;
  if(!strstr(buffer,"done")){
    fprintf(stderr,"parse error : %s\n",buffer);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return -1;
  }
  ms=elapsed_time(&ts);
  *bps=8000 * (float)bytes / ms;
  if(args->verbose > 0)
    fprintf(stdout,"Upload took %f ms for %lu bytes, at %f bps\n",ms,
        bytes,*bps);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  return 0;
error:
  fprintf(stderr,"Error during raw upload : %s\n",ssh_get_error(session));
  if(channel){
    ssh_channel_close(channel);
    ssh_channel_free(channel);
  }
  return -1;
}

const char python_giver[] =
"#!/usr/bin/python\n"
"import sys\n"
"r=sys.stdin.read(2)\n"
"towrite=XXXXXXXXXX\n"
"wrote=0\n"
"mtu = 32786\n"
"buf = 'A'*mtu\n"
"while(wrote < towrite):\n"
"    buffersize=towrite-wrote\n"
"    if(buffersize > mtu):\n"
"        buffersize=mtu\n"
"    if(buffersize == mtu):\n"
"        sys.stdout.write(buf)\n"
"    else:\n"
"        sys.stdout.write('A'*buffersize)\n"
"    wrote+=buffersize\n"
"sys.stdout.flush()\n";

static char *get_python_giver(unsigned long bytes){
  char *giver=malloc(sizeof(python_giver));
  char *ptr;
  char buf[12];

  memcpy(giver,python_giver,sizeof(python_giver));
  ptr=strstr(giver,"XXXXXXXXXX");
  if(!ptr){
    free(giver);
    return NULL;
  }
  sprintf(buf,"0x%.8lx",bytes);
  memcpy(ptr,buf,10);
  return giver;
}

/** @internal
 * @brief benchmarks a raw download (simple upload in a SSH channel) using an
 * existing SSH session.
 * @param[in] session Open SSH session
 * @param[in] args Parsed command line arguments
 * @param[out] bps The calculated bytes per second obtained via benchmark.
 * @return 0 on success, -1 on error.
 */
int benchmarks_raw_down (ssh_session session, struct argument_s *args,
    float *bps){
  unsigned long bytes;
  char *script;
  char cmd[128];
  int err;
  ssh_channel channel;
  struct timestamp_struct ts;
  float ms=0.0;
  unsigned long total=0;

  bytes = args->datasize * 1024 * 1024;
  script =get_python_giver(bytes);
  err=upload_script(session,"/tmp/giver.py",script);
  free(script);
  if(err<0)
    return err;
  channel=ssh_channel_new(session);
  if(channel == NULL)
    goto error;
  if(ssh_channel_open_session(channel)==SSH_ERROR)
    goto error;
  snprintf(cmd,sizeof(cmd),"%s /tmp/giver.py", PYTHON_PATH);
  if(ssh_channel_request_exec(channel,cmd)==SSH_ERROR)
    goto error;
  if((err=ssh_channel_write(channel,"go",2))==SSH_ERROR)
    goto error;
  if(args->verbose>0)
    fprintf(stdout,"Starting download of %lu bytes now\n",bytes);
  timestamp_init(&ts);
  while(total < bytes){
    unsigned long toread = bytes - total;
    int r;
    if(toread > args->chunksize)
      toread = args->chunksize;
    r=ssh_channel_read(channel,buffer,toread,0);
    if(r == SSH_ERROR)
      goto error;
    total += r;
  }

  if(args->verbose>0)
    fprintf(stdout,"Finished download\n");
  ms=elapsed_time(&ts);
  *bps=8000 * (float)bytes / ms;
  if(args->verbose > 0)
    fprintf(stdout,"Download took %f ms for %lu bytes, at %f bps\n",ms,
        bytes,*bps);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  return 0;
error:
  fprintf(stderr,"Error during raw upload : %s\n",ssh_get_error(session));
  if(channel){
    ssh_channel_close(channel);
    ssh_channel_free(channel);
  }
  return -1;
}
