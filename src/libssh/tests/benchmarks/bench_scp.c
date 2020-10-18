/* bench_scp.c
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2011 by Aris Adamantiadis
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

#define SCPDIR "/tmp/"
#define SCPFILE "scpbenchmark"

/** @internal
 * @brief benchmarks a scp upload using an
 * existing SSH session.
 * @param[in] session Open SSH session
 * @param[in] args Parsed command line arguments
 * @param[out] bps The calculated bytes per second obtained via benchmark.
 * @return 0 on success, -1 on error.
 */
int benchmarks_scp_up (ssh_session session, struct argument_s *args,
    float *bps){
  unsigned long bytes;
  struct timestamp_struct ts;
  float ms=0.0;
  unsigned long total=0;
  ssh_scp scp;

  bytes = args->datasize * 1024 * 1024;
  scp = ssh_scp_new(session,SSH_SCP_WRITE,SCPDIR);
  if(scp == NULL)
    goto error;
  if(ssh_scp_init(scp)==SSH_ERROR)
    goto error;
  if(ssh_scp_push_file(scp,SCPFILE,bytes,0777) != SSH_OK)
    goto error;
  if(args->verbose>0)
    fprintf(stdout,"Starting upload of %lu bytes now\n",bytes);
  timestamp_init(&ts);
  while(total < bytes){
    unsigned long towrite = bytes - total;
    int w;
    if(towrite > args->chunksize)
      towrite = args->chunksize;
    w=ssh_scp_write(scp,buffer,towrite);
    if(w == SSH_ERROR)
      goto error;
    total += towrite;
  }
  ms=elapsed_time(&ts);
  *bps=8000 * (float)bytes / ms;
  if(args->verbose > 0)
    fprintf(stdout,"Upload took %f ms for %lu bytes, at %f bps\n",ms,
        bytes,*bps);
  ssh_scp_close(scp);
  ssh_scp_free(scp);
  return 0;
error:
  fprintf(stderr,"Error during scp upload : %s\n",ssh_get_error(session));
  if(scp){
    ssh_scp_close(scp);
    ssh_scp_free(scp);
  }
  return -1;
}

/** @internal
 * @brief benchmarks a scp download using an
 * existing SSH session.
 * @param[in] session Open SSH session
 * @param[in] args Parsed command line arguments
 * @param[out] bps The calculated bytes per second obtained via benchmark.
 * @return 0 on success, -1 on error.
 */
int benchmarks_scp_down (ssh_session session, struct argument_s *args,
    float *bps){
  unsigned long bytes;
  struct timestamp_struct ts;
  float ms=0.0;
  unsigned long total=0;
  ssh_scp scp;
  int r;
  size_t size;

  bytes = args->datasize * 1024 * 1024;
  scp = ssh_scp_new(session,SSH_SCP_READ,SCPDIR SCPFILE);
  if(scp == NULL)
    goto error;
  if(ssh_scp_init(scp)==SSH_ERROR)
    goto error;
  r=ssh_scp_pull_request(scp);
  if(r == SSH_SCP_REQUEST_NEWFILE){
    size=ssh_scp_request_get_size(scp);
    if(bytes > size){
      printf("Only %zd bytes available (on %lu requested).\n",size,bytes);
      bytes = size;
    }
    if(size > bytes){
      printf("File is %zd bytes (on %lu requested). Will cut the end\n",size,bytes);
    }
    if(args->verbose>0)
      fprintf(stdout,"Starting download of %lu bytes now\n",bytes);
    timestamp_init(&ts);
    ssh_scp_accept_request(scp);
    while(total < bytes){
      unsigned long toread = bytes - total;
      if(toread > args->chunksize)
        toread = args->chunksize;
      r=ssh_scp_read(scp,buffer,toread);
      if(r == SSH_ERROR || r == 0)
        goto error;
      total += r;
    }
    ms=elapsed_time(&ts);
    *bps=8000 * (float)bytes / ms;
    if(args->verbose > 0)
      fprintf(stdout,"download took %f ms for %lu bytes, at %f bps\n",ms,
          bytes,*bps);
  } else {
    fprintf(stderr,"Expected SSH_SCP_REQUEST_NEWFILE, got %d\n",r);
    goto error;
  }
  ssh_scp_close(scp);
  ssh_scp_free(scp);
  return 0;
error:
  fprintf(stderr,"Error during scp download : %s\n",ssh_get_error(session));
  if(scp){
    ssh_scp_close(scp);
    ssh_scp_free(scp);
  }
  return -1;
}
