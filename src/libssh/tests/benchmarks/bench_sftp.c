/* bench_sftp.c
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
#include <libssh/sftp.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

#define SFTPDIR "/tmp/"
#define SFTPFILE "scpbenchmark"

/** @internal
 * @brief benchmarks a synchronous sftp upload using an
 * existing SSH session.
 * @param[in] session Open SSH session
 * @param[in] args Parsed command line arguments
 * @param[out] bps The calculated bytes per second obtained via benchmark.
 * @return 0 on success, -1 on error.
 */
int benchmarks_sync_sftp_up (ssh_session session, struct argument_s *args,
    float *bps){
  unsigned long bytes;
  struct timestamp_struct ts;
  float ms=0.0;
  unsigned long total=0;
  sftp_session sftp;
  sftp_file file = NULL;

  bytes = args->datasize * 1024 * 1024;
  sftp = sftp_new(session);
  if(sftp == NULL)
    goto error;
  if(sftp_init(sftp)==SSH_ERROR)
    goto error;
  file = sftp_open(sftp,SFTPDIR SFTPFILE,O_RDWR | O_CREAT | O_TRUNC, 0777);
  if(!file)
    goto error;
  if(args->verbose>0)
    fprintf(stdout,"Starting upload of %lu bytes now\n",bytes);
  timestamp_init(&ts);
  while(total < bytes){
    unsigned long towrite = bytes - total;
    int w;
    if(towrite > args->chunksize)
      towrite = args->chunksize;
    w=sftp_write(file,buffer,towrite);
    if(w == SSH_ERROR)
      goto error;
    total += w;
  }
  sftp_close(file);
  ms=elapsed_time(&ts);
  *bps=8000 * (float)bytes / ms;
  if(args->verbose > 0)
    fprintf(stdout,"Upload took %f ms for %lu bytes, at %f bps\n",ms,
        bytes,*bps);
  sftp_free(sftp);
  return 0;
error:
  fprintf(stderr,"Error during scp upload : %s\n",ssh_get_error(session));
  if(file)
    sftp_close(file);
  if(sftp)
    sftp_free(sftp);
  return -1;
}

/** @internal
 * @brief benchmarks a synchronous sftp download using an
 * existing SSH session.
 * @param[in] session Open SSH session
 * @param[in] args Parsed command line arguments
 * @param[out] bps The calculated bytes per second obtained via benchmark.
 * @return 0 on success, -1 on error.
 */
int benchmarks_sync_sftp_down (ssh_session session, struct argument_s *args,
    float *bps){
  unsigned long bytes;
  struct timestamp_struct ts;
  float ms=0.0;
  unsigned long total=0;
  sftp_session sftp;
  sftp_file file = NULL;
  int r;

  bytes = args->datasize * 1024 * 1024;
  sftp = sftp_new(session);
  if(sftp == NULL)
    goto error;
  if(sftp_init(sftp)==SSH_ERROR)
    goto error;
  file = sftp_open(sftp,SFTPDIR SFTPFILE,O_RDONLY,0);
  if(!file)
    goto error;
  if(args->verbose>0)
    fprintf(stdout,"Starting download of %lu bytes now\n",bytes);
  timestamp_init(&ts);
  while(total < bytes){
    unsigned long toread = bytes - total;
    if(toread > args->chunksize)
      toread = args->chunksize;
    r=sftp_read(file,buffer,toread);
    if(r == SSH_ERROR)
      goto error;
    total += r;
    /* we had a smaller file */
    if(r==0){
      fprintf(stdout,"File smaller than expected : %lu (expected %lu).\n",total,bytes);
      bytes = total;
      break;
    }
  }
  sftp_close(file);
  ms=elapsed_time(&ts);
  *bps=8000 * (float)bytes / ms;
  if(args->verbose > 0)
    fprintf(stdout,"download took %f ms for %lu bytes, at %f bps\n",ms,
        bytes,*bps);
  sftp_free(sftp);
  return 0;
error:
  fprintf(stderr,"Error during sftp download : %s\n",ssh_get_error(session));
  if(file)
    sftp_close(file);
  if(sftp)
    sftp_free(sftp);
  return -1;
}

/** @internal
 * @brief benchmarks an asynchronous sftp download using an
 * existing SSH session.
 * @param[in] session Open SSH session
 * @param[in] args Parsed command line arguments
 * @param[out] bps The calculated bytes per second obtained via benchmark.
 * @return 0 on success, -1 on error.
 */
int benchmarks_async_sftp_down (ssh_session session, struct argument_s *args,
    float *bps){
  unsigned long bytes;
  struct timestamp_struct ts;
  float ms=0.0;
  unsigned long total=0;
  sftp_session sftp;
  sftp_file file = NULL;
  int r,i;
  int warned = 0;
  unsigned long toread;
  int *ids=NULL;
  int concurrent_downloads = args->concurrent_requests;

  bytes = args->datasize * 1024 * 1024;
  sftp = sftp_new(session);
  if(sftp == NULL)
    goto error;
  if(sftp_init(sftp)==SSH_ERROR)
    goto error;
  file = sftp_open(sftp,SFTPDIR SFTPFILE,O_RDONLY,0);
  if(!file)
    goto error;
  ids = malloc(concurrent_downloads * sizeof(int));
  if(args->verbose>0)
    fprintf(stdout,"Starting download of %lu bytes now, using %d concurrent downloads\n",bytes,
        concurrent_downloads);
  timestamp_init(&ts);
  for (i=0;i<concurrent_downloads;++i){
    ids[i]=sftp_async_read_begin(file, args->chunksize);
    if(ids[i]==SSH_ERROR)
        goto error;
  }
  i=0;
  while(total < bytes){
    r = sftp_async_read(file, buffer, args->chunksize, ids[i]);
    if(r == SSH_ERROR)
      goto error;
    total += r;
    if(r != (int)args->chunksize && total != bytes && !warned){
      fprintf(stderr,"async_sftp_download : receiving short reads (%d, requested %d) "
          "the received file will be corrupted and shorted. Adapt chunksize to %d\n",
          r, args->chunksize,r);
      warned = 1;
    }
    /* we had a smaller file */
    if(r==0){
      fprintf(stdout,"File smaller than expected : %lu (expected %lu).\n",total,bytes);
      bytes = total;
      break;
    }
    toread = bytes - total;
    if(toread < args->chunksize * concurrent_downloads){
      /* we've got enough launched downloads */
      ids[i]=-1;
    }
    if(toread > args->chunksize)
      toread = args->chunksize;
    ids[i]=sftp_async_read_begin(file,toread);
    if(ids[i] == SSH_ERROR)
      goto error;
    i = (i+1) % concurrent_downloads;
  }
  sftp_close(file);
  ms=elapsed_time(&ts);
  *bps=8000 * (float)bytes / ms;
  if(args->verbose > 0)
    fprintf(stdout,"download took %f ms for %lu bytes, at %f bps\n",ms,
        bytes,*bps);
  sftp_free(sftp);
  free(ids);
  return 0;
error:
  fprintf(stderr,"Error during sftp download : %s\n",ssh_get_error(session));
  if(file)
    sftp_close(file);
  if(sftp)
    sftp_free(sftp);
  free(ids);
  return -1;
}
