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

#ifndef BENCHMARKS_H_
#define BENCHMARKS_H_

#include <libssh/libssh.h>

/* benchmarks.c */

/* maximum number of parallel hosts that may be checked */
#define MAX_HOSTS_CONNECT 20

enum libssh_benchmarks {
    BENCHMARK_RAW_UPLOAD=0,
    BENCHMARK_RAW_DOWNLOAD,
    BENCHMARK_SCP_UPLOAD,
    BENCHMARK_SCP_DOWNLOAD,
    BENCHMARK_SYNC_SFTP_UPLOAD,
    BENCHMARK_SYNC_SFTP_DOWNLOAD,
    BENCHMARK_ASYNC_SFTP_DOWNLOAD,
    BENCHMARK_NUMBER
};

struct argument_s {
  const char *hosts[MAX_HOSTS_CONNECT];
  int verbose;
  int nhosts;
  int ntests;
  unsigned int datasize;
  unsigned int chunksize;
  int concurrent_requests;
  char *cipher;
};

extern char *buffer;

typedef int (*bench_fct)(ssh_session session, struct argument_s *args,
    float *bps);

struct benchmark {
  const char *name;
  bench_fct fct;
  int enabled;
};

/* latency.c */

struct timestamp_struct {
  struct timeval timestamp;
};

int benchmarks_ping_latency (const char *host, float *average);
int benchmarks_ssh_latency (ssh_session session, float *average);

void timestamp_init(struct timestamp_struct *ts);
float elapsed_time(struct timestamp_struct *ts);

/* bench_raw.c */

int benchmarks_raw_up (ssh_session session, struct argument_s *args,
    float *bps);
int benchmarks_raw_down (ssh_session session, struct argument_s *args,
    float *bps);

/* bench_scp.c */

int benchmarks_scp_up (ssh_session session, struct argument_s *args,
    float *bps);
int benchmarks_scp_down (ssh_session session, struct argument_s *args,
    float *bps);

/* bench_sftp.c */

int benchmarks_sync_sftp_up (ssh_session session, struct argument_s *args,
    float *bps);
int benchmarks_sync_sftp_down (ssh_session session, struct argument_s *args,
    float *bps);
int benchmarks_async_sftp_down (ssh_session session, struct argument_s *args,
    float *bps);
#endif /* BENCHMARKS_H_ */
