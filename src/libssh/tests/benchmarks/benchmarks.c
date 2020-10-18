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

#include "config.h"
#include "benchmarks.h"
#include <libssh/libssh.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct benchmark benchmarks[]= {
    {
        .name="benchmark_raw_upload",
        .fct=benchmarks_raw_up,
        .enabled=0
    },
    {
        .name="benchmark_raw_download",
        .fct=benchmarks_raw_down,
        .enabled=0
    },
    {
        .name="benchmark_scp_upload",
        .fct=benchmarks_scp_up,
        .enabled=0
    },
    {
        .name="benchmark_scp_download",
        .fct=benchmarks_scp_down,
        .enabled=0
    },
    {
        .name="benchmark_sync_sftp_upload",
        .fct=benchmarks_sync_sftp_up,
        .enabled=0
    },
    {
        .name="benchmark_sync_sftp_download",
        .fct=benchmarks_sync_sftp_down,
        .enabled=0
    },
    {
        .name="benchmark_async_sftp_download",
        .fct=benchmarks_async_sftp_down,
        .enabled=0
    }
};

#ifdef HAVE_ARGP_H
#include <argp.h>

const char *argp_program_version = "libssh benchmarks 2011-08-28";
const char *argp_program_bug_address = "Aris Adamantiadis <aris@0xbadc0de.be>";

static char **cmdline;

/* Program documentation. */
static char doc[] = "libssh benchmarks";


/* The options we understand. */
static struct argp_option options[] = {
  {
    .name  = "verbose",
    .key   = 'v',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Make libssh benchmark more verbose",
    .group = 0
  },
  {
    .name  = "raw-upload",
    .key   = '1',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Upload raw data using channel",
    .group = 0
  },
  {
    .name  = "raw-download",
    .key   = '2',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Download raw data using channel",
    .group = 0
  },
  {
    .name  = "scp-upload",
    .key   = '3',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Upload data using SCP",
    .group = 0
  },
  {
    .name  = "scp-download",
    .key   = '4',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Download data using SCP",
    .group = 0
  },
  {
    .name  = "sync-sftp-upload",
    .key   = '5',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Upload data using synchronous SFTP",
    .group = 0

  },
  {
    .name  = "sync-sftp-download",
    .key   = '6',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Download data using synchronous SFTP (slow)",
    .group = 0

  },
  {
    .name  = "async-sftp-download",
    .key   = '7',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Download data using asynchronous SFTP (fast)",
    .group = 0

  },
  {
    .name  = "host",
    .key   = 'h',
    .arg   = "HOST",
    .flags = 0,
    .doc   = "Add a host to connect for benchmark (format user@hostname)",
    .group = 0
  },
  {
    .name  = "size",
    .key   = 's',
    .arg   = "MBYTES",
    .flags = 0,
    .doc   = "MBytes of data to send/receive per test",
    .group = 0
  },
  {
    .name  = "chunk",
    .key   = 'c',
    .arg   = "bytes",
    .flags = 0,
    .doc   = "size of data chunks to send/receive",
    .group = 0
  },
  {
    .name  = "prequests",
    .key   = 'p',
    .arg   = "number [20]",
    .flags = 0,
    .doc   = "[async SFTP] number of concurrent requests",
    .group = 0
  },
  {
    .name  = "cipher",
    .key   = 'C',
    .arg   = "cipher",
    .flags = 0,
    .doc   = "Cryptographic cipher to be used",
    .group = 0
  },

  {NULL, 0, NULL, 0, NULL, 0}
};

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  /* Get the input argument from argp_parse, which we
   * know is a pointer to our arguments structure.
   */
  struct argument_s *arguments = state->input;

  /* arg is currently not used */
  (void) arg;

  switch (key) {
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
      benchmarks[key - '1'].enabled = 1;
      arguments->ntests ++;
      break;
    case 'v':
      arguments->verbose++;
      break;
    case 's':
      arguments->datasize = atoi(arg);
      break;
    case 'p':
      arguments->concurrent_requests = atoi(arg);
      break;
    case 'c':
      arguments->chunksize = atoi(arg);
      break;
    case 'C':
      arguments->cipher = arg;
      break;
    case 'h':
      if(arguments->nhosts >= MAX_HOSTS_CONNECT){
        fprintf(stderr, "Too much hosts\n");
        return ARGP_ERR_UNKNOWN;
      }
      arguments->hosts[arguments->nhosts]=arg;
      arguments->nhosts++;
      break;
    case ARGP_KEY_ARG:
      /* End processing here. */
      cmdline = &state->argv [state->next - 1];
      state->next = state->argc;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, NULL, doc, NULL, NULL, NULL};

#endif /* HAVE_ARGP_H */

static void cmdline_parse(int argc, char **argv, struct argument_s *arguments) {
  /*
   * Parse our arguments; every option seen by parse_opt will
   * be reflected in arguments.
   */
#ifdef HAVE_ARGP_H
  argp_parse(&argp, argc, argv, 0, 0, arguments);
#else /* HAVE_ARGP_H */
  (void) argc;
  (void) argv;
  arguments->hosts[0]="localhost";
  arguments->nhosts=1;
#endif /* HAVE_ARGP_H */
}

static void arguments_init(struct argument_s *arguments){
  memset(arguments,0,sizeof(*arguments));
  arguments->chunksize=32758;
  arguments->concurrent_requests=20;
  arguments->datasize = 10;
}

static ssh_session connect_host(const char *host, int verbose, char *cipher){
  ssh_session session=ssh_new();
  if(session==NULL)
    goto error;
  if(ssh_options_set(session,SSH_OPTIONS_HOST, host)<0)
    goto error;
  ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbose);
  if(cipher != NULL){
    if (ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, cipher) ||
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, cipher)){
      goto error;
    }
  }
  ssh_options_parse_config(session, NULL);
  if(ssh_connect(session)==SSH_ERROR)
    goto error;
  if(ssh_userauth_autopubkey(session,NULL) != SSH_AUTH_SUCCESS)
    goto error;
  return session;
error:
  fprintf(stderr,"Error connecting to \"%s\": %s\n",host,ssh_get_error(session));
  ssh_free(session);
  return NULL;
}

static char *network_speed(float bps){
  static char buf[128];
  if(bps > 1000*1000*1000){
    /* Gbps */
    snprintf(buf,sizeof(buf),"%f Gbps",bps/(1000*1000*1000));
  } else if(bps > 1000*1000){
    /* Mbps */
    snprintf(buf,sizeof(buf),"%f Mbps",bps/(1000*1000));
  } else if(bps > 1000){
    snprintf(buf,sizeof(buf),"%f Kbps",bps/1000);
  } else {
    snprintf(buf,sizeof(buf),"%f bps",bps);
  }
  return buf;
}

static void do_benchmarks(ssh_session session, struct argument_s *arguments,
    const char *hostname){
  float ping_rtt=0.0;
  float ssh_rtt=0.0;
  float bps=0.0;
  int i;
  int err;
  struct benchmark *b;

  if(arguments->verbose>0)
    fprintf(stdout,"Testing ICMP RTT\n");
  err=benchmarks_ping_latency(hostname, &ping_rtt);
  if(err == 0){
    fprintf(stdout,"ping RTT : %f ms\n",ping_rtt);
  }
  err=benchmarks_ssh_latency(session, &ssh_rtt);
  if(err==0){
    fprintf(stdout, "SSH RTT : %f ms. Theoretical max BW (win=128K) : %s\n",ssh_rtt,network_speed(128000.0/(ssh_rtt / 1000.0)));
  }
  for (i=0 ; i<BENCHMARK_NUMBER ; ++i){
    b = &benchmarks[i];
    if(b->enabled){
      err=b->fct(session,arguments,&bps);
      if(err==0){
        fprintf(stdout, "%s : %s : %s\n",hostname, b->name, network_speed(bps));
      }
    }
  }
}

char *buffer;

int main(int argc, char **argv){
  struct argument_s arguments;
  ssh_session session;
  int i;

  arguments_init(&arguments);
  cmdline_parse(argc, argv, &arguments);
  if (arguments.nhosts==0){
    fprintf(stderr,"At least one host (-h) must be specified\n");
    return EXIT_FAILURE;
  }
  if (arguments.ntests==0){
    for(i=0; i < BENCHMARK_NUMBER ; ++i){
      benchmarks[i].enabled=1;
    }
    arguments.ntests=BENCHMARK_NUMBER;
  }
  buffer=malloc(arguments.chunksize > 1024 ? arguments.chunksize : 1024);
  if(buffer == NULL){
    fprintf(stderr,"Allocation of chunk buffer failed\n");
    return EXIT_FAILURE;
  }
  if (arguments.verbose > 0){
    fprintf(stdout, "Will try hosts ");
    for(i=0;i<arguments.nhosts;++i){
      fprintf(stdout,"\"%s\" ", arguments.hosts[i]);
    }
    fprintf(stdout,"with benchmarks ");
    for(i=0;i<BENCHMARK_NUMBER;++i){
      if(benchmarks[i].enabled)
        fprintf(stdout,"\"%s\" ",benchmarks[i].name);
    }
    fprintf(stdout,"\n");
  }

  for(i=0; i<arguments.nhosts;++i){
    if(arguments.verbose > 0)
      fprintf(stdout,"Connecting to \"%s\"...\n",arguments.hosts[i]);
    session=connect_host(arguments.hosts[i], arguments.verbose, arguments.cipher);
    if(session != NULL && arguments.verbose > 0)
      fprintf(stdout,"Success\n");
    if(session == NULL){
      fprintf(stderr,"Errors occurred, stopping\n");
      return EXIT_FAILURE;
    }
    do_benchmarks(session, &arguments, arguments.hosts[i]);
    ssh_disconnect(session);
    ssh_free(session);
  }
  return EXIT_SUCCESS;
}

