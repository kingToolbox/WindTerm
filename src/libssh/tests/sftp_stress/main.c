/*
 * main.c
 *
 *  Created on: 22 juin 2009
 *      Author: aris
 */
#include <stdio.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#define TEST_READ 1
#define TEST_WRITE 2
#define NTHREADS 3
#define FILESIZE 100000
unsigned char samplefile[FILESIZE];
volatile int stop=0;

const char* hosts[]={"localhost","barebone"};
void signal_stop(){
  stop=1;
  printf("Stopping...\n");
}

SSH_SESSION *connect_host(const char *hostname);
int sftp_test(SSH_SESSION *session, int test);

int docycle(const char *host, int test){
  SSH_SESSION *session=connect_host(host);
  int ret=SSH_ERROR;
  if(!session){
    printf("connect failed\n");
  } else {
    printf("Connected\n");
    ret=sftp_test(session,test);
    if(ret != SSH_OK){
      printf("Error in sftp\n");
    }
    ssh_disconnect(session);
  }
  return ret;
}

int thread(){
  while(docycle(hosts[rand()%2],TEST_WRITE) == SSH_OK)
    if(stop)
      break;
  return 0;
}

int main(int argc, char **argv){
  int i;
  pthread_t threads[NTHREADS];
  ssh_init();
  srand(time(NULL));
  for(i=0;i<FILESIZE;++i)
    samplefile[i]=rand() & 0xff;
  signal(SIGTERM,signal_stop);
  signal(SIGINT,signal_stop);

  for(i=0;i<NTHREADS;++i){
    srand(i);
    pthread_create(&threads[i],NULL,(void *) thread, NULL);
  }
  for(i=0;i<NTHREADS;++i){
    pthread_join(threads[i],NULL);
  }
  ssh_finalize();
  printf("Ended\n");
  return 0;
}

SSH_SESSION *connect_host(const char *hostname){
  SSH_SESSION *session;
  SSH_OPTIONS *options;
  int auth=0;
  int state;

  options=ssh_options_new();
  ssh_options_set_host(options,hostname);
  session=ssh_new();
  ssh_set_options(session,options);
  if(ssh_connect(session)){
    fprintf(stderr,"Connection failed : %s\n",ssh_get_error(session));
    ssh_disconnect(session);
    return NULL;
  }

  state = ssh_session_is_known_server(session);
  switch(state){
    case SSH_SERVER_KNOWN_OK:
      break; /* ok */
    case SSH_SERVER_KNOWN_CHANGED:
      fprintf(stderr,"Host key for server changed : server's one is now :\n");
      fprintf(stderr,"For security reason, connection will be stopped\n");
      ssh_disconnect(session);
      ssh_finalize();
      return NULL;
    case SSH_SERVER_FOUND_OTHER:
      fprintf(stderr,"The host key for this server was not found but an other type of key exists.\n");
      fprintf(stderr,"An attacker might change the default server key to confuse your client"
          "into thinking the key does not exist\n"
          "We advise you to rerun the client with -d or -r for more safety.\n");
      ssh_disconnect(session);
      ssh_finalize();
      return NULL;
    case SSH_SERVER_NOT_KNOWN:
      fprintf(stderr,"The server is unknown. Leaving now");
      ssh_disconnect(session);
      return NULL;
    case SSH_SERVER_ERROR:
      fprintf(stderr,"%s",ssh_get_error(session));
      ssh_disconnect(session);
      return NULL;
  }

  ssh_userauth_none(session, NULL);

  auth=ssh_userauth_autopubkey(session, NULL);
  if(auth==SSH_AUTH_ERROR){
    fprintf(stderr,"Authenticating with pubkey: %s\n",ssh_get_error(session));
    ssh_disconnect(session);
    return NULL;
  }
  if(auth!=SSH_AUTH_SUCCESS){
    fprintf(stderr,"Authentication failed: %s\n",ssh_get_error(session));
    ssh_disconnect(session);
    return NULL;
  }
  ssh_log(session, SSH_LOG_FUNCTIONS, "Authentication success");
  return session;
}

int sftp_test(SSH_SESSION *session, int test){
  SFTP_SESSION *sftp=sftp_new(session);
  SFTP_FILE *file;
  int wrote=0;
  char name[128];
  if(sftp == NULL)
    return SSH_ERROR;
  if(sftp_init(sftp)<0){
    printf("problem initializing sftp : %s\n",ssh_get_error(session));
    return SSH_ERROR;
  }
  if(test==TEST_WRITE){
    snprintf(name,sizeof(name),"/tmp/libsshstress%d",rand());
    file=sftp_open(sftp,name,O_RDWR|O_CREAT,0777);
    if(!file){
      printf("Failed to open file : %s\n",ssh_get_error(session));
      sftp_free(sftp);
      return SSH_ERROR;
    }
    while(wrote<FILESIZE){
      int max=FILESIZE-wrote;
      int towrite=rand()%max + 1;
      int ret=sftp_write(file,&samplefile[wrote],towrite);
      if(ret<=0){
        printf("Problem while writing : %s\n",ssh_get_error(session));
        sftp_free(sftp);
        return SSH_ERROR;
      }
      if(ret != towrite){
        printf("Asked to write %d, wrote %d\n",towrite,ret);
      }
      wrote += ret;
    }
    sftp_close(file);
  }
  sftp_free(sftp);
  return SSH_OK;
}
