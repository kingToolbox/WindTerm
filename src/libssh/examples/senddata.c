#include <stdio.h>

#include <libssh/libssh.h>
#include "examples_common.h"

#define LIMIT 0x100000000UL

int main(void) {
  ssh_session session;
  ssh_channel channel;
  char buffer[1024*1024];
  int rc;
  uint64_t total=0;
  uint64_t lastshown=4096;
  session = connect_ssh("localhost", NULL, 0);
  if (session == NULL) {
    return 1;
  }

  channel = ssh_channel_new(session);;
  if (channel == NULL) {
    ssh_disconnect(session);
    return 1;
  }

  rc = ssh_channel_open_session(channel);
  if (rc < 0) {
    ssh_channel_close(channel);
    ssh_disconnect(session);
    return 1;
  }

  rc = ssh_channel_request_exec(channel, "cat > /dev/null");
  if (rc < 0) {
    ssh_channel_close(channel);
    ssh_disconnect(session);
    return 1;
  }


  while ((rc = ssh_channel_write(channel, buffer, sizeof(buffer))) > 0) {
    total += rc;
    if(total/2 >= lastshown){
      printf("written %llx\n", (long long unsigned int) total);
      lastshown=total;
    }
    if(total > LIMIT)
      break;
  }
    
  if (rc < 0) {
    printf("error : %s\n",ssh_get_error(session));
    ssh_channel_close(channel);
    ssh_disconnect(session);
    return 1;
  }

  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);

  ssh_disconnect(session);

  return 0;
}
