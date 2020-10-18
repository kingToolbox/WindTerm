#include <stdio.h>

#include <libssh/libssh.h>
#include "examples_common.h"
#include <libssh/sftp.h>

int main(void) {
  ssh_session session;
  sftp_session sftp;
  char buffer[1024*1024];
  int rc;

  session = connect_ssh("localhost", NULL, 0);
  if (session == NULL) {
    return 1;
  }

  sftp=sftp_new(session);
  sftp_init(sftp);
  rc=sftp_rename(sftp,"/tmp/test","/tmp/test");
  rc=sftp_rename(sftp,"/tmp/test","/tmp/test");
  rc=sftp_chmod(sftp,"/tmp/test",0644);
  if (rc < 0) {
    printf("error : %s\n",ssh_get_error(sftp));

    ssh_disconnect(session);
    return 1;
  }

  ssh_disconnect(session);

  return 0;
}
