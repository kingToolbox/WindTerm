/* simple exec example */
#include <stdio.h>

#include <libssh/libssh.h>
#include "examples_common.h"

int main(void) {
    ssh_session session;
    ssh_channel channel;
    char buffer[256];
    int rbytes, wbytes, total = 0;
    int rc;

    session = connect_ssh("localhost", NULL, 0);
    if (session == NULL) {
        ssh_finalize();
        return 1;
    }

    channel = ssh_channel_new(session);;
    if (channel == NULL) {
        ssh_disconnect(session);
        ssh_free(session);
        ssh_finalize();
        return 1;
    }

    rc = ssh_channel_open_session(channel);
    if (rc < 0) {
        goto failed;
    }

    rc = ssh_channel_request_exec(channel, "lsof");
    if (rc < 0) {
        goto failed;
    }

    rbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    if (rbytes <= 0) {
        goto failed;
    }

    do {
        wbytes = fwrite(buffer + total, 1, rbytes, stdout);
        if (wbytes <= 0) {
            goto failed;
        }

        total += wbytes;

        /* When it was not possible to write the whole buffer to stdout */
        if (wbytes < rbytes) {
            rbytes -= wbytes;
            continue;
        }

        rbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        total = 0;
    } while (rbytes > 0);

    if (rbytes < 0) {
        goto failed;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    ssh_finalize();

    return 0;
failed:
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    ssh_finalize();

    return 1;
}
