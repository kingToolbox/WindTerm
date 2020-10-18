/* Test the ability to use ssh_bind_accept_fd.
 *
 * Expected behavior: Prints "SUCCESS!"
 *
 * Faulty behavior observed before change: Connection timeout
 */

#include <arpa/inet.h>
#include <err.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

struct options {
  const char *server_keyfile;
} options;

const char HOST[] = "127.0.0.1";
const int PORT = 3333;

int get_connection() {
  int rc, server_socket, client_conn = -1;
  struct sockaddr_in server_socket_addr;
  struct sockaddr_storage client_conn_addr;
  socklen_t client_conn_addr_size = sizeof(client_conn_addr);

  server_socket = socket(PF_INET, SOCK_STREAM, 0);
  if (server_socket < 0) {
    goto out;
  }

  server_socket_addr.sin_family = AF_INET;
  server_socket_addr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, HOST, &server_socket_addr.sin_addr) != 1) {
    goto out;
  }

  rc = bind(server_socket, (struct sockaddr *)&server_socket_addr,
            sizeof(server_socket_addr));
  if (rc < 0) {
    goto out;
  }

  if (listen(server_socket, 0) < 0) {
    goto out;
  }

  client_conn = accept(server_socket,
                       (struct sockaddr *)&client_conn_addr,
                       &client_conn_addr_size);

 out:
  return client_conn;
}

void ssh_server() {
  ssh_bind bind;
  ssh_session session;

  int client_conn = get_connection();
  if (client_conn < 0) {
    err(1, "get_connection");
  }

  bind = ssh_bind_new();
  if (!bind) {
    errx(1, "ssh_bind_new");
  }

#ifdef HAVE_DSA
  /*TODO mbedtls this is probably required */
  if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_DSAKEY,
                           options.server_keyfile) != SSH_OK) {
    errx(1, "ssh_bind_options_set(SSH_BIND_OPTIONS_DSAKEY");
  }
#else
  if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSAKEY,
                           options.server_keyfile) != SSH_OK) {
    errx(1, "ssh_bind_options_set(SSH_BIND_OPTIONS_RSAKEY");
  }
#endif

  session = ssh_new();
  if (!session) {
    errx(1, "ssh_new");
  }

  if (ssh_bind_accept_fd(bind, session, client_conn) != SSH_OK) {
    errx(1, "ssh_bind_accept: %s", ssh_get_error(bind));
  }

  if (ssh_handle_key_exchange(session) != SSH_OK) {
    errx(1, "ssh_handle_key_exchange: %s", ssh_get_error(session));
  }

  printf("SUCCESS!\n");
}

void ssh_client() {
  ssh_session session;

  session = ssh_new();
  if (!session) {
    errx(1, "ssh_new");
  }

  if (ssh_options_set(session, SSH_OPTIONS_HOST, HOST) < 0) {
    errx(1, "ssh_options_set(SSH_OPTIONS_HOST)");
  }
  if (ssh_options_set(session, SSH_OPTIONS_PORT, &PORT) < 0) {
    errx(1, "ssh_options_set(SSH_OPTIONS_PORT)");
  }

  if (ssh_connect(session) != SSH_OK) {
    errx(1, "ssh_connect: %s", ssh_get_error(session));
  }
}

int main(int argc, const char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <private key file>\n", argv[0]);
    exit(1);
  }

  options.server_keyfile = argv[1];

  pid_t pid = fork();
  if (pid < 0) {
    errx(1, "fork");
  }
  if (pid == 0) {
    /* Allow the server to get set up */
    sleep(3);

    ssh_client();
  } else {
    ssh_server();
  }

  return 0;
}
