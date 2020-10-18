/* libssh_scp.c
 * Sample implementation of a SCP client
 */

/*
Copyright 2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <libssh/libssh.h>
#include "examples_common.h"

static char **sources;
static int nsources;
static char *destination;
static int verbosity = 0;

struct location {
    int is_ssh;
    char *user;
    char *host;
    char *path;
    ssh_session session;
    ssh_scp scp;
    FILE *file;
};

enum {
    READ,
    WRITE
};

static void usage(const char *argv0) {
    fprintf(stderr, "Usage : %s [options] [[user@]host1:]file1 ... \n"
            "                               [[user@]host2:]destination\n"
            "sample scp client - libssh-%s\n",
            //      "Options :\n",
            //      "  -r : use RSA to verify host public key\n",
            argv0,
            ssh_version(0));
    exit(0);
}

static int opts(int argc, char **argv) {
    int i;

    while((i = getopt(argc, argv, "v")) != -1) {
        switch(i) {
        case 'v':
            verbosity++;
            break;
        default:
            fprintf(stderr, "unknown option %c\n", optopt);
            usage(argv[0]);
            return -1;
        }
    }

    nsources = argc - optind - 1;
    if (nsources < 1) {
        usage(argv[0]);
        return -1;
    }

    sources = malloc((nsources + 1) * sizeof(char *));
    if (sources == NULL) {
        return -1;
    }

    for(i = 0; i < nsources; ++i) {
        sources[i] = argv[optind];
        optind++;
    }

    sources[i] = NULL;
    destination = argv[optind];
    return 0;
}

static void location_free(struct location *loc)
{
    if (loc) {
        if (loc->path) {
            free(loc->path);
        }
        loc->path = NULL;
        if (loc->is_ssh) {
            if (loc->host) {
                free(loc->host);
            }
            loc->host = NULL;
            if (loc->user) {
                free(loc->user);
            }
            loc->user = NULL;
            if (loc->host) {
                free(loc->host);
            }
            loc->host = NULL;
        }
        free(loc);
    }
}

static struct location *parse_location(char *loc) {
    struct location *location;
    char *ptr;

    location = malloc(sizeof(struct location));
    if (location == NULL) {
        return NULL;
    }
    memset(location, 0, sizeof(struct location));

    location->host = location->user = NULL;
    ptr = strchr(loc, ':');

    if (ptr != NULL) {
        location->is_ssh = 1;
        location->path = strdup(ptr+1);
        *ptr = '\0';
        ptr = strchr(loc, '@');

        if (ptr != NULL) {
            location->host = strdup(ptr+1);
            *ptr = '\0';
            location->user = strdup(loc);
        } else {
            location->host = strdup(loc);
        }
    } else {
        location->is_ssh = 0;
        location->path = strdup(loc);
    }
    return location;
}

static void close_location(struct location *loc) {
    int rc;

    if (loc) {
        if (loc->is_ssh) {
            if (loc->scp) {
                rc = ssh_scp_close(loc->scp);
                if (rc == SSH_ERROR) {
                    fprintf(stderr,
                            "Error closing scp: %s\n",
                            ssh_get_error(loc->session));
                }
                ssh_scp_free(loc->scp);
                loc->scp = NULL;
            }
            if (loc->session) {
                ssh_disconnect(loc->session);
                ssh_free(loc->session);
                loc->session = NULL;
            }
        } else {
            if (loc->file) {
                fclose(loc->file);
                loc->file = NULL;
            }
        }
    }
}

static int open_location(struct location *loc, int flag) {
    if (loc->is_ssh && flag == WRITE) {
        loc->session = connect_ssh(loc->host, loc->user, verbosity);
        if (!loc->session) {
            fprintf(stderr, "Couldn't connect to %s\n", loc->host);
            return -1;
        }

        loc->scp = ssh_scp_new(loc->session, SSH_SCP_WRITE, loc->path);
        if (!loc->scp) {
            fprintf(stderr, "error : %s\n", ssh_get_error(loc->session));
            ssh_disconnect(loc->session);
            ssh_free(loc->session);
            loc->session = NULL;
            return -1;
        }

        if (ssh_scp_init(loc->scp) == SSH_ERROR) {
            fprintf(stderr, "error : %s\n", ssh_get_error(loc->session));
            ssh_scp_free(loc->scp);
            loc->scp = NULL;
            ssh_disconnect(loc->session);
            ssh_free(loc->session);
            loc->session = NULL;
            return -1;
        }
        return 0;
    } else if (loc->is_ssh && flag == READ) {
        loc->session = connect_ssh(loc->host, loc->user, verbosity);
        if (!loc->session) {
            fprintf(stderr, "Couldn't connect to %s\n", loc->host);
            return -1;
        }

        loc->scp = ssh_scp_new(loc->session, SSH_SCP_READ, loc->path);
        if (!loc->scp) {
            fprintf(stderr, "error : %s\n", ssh_get_error(loc->session));
            ssh_disconnect(loc->session);
            ssh_free(loc->session);
            loc->session = NULL;
            return -1;
        }

        if (ssh_scp_init(loc->scp) == SSH_ERROR) {
            fprintf(stderr, "error : %s\n", ssh_get_error(loc->session));
            ssh_scp_free(loc->scp);
            loc->scp = NULL;
            ssh_disconnect(loc->session);
            ssh_free(loc->session);
            loc->session = NULL;
            return -1;
        }
        return 0;
    } else {
        loc->file = fopen(loc->path, flag == READ ? "r":"w");
        if (!loc->file) {
            if (errno == EISDIR) {
                if (chdir(loc->path)) {
                    fprintf(stderr,
                            "Error changing directory to %s: %s\n",
                            loc->path, strerror(errno));
                    return -1;
                }
                return 0;
            }
            fprintf(stderr,
                    "Error opening %s: %s\n",
                    loc->path, strerror(errno));
            return -1;
        }
        return 0;
    }
    return -1;
}

/** @brief copies files from source location to destination
 * @param src source location
 * @param dest destination location
 * @param recursive Copy also directories
 */
static int do_copy(struct location *src, struct location *dest, int recursive) {
    size_t size;
    socket_t fd;
    struct stat s;
    int w, r;
    char buffer[16384];
    size_t total = 0;
    mode_t mode;
    char *filename = NULL;

    /* recursive mode doesn't work yet */
    (void)recursive;
    /* Get the file name and size*/
    if (!src->is_ssh) {
        fd = fileno(src->file);
        if (fd < 0) {
            fprintf(stderr,
                    "Invalid file pointer, error: %s\n",
                    strerror(errno));
            return -1;
        }
        r = fstat(fd, &s);
        if (r < 0) {
            return -1;
        }
        size = s.st_size;
        mode = s.st_mode & ~S_IFMT;
        filename = ssh_basename(src->path);
    } else {
        size = 0;
        do {
            r = ssh_scp_pull_request(src->scp);
            if (r == SSH_SCP_REQUEST_NEWDIR) {
                ssh_scp_deny_request(src->scp, "Not in recursive mode");
                continue;
            }
            if (r == SSH_SCP_REQUEST_NEWFILE) {
                size = ssh_scp_request_get_size(src->scp);
                filename = strdup(ssh_scp_request_get_filename(src->scp));
                mode = ssh_scp_request_get_permissions(src->scp);
                //ssh_scp_accept_request(src->scp);
                break;
            }
            if (r == SSH_ERROR) {
                fprintf(stderr,
                        "Error: %s\n",
                        ssh_get_error(src->session));
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }
        } while(r != SSH_SCP_REQUEST_NEWFILE);
    }

    if (dest->is_ssh) {
        r = ssh_scp_push_file(dest->scp, src->path, size, mode);
        //  snprintf(buffer, sizeof(buffer), "C0644 %d %s\n", size, src->path);
        if (r == SSH_ERROR) {
            fprintf(stderr,
                    "error: %s\n",
                    ssh_get_error(dest->session));
            SSH_STRING_FREE_CHAR(filename);
            ssh_scp_free(dest->scp);
            dest->scp = NULL;
            return -1;
        }
    } else {
        if (!dest->file) {
            dest->file = fopen(filename, "w");
            if (!dest->file) {
                fprintf(stderr,
                        "Cannot open %s for writing: %s\n",
                        filename, strerror(errno));
                if (src->is_ssh) {
                    ssh_scp_deny_request(src->scp, "Cannot open local file");
                }
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }
        }
        if (src->is_ssh) {
            ssh_scp_accept_request(src->scp);
        }
    }

    do {
        if (src->is_ssh) {
            r = ssh_scp_read(src->scp, buffer, sizeof(buffer));
            if (r == SSH_ERROR) {
                fprintf(stderr,
                        "Error reading scp: %s\n",
                        ssh_get_error(src->session));
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }

            if (r == 0) {
                break;
            }
        } else {
            r = fread(buffer, 1, sizeof(buffer), src->file);
            if (r == 0) {
                break;
            }

            if (r < 0) {
                fprintf(stderr,
                        "Error reading file: %s\n",
                        strerror(errno));
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }
        }

        if (dest->is_ssh) {
            w = ssh_scp_write(dest->scp, buffer, r);
            if (w == SSH_ERROR) {
                fprintf(stderr,
                        "Error writing in scp: %s\n",
                        ssh_get_error(dest->session));
                ssh_scp_free(dest->scp);
                dest->scp = NULL;
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }
        } else {
            w = fwrite(buffer, r, 1, dest->file);
            if (w <= 0) {
                fprintf(stderr,
                        "Error writing in local file: %s\n",
                        strerror(errno));
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }
        }
        total += r;

    } while(total < size);

    SSH_STRING_FREE_CHAR(filename);
    printf("wrote %zu bytes\n", total);
    return 0;
}

int main(int argc, char **argv) {
    struct location *dest, *src;
    int i;
    int r;
    if (opts(argc, argv) < 0) {
        r = EXIT_FAILURE;
        goto end;
    }

    dest = parse_location(destination);
    if (dest == NULL) {
        r = EXIT_FAILURE;
        goto end;
    }

    if (open_location(dest, WRITE) < 0) {
        location_free(dest);
        r = EXIT_FAILURE;
        goto end;
    }

    for (i = 0; i < nsources; ++i) {
        src = parse_location(sources[i]);
        if (src == NULL) {
            r = EXIT_FAILURE;
            goto close_dest;
        }

        if (open_location(src, READ) < 0) {
            location_free(src);
            r = EXIT_FAILURE;
            goto close_dest;
        }

        if (do_copy(src, dest, 0) < 0) {
            close_location(src);
            location_free(src);
            break;
        }

        close_location(src);
        location_free(src);
    }

    r = 0;

close_dest:
    close_location(dest);
    location_free(dest);
end:
    return r;
}
