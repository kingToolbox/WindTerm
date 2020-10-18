/* ssh_client.c */

/*
 * Copyright 2003-2015 Aris Adamantiadis
 *
 * This file is part of the SSH Library
 *
 * You are free to copy this file, modify it in any way, consider it being public
 * domain. This does not apply to the rest of the library though, but it is
 * allowed to cut-and-paste working code from this file to any license of
 * program.
 * The goal is to show the API in action. It's not a reference on how terminal
 * clients must be made or how a client should react.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/select.h>
#include <sys/time.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif

#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>


#include "examples_common.h"
#define MAXCMD 10

static char *host;
static char *user;
static char *cmds[MAXCMD];
static struct termios terminal;

static char *pcap_file = NULL;

static char *proxycommand;

static int auth_callback(const char *prompt,
                         char *buf,
                         size_t len,
                         int echo,
                         int verify,
                         void *userdata)
{
    (void) verify;
    (void) userdata;

    return ssh_getpass(prompt, buf, len, echo, verify);
}

struct ssh_callbacks_struct cb = {
    .auth_function = auth_callback,
    .userdata = NULL,
};

static void add_cmd(char *cmd)
{
    int n;

    for (n = 0; (n < MAXCMD) && cmds[n] != NULL; n++);

    if (n == MAXCMD) {
        return;
    }

    cmds[n] = strdup(cmd);
}

static void usage(void)
{
    fprintf(stderr,
            "Usage : ssh [options] [login@]hostname\n"
            "sample client - libssh-%s\n"
            "Options :\n"
            "  -l user : log in as user\n"
            "  -p port : connect to port\n"
            "  -d : use DSS to verify host public key\n"
            "  -r : use RSA to verify host public key\n"
#ifdef WITH_PCAP
            "  -P file : create a pcap debugging file\n"
#endif
#ifndef _WIN32
            "  -T proxycommand : command to execute as a socket proxy\n"
#endif
            "\n",
            ssh_version(0));

    exit(0);
}

static int opts(int argc, char **argv)
{
    int i;

    while((i = getopt(argc,argv,"T:P:")) != -1) {
        switch(i){
        case 'P':
            pcap_file = optarg;
            break;
#ifndef _WIN32
        case 'T':
            proxycommand = optarg;
            break;
#endif
        default:
            fprintf(stderr, "Unknown option %c\n", optopt);
            usage();
        }
    }
    if (optind < argc) {
        host = argv[optind++];
    }

    while(optind < argc) {
        add_cmd(argv[optind++]);
    }

    if (host == NULL) {
        usage();
    }

    return 0;
}

#ifndef HAVE_CFMAKERAW
static void cfmakeraw(struct termios *termios_p)
{
    termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    termios_p->c_oflag &= ~OPOST;
    termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    termios_p->c_cflag &= ~(CSIZE|PARENB);
    termios_p->c_cflag |= CS8;
}
#endif


static void do_cleanup(int i)
{
  /* unused variable */
  (void) i;

  tcsetattr(0, TCSANOW, &terminal);
}

static void do_exit(int i)
{
    /* unused variable */
    (void) i;

    do_cleanup(0);
    exit(0);
}

static ssh_channel chan;
static int signal_delayed = 0;

static void sigwindowchanged(int i)
{
    (void) i;
    signal_delayed = 1;
}

static void setsignal(void)
{
    signal(SIGWINCH, sigwindowchanged);
    signal_delayed = 0;
}

static void sizechanged(void)
{
    struct winsize win = {
        .ws_row = 0,
    };

    ioctl(1, TIOCGWINSZ, &win);
    ssh_channel_change_pty_size(chan,win.ws_col, win.ws_row);
    setsignal();
}

static void select_loop(ssh_session session,ssh_channel channel)
{
    ssh_connector connector_in, connector_out, connector_err;
    int rc;

    ssh_event event = ssh_event_new();

    /* stdin */
    connector_in = ssh_connector_new(session);
    ssh_connector_set_out_channel(connector_in, channel, SSH_CONNECTOR_STDINOUT);
    ssh_connector_set_in_fd(connector_in, 0);
    ssh_event_add_connector(event, connector_in);

    /* stdout */
    connector_out = ssh_connector_new(session);
    ssh_connector_set_out_fd(connector_out, 1);
    ssh_connector_set_in_channel(connector_out, channel, SSH_CONNECTOR_STDINOUT);
    ssh_event_add_connector(event, connector_out);

    /* stderr */
    connector_err = ssh_connector_new(session);
    ssh_connector_set_out_fd(connector_err, 2);
    ssh_connector_set_in_channel(connector_err, channel, SSH_CONNECTOR_STDERR);
    ssh_event_add_connector(event, connector_err);

    while (ssh_channel_is_open(channel)) {
        if (signal_delayed) {
            sizechanged();
        }
        rc = ssh_event_dopoll(event, 60000);
        if (rc == SSH_ERROR) {
            fprintf(stderr, "Error in ssh_event_dopoll()\n");
            break;
        }
    }
    ssh_event_remove_connector(event, connector_in);
    ssh_event_remove_connector(event, connector_out);
    ssh_event_remove_connector(event, connector_err);

    ssh_connector_free(connector_in);
    ssh_connector_free(connector_out);
    ssh_connector_free(connector_err);

    ssh_event_free(event);
}

static void shell(ssh_session session)
{
    ssh_channel channel;
    struct termios terminal_local;
    int interactive=isatty(0);

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        return;
    }

    if (interactive) {
        tcgetattr(0, &terminal_local);
        memcpy(&terminal, &terminal_local, sizeof(struct termios));
    }

    if (ssh_channel_open_session(channel)) {
        printf("Error opening channel : %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }
    chan = channel;
    if (interactive) {
        ssh_channel_request_pty(channel);
        sizechanged();
    }

    if (ssh_channel_request_shell(channel)) {
        printf("Requesting shell : %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }

    if (interactive) {
        cfmakeraw(&terminal_local);
        tcsetattr(0, TCSANOW, &terminal_local);
        setsignal();
    }
    signal(SIGTERM, do_cleanup);
    select_loop(session, channel);
    if (interactive) {
        do_cleanup(0);
    }
    ssh_channel_free(channel);
}

static void batch_shell(ssh_session session)
{
    ssh_channel channel;
    char buffer[1024];
    size_t i;
    int s = 0;

    for (i = 0; i < MAXCMD && cmds[i]; ++i) {
        s += snprintf(buffer + s, sizeof(buffer) - s, "%s ", cmds[i]);
        free(cmds[i]);
        cmds[i] = NULL;
    }

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        return;
    }

    ssh_channel_open_session(channel);
    if (ssh_channel_request_exec(channel, buffer)) {
        printf("Error executing '%s' : %s\n", buffer, ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }
    select_loop(session, channel);
    ssh_channel_free(channel);
}

static int client(ssh_session session)
{
    int auth = 0;
    char *banner;
    int state;

    if (user) {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
            return -1;
        }
    }
    if (ssh_options_set(session, SSH_OPTIONS_HOST ,host) < 0) {
        return -1;
    }
    if (proxycommand != NULL) {
        if (ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, proxycommand)) {
            return -1;
        }
    }
    ssh_options_parse_config(session, NULL);

    if (ssh_connect(session)) {
        fprintf(stderr, "Connection failed : %s\n", ssh_get_error(session));
        return -1;
    }

    state = verify_knownhost(session);
    if (state != 0) {
        return -1;
    }

    ssh_userauth_none(session, NULL);
    banner = ssh_get_issue_banner(session);
    if (banner) {
        printf("%s\n", banner);
        free(banner);
    }
    auth = authenticate_console(session);
    if (auth != SSH_AUTH_SUCCESS) {
        return -1;
    }
    if (cmds[0] == NULL) {
        shell(session);
    } else {
        batch_shell(session);
    }

    return 0;
}

static ssh_pcap_file pcap;
static void set_pcap(ssh_session session)
{
    if (pcap_file == NULL) {
        return;
    }

    pcap = ssh_pcap_file_new();
    if (pcap == NULL) {
        return;
    }

    if (ssh_pcap_file_open(pcap, pcap_file) == SSH_ERROR) {
        printf("Error opening pcap file\n");
        ssh_pcap_file_free(pcap);
        pcap = NULL;
        return;
    }
    ssh_set_pcap_file(session, pcap);
}

static void cleanup_pcap(void)
{
    if (pcap != NULL) {
        ssh_pcap_file_free(pcap);
    }
    pcap = NULL;
}

int main(int argc, char **argv)
{
    ssh_session session;

    session = ssh_new();

    ssh_callbacks_init(&cb);
    ssh_set_callbacks(session,&cb);

    if (ssh_options_getopt(session, &argc, argv)) {
        fprintf(stderr,
                "Error parsing command line: %s\n",
                ssh_get_error(session));
        usage();
    }
    opts(argc, argv);
    signal(SIGTERM, do_exit);

    set_pcap(session);
    client(session);

    ssh_disconnect(session);
    ssh_free(session);
    cleanup_pcap();

    ssh_finalize();

    return 0;
}
