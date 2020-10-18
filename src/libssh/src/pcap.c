/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
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

/* pcap.c */
#include "config.h"
#ifdef WITH_PCAP

#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#include <errno.h>
#include <stdlib.h>

#include "libssh/libssh.h"
#include "libssh/pcap.h"
#include "libssh/session.h"
#include "libssh/buffer.h"
#include "libssh/socket.h"

/**
 * @internal
 *
 * @defgroup libssh_pcap The libssh pcap functions
 * @ingroup libssh
 *
 * The pcap file generation
 *
 *
 * @{
 */

/* The header of a pcap file is the following. We are not going to make it
 * very complicated.
 * Just for information.
 */
struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t   thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
};

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define DLT_RAW         12      /* raw IP */

/* TCP flags */
#define TH_FIN        0x01
#define TH_SYN        0x02
#define TH_RST        0x04
#define TH_PUSH       0x08
#define TH_ACK        0x10
#define TH_URG        0x20

/* The header of a pcap packet.
 * Just for information.
 */
struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
};

/** @private
 * @brief a pcap context expresses the state of a pcap dump
 * in a SSH session only. Multiple pcap contexts may be used into
 * a single pcap file.
 */

struct ssh_pcap_context_struct {
	ssh_session session;
	ssh_pcap_file file;
	int connected;
	/* All of these information are useful to generate
	 * the dummy IP and TCP packets
	 */
	uint32_t ipsource;
	uint32_t ipdest;
	uint16_t portsource;
	uint16_t portdest;
	uint32_t outsequence;
	uint32_t insequence;
};

/** @private
 * @brief a pcap file expresses the state of a pcap file which may
 * contain several streams.
 */
struct ssh_pcap_file_struct {
	FILE *output;
	uint16_t ipsequence;
};

/**
 * @brief create a new ssh_pcap_file object
 */
ssh_pcap_file ssh_pcap_file_new(void) {
    struct ssh_pcap_file_struct *pcap;

    pcap = (struct ssh_pcap_file_struct *) malloc(sizeof(struct ssh_pcap_file_struct));
    if (pcap == NULL) {
        return NULL;
    }
    ZERO_STRUCTP(pcap);

    return pcap;
}

/** @internal
 * @brief writes a packet on file
 */
static int ssh_pcap_file_write(ssh_pcap_file pcap, ssh_buffer packet){
	int err;
	uint32_t len;
	if(pcap == NULL || pcap->output==NULL)
		return SSH_ERROR;
	len=ssh_buffer_get_len(packet);
	err=fwrite(ssh_buffer_get(packet),len,1,pcap->output);
	if(err<0)
		return SSH_ERROR;
	else
		return SSH_OK;
}

/** @internal
 * @brief prepends a packet with the pcap header and writes packet
 * on file
 */
int ssh_pcap_file_write_packet(ssh_pcap_file pcap, ssh_buffer packet, uint32_t original_len){
	ssh_buffer header=ssh_buffer_new();
	struct timeval now;
	int err;
	if(header == NULL)
		return SSH_ERROR;
	gettimeofday(&now,NULL);
    err = ssh_buffer_allocate_size(header,
                                   sizeof(uint32_t) * 4 +
                                   ssh_buffer_get_len(packet));
    if (err < 0) {
        goto error;
    }
    err = ssh_buffer_add_u32(header,htonl(now.tv_sec));
    if (err < 0) {
        goto error;
    }
    err = ssh_buffer_add_u32(header,htonl(now.tv_usec));
    if (err < 0) {
        goto error;
    }
    err = ssh_buffer_add_u32(header,htonl(ssh_buffer_get_len(packet)));
    if (err < 0) {
        goto error;
    }
    err = ssh_buffer_add_u32(header,htonl(original_len));
    if (err < 0) {
        goto error;
    }
    err = ssh_buffer_add_buffer(header,packet);
    if (err < 0) {
        goto error;
    }
	err=ssh_pcap_file_write(pcap,header);
error:
	SSH_BUFFER_FREE(header);
	return err;
}

/**
 * @brief opens a new pcap file and create header
 */
int ssh_pcap_file_open(ssh_pcap_file pcap, const char *filename){
	ssh_buffer header;
	int err;
	if(pcap == NULL)
		return SSH_ERROR;
	if(pcap->output){
		fclose(pcap->output);
		pcap->output=NULL;
	}
	pcap->output=fopen(filename,"wb");
	if(pcap->output==NULL)
		return SSH_ERROR;
	header=ssh_buffer_new();
	if(header==NULL)
		return SSH_ERROR;
    err = ssh_buffer_allocate_size(header,
                                   sizeof(uint32_t) * 5 +
                                   sizeof(uint16_t) * 2);
    if (err < 0) {
        goto error;
    }
    err = ssh_buffer_add_u32(header,htonl(PCAP_MAGIC));
    if (err < 0) {
        goto error;
    }
    err = ssh_buffer_add_u16(header,htons(PCAP_VERSION_MAJOR));
    if (err < 0) {
        goto error;
    }
    err = ssh_buffer_add_u16(header,htons(PCAP_VERSION_MINOR));
    if (err < 0) {
        goto error;
    }
	/* currently hardcode GMT to 0 */
    err = ssh_buffer_add_u32(header,htonl(0));
    if (err < 0) {
        goto error;
    }
	/* accuracy */
    err = ssh_buffer_add_u32(header,htonl(0));
    if (err < 0) {
        goto error;
    }
	/* size of the biggest packet */
    err = ssh_buffer_add_u32(header,htonl(MAX_PACKET_LEN));
    if (err < 0) {
        goto error;
    }
	/* we will write sort-of IP */
    err = ssh_buffer_add_u32(header,htonl(DLT_RAW));
    if (err < 0) {
        goto error;
    }
	err=ssh_pcap_file_write(pcap,header);
error:
	SSH_BUFFER_FREE(header);
	return err;
}

int ssh_pcap_file_close(ssh_pcap_file pcap){
	int err;
	if(pcap ==NULL || pcap->output==NULL)
		return SSH_ERROR;
	err=fclose(pcap->output);
	pcap->output=NULL;
	if(err != 0)
		return SSH_ERROR;
	else
		return SSH_OK;
}

void ssh_pcap_file_free(ssh_pcap_file pcap){
	ssh_pcap_file_close(pcap);
	SAFE_FREE(pcap);
}


/** @internal
 * @brief allocates a new ssh_pcap_context object
 */

ssh_pcap_context ssh_pcap_context_new(ssh_session session){
	ssh_pcap_context ctx = (struct ssh_pcap_context_struct *) malloc(sizeof(struct ssh_pcap_context_struct));
	if(ctx==NULL){
		ssh_set_error_oom(session);
		return NULL;
	}
	ZERO_STRUCTP(ctx);
	ctx->session=session;
	return ctx;
}

void ssh_pcap_context_free(ssh_pcap_context ctx){
	SAFE_FREE(ctx);
}

void ssh_pcap_context_set_file(ssh_pcap_context ctx, ssh_pcap_file pcap){
	ctx->file=pcap;
}

/** @internal
 * @brief sets the IP and port parameters in the connection
 */
static int ssh_pcap_context_connect(ssh_pcap_context ctx)
{
    ssh_session session=ctx->session;
    struct sockaddr_in local = {
        .sin_family = AF_UNSPEC,
    };
    struct sockaddr_in remote = {
        .sin_family = AF_UNSPEC,
    };
    socket_t fd;
    socklen_t len;
    int rc;

    if (session == NULL) {
        return SSH_ERROR;
    }

    if (session->socket == NULL) {
        return SSH_ERROR;
    }

    fd = ssh_socket_get_fd(session->socket);

    /* TODO: adapt for windows */
    if (fd < 0) {
        return SSH_ERROR;
    }

    len = sizeof(local);
    rc = getsockname(fd, (struct sockaddr *)&local, &len);
    if (rc < 0) {
        ssh_set_error(session,
                      SSH_REQUEST_DENIED,
                      "Getting local IP address: %s",
                      strerror(errno));
        return SSH_ERROR;
    }

    len = sizeof(remote);
    rc = getpeername(fd, (struct sockaddr *)&remote, &len);
    if (rc < 0) {
        ssh_set_error(session,
                      SSH_REQUEST_DENIED,
                      "Getting remote IP address: %s",
                      strerror(errno));
        return SSH_ERROR;
    }

    if (local.sin_family != AF_INET) {
        ssh_set_error(session,
                      SSH_REQUEST_DENIED,
                      "Only IPv4 supported for pcap logging");
        return SSH_ERROR;
    }

    memcpy(&ctx->ipsource, &local.sin_addr, sizeof(ctx->ipsource));
    memcpy(&ctx->ipdest, &remote.sin_addr, sizeof(ctx->ipdest));
    memcpy(&ctx->portsource, &local.sin_port, sizeof(ctx->portsource));
    memcpy(&ctx->portdest, &remote.sin_port, sizeof(ctx->portdest));

    ctx->connected = 1;
    return SSH_OK;
}

#define IPHDR_LEN 20
#define TCPHDR_LEN 20
#define TCPIPHDR_LEN (IPHDR_LEN + TCPHDR_LEN)
/** @internal
 * @brief write a SSH packet as a TCP over IP in a pcap file
 * @param ctx open pcap context
 * @param direction SSH_PCAP_DIRECTION_IN if the packet has been received
 * @param direction SSH_PCAP_DIRECTION_OUT if the packet has been emitted
 * @param data pointer to the data to write
 * @param len data to write in the pcap file. May be smaller than origlen.
 * @param origlen number of bytes of complete data.
 * @returns SSH_OK write is successful
 * @returns SSH_ERROR an error happened.
 */
int ssh_pcap_context_write(ssh_pcap_context ctx,
                           enum ssh_pcap_direction direction,
		           void *data,
                           uint32_t len,
                           uint32_t origlen)
{
    ssh_buffer ip;
    int rc;

    if (ctx == NULL || ctx->file == NULL) {
        return SSH_ERROR;
    }
    if (ctx->connected == 0) {
        if (ssh_pcap_context_connect(ctx) == SSH_ERROR) {
            return SSH_ERROR;
        }
    }
    ip = ssh_buffer_new();
    if (ip == NULL) {
        ssh_set_error_oom(ctx->session);
        return SSH_ERROR;
    }

    /* build an IP packet */
    rc = ssh_buffer_pack(ip,
                         "bbwwwbbw",
                         4 << 4 | 5, /* V4, 20 bytes */
                         0,          /* tos */
                         origlen + TCPIPHDR_LEN, /* total len */
                         ctx->file->ipsequence,  /* IP id number */
                         0,          /* fragment offset */
                         64,         /* TTL */
                         6,          /* protocol TCP=6 */
                         0);         /* checksum */

    ctx->file->ipsequence++;
    if (rc != SSH_OK){
        goto error;
    }
    if (direction == SSH_PCAP_DIR_OUT) {
        rc = ssh_buffer_add_u32(ip, ctx->ipsource);
        if (rc < 0) {
            goto error;
        }
        rc = ssh_buffer_add_u32(ip, ctx->ipdest);
        if (rc < 0) {
            goto error;
        }
    } else {
        rc = ssh_buffer_add_u32(ip, ctx->ipdest);
        if (rc < 0) {
            goto error;
        }
        rc = ssh_buffer_add_u32(ip, ctx->ipsource);
        if (rc < 0) {
            goto error;
        }
    }
    /* TCP */
    if (direction == SSH_PCAP_DIR_OUT) {
        rc = ssh_buffer_add_u16(ip, ctx->portsource);
        if (rc < 0) {
            goto error;
        }
        rc = ssh_buffer_add_u16(ip, ctx->portdest);
        if (rc < 0) {
            goto error;
        }
    } else {
        rc = ssh_buffer_add_u16(ip, ctx->portdest);
        if (rc < 0) {
            goto error;
        }
        rc = ssh_buffer_add_u16(ip, ctx->portsource);
        if (rc < 0) {
            goto error;
        }
    }
    /* sequence number */
    if (direction == SSH_PCAP_DIR_OUT) {
        rc = ssh_buffer_pack(ip, "d", ctx->outsequence);
        if (rc != SSH_OK) {
            goto error;
        }
        ctx->outsequence += origlen;
    } else {
        rc = ssh_buffer_pack(ip, "d", ctx->insequence);
        if (rc != SSH_OK) {
            goto error;
        }
        ctx->insequence += origlen;
    }
    /* ack number */
    if (direction == SSH_PCAP_DIR_OUT) {
        rc = ssh_buffer_pack(ip, "d", ctx->insequence);
        if (rc != SSH_OK) {
            goto error;
        }
    } else {
        rc = ssh_buffer_pack(ip, "d", ctx->outsequence);
        if (rc != SSH_OK) {
            goto error;
        }
    }

    rc = ssh_buffer_pack(ip,
                         "bbwwwP",
                         5 << 4,             /* header len = 20 = 5 * 32 bits, at offset 4*/
                         TH_PUSH | TH_ACK,   /* flags */
                         65535,              /* window */
                         0,                  /* checksum */
                         0,                  /* urgent data ptr */
                         (size_t)len, data); /* actual data */
    if (rc != SSH_OK) {
        goto error;
    }
    rc = ssh_pcap_file_write_packet(ctx->file, ip, origlen + TCPIPHDR_LEN);

error:
    SSH_BUFFER_FREE(ip);
    return rc;
}

/** @brief sets the pcap file used to trace the session
 * @param current session
 * @param pcap an handler to a pcap file. A pcap file may be used in several
 * sessions.
 * @returns SSH_ERROR in case of error, SSH_OK otherwise.
 */
int ssh_set_pcap_file(ssh_session session, ssh_pcap_file pcap){
	ssh_pcap_context ctx=ssh_pcap_context_new(session);
	if(ctx==NULL){
		ssh_set_error_oom(session);
		return SSH_ERROR;
	}
	ctx->file=pcap;
	if(session->pcap_ctx)
		ssh_pcap_context_free(session->pcap_ctx);
	session->pcap_ctx=ctx;
	return SSH_OK;
}


#else /* WITH_PCAP */

/* Simple stub returning errors when no pcap compiled in */

#include "libssh/libssh.h"
#include "libssh/priv.h"

int ssh_pcap_file_close(ssh_pcap_file pcap){
	(void) pcap;
	return SSH_ERROR;
}

void ssh_pcap_file_free(ssh_pcap_file pcap){
	(void) pcap;
}

ssh_pcap_file ssh_pcap_file_new(void){
	return NULL;
}
int ssh_pcap_file_open(ssh_pcap_file pcap, const char *filename){
	(void) pcap;
	(void) filename;
	return SSH_ERROR;
}

int ssh_set_pcap_file(ssh_session session, ssh_pcap_file pcapfile){
	(void) pcapfile;
	ssh_set_error(session,SSH_REQUEST_DENIED,"Pcap support not compiled in");
	return SSH_ERROR;
}

#endif

/** @} */
