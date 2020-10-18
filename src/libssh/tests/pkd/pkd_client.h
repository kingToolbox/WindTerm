/*
 * pkd_client.h -- macros for generating client-specific command
 *                 invocations for use with pkd testing
 *
 * (c) 2014, 2018 Jon Simons <jon@jonsimons.org>
 */

#ifndef __PKD_CLIENT_H__
#define __PKD_CLIENT_H__

#include "config.h"
#include "tests_config.h"

/* OpenSSH */

#define OPENSSH_BINARY SSH_EXECUTABLE
#define OPENSSH_KEYGEN "ssh-keygen"

#define OPENSSH_HOSTKEY_ALGOS \
  "-o HostKeyAlgorithms="        \
  OPENSSH_KEYS

#define OPENSSH_PKACCEPTED_TYPES \
  "-o PubkeyAcceptedKeyTypes="  \
  OPENSSH_KEYS

#define OPENSSH_CMD_START(hostkey_algos) \
    OPENSSH_BINARY " "                  \
    "-o UserKnownHostsFile=/dev/null "  \
    "-o StrictHostKeyChecking=no "      \
    "-F /dev/null "                     \
    hostkey_algos " "                   \
    OPENSSH_PKACCEPTED_TYPES " "        \
    "-i " CLIENT_ID_FILE " "            \
    "1> %s.out "                        \
    "2> %s.err "                        \
    "-vvv "

#define OPENSSH_CMD_END "-p 1234 localhost ls"

#define OPENSSH_CMD \
    OPENSSH_CMD_START(OPENSSH_HOSTKEY_ALGOS) OPENSSH_CMD_END

#define OPENSSH_KEX_CMD(kexalgo) \
    OPENSSH_CMD_START(OPENSSH_HOSTKEY_ALGOS) "-o KexAlgorithms=" kexalgo " " OPENSSH_CMD_END

#define OPENSSH_CIPHER_CMD(ciphers) \
    OPENSSH_CMD_START(OPENSSH_HOSTKEY_ALGOS) "-c " ciphers " " OPENSSH_CMD_END

#define OPENSSH_MAC_CMD(macs) \
    OPENSSH_CMD_START(OPENSSH_HOSTKEY_ALGOS) "-c aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,aes192-cbc,aes128-cbc -o MACs=" macs " " OPENSSH_CMD_END

#define OPENSSH_HOSTKEY_CMD(hostkeyalgo) \
    OPENSSH_CMD_START("-o HostKeyAlgorithms=" hostkeyalgo " ") OPENSSH_CMD_END

#define OPENSSH_CERT_CMD \
    OPENSSH_CMD_START(OPENSSH_HOSTKEY_ALGOS) "-o CertificateFile=" CLIENT_ID_FILE "-cert.pub " OPENSSH_CMD_END

#define OPENSSH_SHA256_CERT_CMD \
    OPENSSH_CMD_START(OPENSSH_HOSTKEY_ALGOS) "-o CertificateFile=" CLIENT_ID_FILE "-sha256-cert.pub " OPENSSH_CMD_END

/* Dropbear */

#define DROPBEAR_BINARY "dbclient"
#define DROPBEAR_KEYGEN "dropbearkey"

#define DROPBEAR_CMD_START \
    DROPBEAR_BINARY " "      \
    "-y -y "                 \
    "-i " CLIENT_ID_FILE " " \
    "1> %s.out "             \
    "2> %s.err "

#define DROPBEAR_CMD_END "-p 1234 localhost ls"

#define DROPBEAR_CMD \
    DROPBEAR_CMD_START DROPBEAR_CMD_END

#if 0 /* dbclient does not expose control over kex algo */
#define DROPBEAR_KEX_CMD(kexalgo) \
    DROPBEAR_CMD
#endif

#define DROPBEAR_CIPHER_CMD(ciphers) \
    DROPBEAR_CMD_START "-c " ciphers " " DROPBEAR_CMD_END

#define DROPBEAR_MAC_CMD(macs) \
    DROPBEAR_CMD_START "-m " macs " " DROPBEAR_CMD_END

#endif /* __PKD_CLIENT_H__ */
