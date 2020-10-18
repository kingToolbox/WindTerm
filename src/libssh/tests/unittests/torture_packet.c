#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/libssh.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/buffer.h"
#include "libssh/socket.h"
#include "libssh/callbacks.h"

#include "socket.c"

uint8_t test_data[]="AThis is test data. Use it to check the validity of packet functions"
                    "AThis is test data. Use it to check the validity of packet functions"
                    "AThis is test data. Use it to check the validity of packet functions"
                    "AThis is test data. Use it to check the validity of packet functions";
uint8_t key[]="iekaeshoa7ooCie2shai8shahngee3ONsee3xoishooj0ojei6aeChieth1iraPh";
uint8_t iv[]="eixaxughoomah4ui7Aew3ohxuolaifuu";
uint8_t mac[]="thook2Jai0ahmahyae7ChuuruoPhee8Y";

static uint8_t *copy_data(uint8_t *data, size_t len){
    uint8_t *ret = malloc(len);
    assert_non_null(ret);
    memcpy(ret, data, len);
    return ret;
}

static SSH_PACKET_CALLBACK(copy_packet_data){
    uint8_t *response = user;
    size_t len = ssh_buffer_get_len(packet);
    (void)type;
    (void)session;

    if(len > 1024){
        len = 1024;
    }
    ssh_buffer_get_data(packet, response, len);

    return 0;
}

static void
torture_packet(const char *cipher, const char *mac_type,
               const char *comp_type, size_t payload_len)
{
    ssh_session session = ssh_new();
    int verbosity = torture_libssh_verbosity();
    struct ssh_crypto_struct *crypto;
    struct ssh_cipher_struct *in_cipher;
    struct ssh_cipher_struct *out_cipher;
    int rc;
    int sockets[2];
    uint8_t buffer[1024];
    uint8_t response[1024];
    size_t encrypted_packet_len;
    ssh_packet_callback callbacks[]={copy_packet_data};
    struct ssh_packet_callbacks_struct cb = {
            .start='A',
            .n_callbacks=1,
            .callbacks=callbacks,
            .user=response
    };
    int cmp;

    assert_non_null(session);
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    crypto = session->next_crypto;

    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    assert_int_equal(rc, 0);

    crypto->kex_methods[SSH_KEX] = strdup("curve25519-sha256@libssh.org");
    crypto->kex_methods[SSH_HOSTKEYS] = strdup("ssh-rsa");
    crypto->kex_methods[SSH_CRYPT_C_S] = strdup(cipher);
    crypto->kex_methods[SSH_CRYPT_S_C] = strdup(cipher);
    crypto->kex_methods[SSH_MAC_C_S] = strdup(mac_type);
    crypto->kex_methods[SSH_MAC_S_C] = strdup(mac_type);
    crypto->kex_methods[SSH_COMP_C_S] = strdup(comp_type);
    crypto->kex_methods[SSH_COMP_S_C] = strdup(comp_type);
    crypto->kex_methods[SSH_LANG_C_S] = strdup("none");
    crypto->kex_methods[SSH_LANG_S_C] = strdup("none");
    rc = crypt_set_algorithms_client(session);
    assert_int_equal(rc, SSH_OK);
    session->current_crypto = session->next_crypto;
    session->next_crypto = crypto_new();
    crypto->encryptkey = copy_data(key, sizeof(key));
    crypto->decryptkey = copy_data(key, sizeof(key));
    crypto->encryptIV = copy_data(iv, sizeof(iv));
    crypto->decryptIV = copy_data(iv, sizeof(iv));
    crypto->encryptMAC = copy_data(mac, sizeof(mac));
    crypto->decryptMAC = copy_data(mac, sizeof(mac));

    in_cipher = session->current_crypto->in_cipher;
    rc = in_cipher->set_decrypt_key(in_cipher,
                                    session->current_crypto->decryptkey,
                                    session->current_crypto->decryptIV);
    assert_int_equal(rc, SSH_OK);

    out_cipher = session->current_crypto->out_cipher;
    rc = out_cipher->set_encrypt_key(out_cipher,
                                     session->current_crypto->encryptkey,
                                     session->current_crypto->encryptIV);
    session->current_crypto->used = SSH_DIRECTION_BOTH;
    assert_int_equal(rc, SSH_OK);

    assert_non_null(session->out_buffer);
    ssh_buffer_add_data(session->out_buffer, test_data, payload_len);
    session->socket->fd = sockets[0];
    session->socket->write_wontblock = 1;
    rc = ssh_packet_send(session);
    assert_int_equal(rc, SSH_OK);

    rc = recv(sockets[1], buffer, sizeof(buffer), 0);
    assert_true(rc > 0);
    encrypted_packet_len = rc;
    cmp = strcmp(comp_type, "none");
    if (cmp == 0) {
        assert_in_range(encrypted_packet_len,
                        payload_len + 4,
                        payload_len + (32 * 3));
    }
    rc = send(sockets[0], buffer, encrypted_packet_len, 0);
    assert_int_equal(rc, encrypted_packet_len);

    ssh_packet_set_callbacks(session, &cb);
    explicit_bzero(response, sizeof(response));
    rc = ssh_packet_socket_callback(buffer, encrypted_packet_len, session);
    assert_int_not_equal(rc, SSH_ERROR);
    if(payload_len > 0){
        assert_memory_equal(response, test_data+1, payload_len-1);
    }
    close(sockets[0]);
    close(sockets[1]);
    session->socket->fd = SSH_INVALID_SOCKET;
    ssh_free(session);
}

static void torture_packet_aes128_ctr_etm(UNUSED_PARAM(void **state))
{
    int i;
    for (i = 1; i < 256; ++i) {
        torture_packet("aes128-ctr", "hmac-sha1-etm@openssh.com", "none", i);
    }
}

static void torture_packet_aes192_ctr_etm(UNUSED_PARAM(void **state))
{
    int i;
    for (i = 1; i < 256; ++i) {
        torture_packet("aes192-ctr", "hmac-sha1-etm@openssh.com", "none", i);
    }
}

static void torture_packet_aes256_ctr_etm(UNUSED_PARAM(void **state))
{
    int i;
    for (i = 1; i < 256; ++i) {
        torture_packet("aes256-ctr", "hmac-sha1-etm@openssh.com", "none", i);
    }
}

static void torture_packet_aes128_ctr(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("aes128-ctr", "hmac-sha1", "none", i);
    }
}

static void torture_packet_aes192_ctr(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("aes192-ctr", "hmac-sha1", "none", i);
    }
}

static void torture_packet_aes256_ctr(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("aes256-ctr", "hmac-sha1", "none", i);
    }
}

static void torture_packet_aes128_cbc(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("aes128-cbc", "hmac-sha1", "none", i);
    }
}

static void torture_packet_aes192_cbc(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("aes192-cbc", "hmac-sha1", "none", i);
    }
}

static void torture_packet_aes256_cbc(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("aes256-cbc", "hmac-sha1", "none", i);
    }
}

static void torture_packet_aes128_cbc_etm(UNUSED_PARAM(void **state))
{
    int i;
    for (i = 1; i < 256; ++i) {
        torture_packet("aes128-cbc", "hmac-sha1-etm@openssh.com", "none", i);
    }
}

static void torture_packet_aes192_cbc_etm(UNUSED_PARAM(void **state))
{
    int i;
    for (i = 1; i < 256; ++i) {
        torture_packet("aes192-cbc", "hmac-sha1-etm@openssh.com", "none", i);
    }
}

static void torture_packet_aes256_cbc_etm(UNUSED_PARAM(void **state))
{
    int i;
    for (i = 1; i < 256; ++i) {
        torture_packet("aes256-cbc", "hmac-sha1-etm@openssh.com", "none", i);
    }
}

static void torture_packet_3des_cbc(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("3des-cbc", "hmac-sha1", "none", i);
    }
}

static void torture_packet_3des_cbc_etm(UNUSED_PARAM(void **state))
{
    int i;
    for (i = 1; i < 256; ++i) {
        torture_packet("3des-cbc", "hmac-sha1-etm@openssh.com", "none", i);
    }
}

static void torture_packet_chacha20(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("chacha20-poly1305@openssh.com", "none", "none", i);
    }
}

static void torture_packet_aes128_gcm(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("aes128-gcm@openssh.com", "none", "none", i);
    }
}

static void torture_packet_aes256_gcm(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("aes256-gcm@openssh.com", "none", "none", i);
    }
}

static void torture_packet_compress_zlib(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("aes256-ctr", "hmac-sha1", "zlib", i);
    }
}

static void torture_packet_compress_zlib_openssh(void **state)
{
    int i;
    (void)state; /* unused */
    for (i=1;i<256;++i){
        torture_packet("aes256-ctr", "hmac-sha1", "zlib@openssh.com", i);
    }
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_packet_aes128_ctr),
        cmocka_unit_test(torture_packet_aes192_ctr),
        cmocka_unit_test(torture_packet_aes256_ctr),
        cmocka_unit_test(torture_packet_aes128_ctr_etm),
        cmocka_unit_test(torture_packet_aes192_ctr_etm),
        cmocka_unit_test(torture_packet_aes256_ctr_etm),
        cmocka_unit_test(torture_packet_aes128_cbc),
        cmocka_unit_test(torture_packet_aes192_cbc),
        cmocka_unit_test(torture_packet_aes256_cbc),
        cmocka_unit_test(torture_packet_aes128_cbc_etm),
        cmocka_unit_test(torture_packet_aes192_cbc_etm),
        cmocka_unit_test(torture_packet_aes256_cbc_etm),
        cmocka_unit_test(torture_packet_3des_cbc),
        cmocka_unit_test(torture_packet_3des_cbc_etm),
        cmocka_unit_test(torture_packet_chacha20),
        cmocka_unit_test(torture_packet_aes128_gcm),
        cmocka_unit_test(torture_packet_aes256_gcm),
        cmocka_unit_test(torture_packet_compress_zlib),
        cmocka_unit_test(torture_packet_compress_zlib_openssh),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
