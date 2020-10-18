#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#define DEBUG_BUFFER
#include "buffer.c"

#define LIMIT (8*1024*1024)

static int setup(void **state) {
    ssh_buffer buffer;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        return -1;
    }
    ssh_buffer_set_secure(buffer);
    *state = (void *) buffer;

    return 0;
}

static int teardown(void **state) {
    SSH_BUFFER_FREE(*state);

    return 0;
}

/*
 * Test if the continuously growing buffer size never exceeds 2 time its
 * real capacity
 */
static void torture_growing_buffer(void **state) {
  ssh_buffer buffer = *state;
  int i;

  for(i=0;i<LIMIT;++i){
    ssh_buffer_add_data(buffer,"A",1);
    if(buffer->used >= 128){
      if(ssh_buffer_get_len(buffer) * 2 < buffer->allocated){
        assert_true(ssh_buffer_get_len(buffer) * 2 >= buffer->allocated);
      }
    }
  }
}

/*
 * Test if the continuously growing buffer size never exceeds 2 time its
 * real capacity, when we remove 1 byte after each call (sliding window)
 */
static void torture_growing_buffer_shifting(void **state) {
  ssh_buffer buffer = *state;
  int i;
  unsigned char c;
  for(i=0; i<1024;++i){
    ssh_buffer_add_data(buffer,"S",1);
  }
  for(i=0;i<LIMIT;++i){
    ssh_buffer_get_u8(buffer,&c);
    ssh_buffer_add_data(buffer,"A",1);
    if(buffer->used >= 128){
      if(ssh_buffer_get_len(buffer) * 4 < buffer->allocated){
        assert_true(ssh_buffer_get_len(buffer) * 4 >= buffer->allocated);
        return;
      }
    }
  }
}

/*
 * Test the behavior of ssh_buffer_prepend_data
 */
static void torture_buffer_prepend(void **state) {
  ssh_buffer buffer = *state;
  uint32_t v;
  ssh_buffer_add_data(buffer,"abcdef",6);
  ssh_buffer_prepend_data(buffer,"xyz",3);
  assert_int_equal(ssh_buffer_get_len(buffer),9);
  assert_memory_equal(ssh_buffer_get(buffer),  "xyzabcdef", 9);

  /* Now remove 4 bytes and see if we can replace them */
  ssh_buffer_get_u32(buffer,&v);
  assert_int_equal(ssh_buffer_get_len(buffer),5);
  assert_memory_equal(ssh_buffer_get(buffer), "bcdef", 5);

  ssh_buffer_prepend_data(buffer,"aris",4);
  assert_int_equal(ssh_buffer_get_len(buffer),9);
  assert_memory_equal(ssh_buffer_get(buffer), "arisbcdef", 9);

  /* same thing but we add 5 bytes now */
  ssh_buffer_get_u32(buffer,&v);
  assert_int_equal(ssh_buffer_get_len(buffer),5);
  assert_memory_equal(ssh_buffer_get(buffer), "bcdef", 5);

  ssh_buffer_prepend_data(buffer,"12345",5);
  assert_int_equal(ssh_buffer_get_len(buffer),10);
  assert_memory_equal(ssh_buffer_get(buffer), "12345bcdef", 10);
}

/*
 * Test the behavior of ssh_buffer_get_ssh_string with invalid data
 */
static void torture_ssh_buffer_get_ssh_string(void **state) {
  ssh_buffer buffer;
  int i,j,k,l, rc;
  /* some values that can go wrong */
  uint32_t values[] = {0xffffffff, 0xfffffffe, 0xfffffffc, 0xffffff00,
      0x80000000, 0x80000004, 0x7fffffff};
  char data[128];
  (void)state;
  memset(data,'X',sizeof(data));
  for(i=0; i < (int)(sizeof(values)/sizeof(values[0]));++i){
    for(j=0; j< (int)sizeof(data);++j){
      for(k=1;k<5;++k){
        buffer = ssh_buffer_new();
        assert_non_null(buffer);

        for(l=0;l<k;++l){
          rc = ssh_buffer_add_u32(buffer,htonl(values[i]));
          assert_int_equal(rc, 0);
        }
        rc = ssh_buffer_add_data(buffer,data,j);
        assert_int_equal(rc, 0);
        for(l=0;l<k;++l){
          ssh_string str = ssh_buffer_get_ssh_string(buffer);
          assert_null(str);
          SSH_STRING_FREE(str);
        }
        SSH_BUFFER_FREE(buffer);
      }
    }
  }
}

static void torture_ssh_buffer_add_format(void **state) {
    ssh_buffer buffer=*state;
    uint8_t b;
    uint16_t w;
    uint32_t d;
    uint64_t q;
    ssh_string s;
    int rc;
    size_t len;
    uint8_t verif[]="\x42\x13\x37\x0b\xad\xc0\xde\x13\x24\x35\x46"
            "\xac\xbd\xce\xdf"
            "\x00\x00\x00\x06" "libssh"
            "\x00\x00\x00\x05" "rocks"
            "So much"
            "Fun!";

    b=0x42;
    w=0x1337;
    d=0xbadc0de;
    q=0x13243546acbdcedf;
    s=ssh_string_from_char("libssh");
    rc=ssh_buffer_pack(buffer, "bwdqSsPt",b,w,d,q,s,"rocks",7,"So much","Fun!");
    assert_int_equal(rc, SSH_OK);

    len = ssh_buffer_get_len(buffer);
    assert_int_equal(len, sizeof(verif) - 1);
    assert_memory_equal(ssh_buffer_get(buffer), verif, sizeof(verif) -1);

    SSH_STRING_FREE(s);
}

static void torture_ssh_buffer_get_format(void **state) {
    ssh_buffer buffer=*state;
    uint8_t b=0;
    uint16_t w=0;
    uint32_t d=0;
    uint64_t q=0;
    ssh_string s=NULL;
    char *s1=NULL, *s2=NULL;
    int rc;
    size_t len;
    uint8_t verif[]="\x42\x13\x37\x0b\xad\xc0\xde\x13\x24\x35\x46"
            "\xac\xbd\xce\xdf"
            "\x00\x00\x00\x06" "libssh"
            "\x00\x00\x00\x05" "rocks"
            "So much";

    rc = ssh_buffer_add_data(buffer, verif, sizeof(verif) - 1);
    assert_int_equal(rc, SSH_OK);
    rc = ssh_buffer_unpack(buffer, "bwdqSsP",&b,&w,&d,&q,&s,&s1,(size_t)7,&s2);
    assert_int_equal(rc, SSH_OK);

    assert_int_equal(b, 0x42);
    assert_int_equal(w, 0x1337);

    assert_true(d == 0xbadc0de);
    assert_true(q == 0x13243546acbdcedf);

    assert_non_null(s);
    assert_int_equal(ssh_string_len(s), 6);
    assert_memory_equal(ssh_string_data(s), "libssh", 6);

    assert_non_null(s1);
    assert_string_equal(s1, "rocks");

    assert_non_null(s2);
    assert_memory_equal(s2, "So much", 7);

    len = ssh_buffer_get_len(buffer);
    assert_int_equal(len, 0);
    SAFE_FREE(s);
    SAFE_FREE(s1);
    SAFE_FREE(s2);
}

static void torture_ssh_buffer_get_format_error(void **state) {
    ssh_buffer buffer=*state;
    uint8_t b=0;
    uint16_t w=0;
    uint32_t d=0;
    uint64_t q=0;
    ssh_string s=NULL;
    char *s1=NULL, *s2=NULL;
    int rc;
    uint8_t verif[]="\x42\x13\x37\x0b\xad\xc0\xde\x13\x24\x35\x46"
            "\xac\xbd\xce\xdf"
            "\x00\x00\x00\x06" "libssh"
            "\x00\x00\x00\x05" "rocks"
            "So much";

    rc = ssh_buffer_add_data(buffer, verif, sizeof(verif) - 1);
    assert_int_equal(rc, SSH_OK);
    rc = ssh_buffer_unpack(buffer, "bwdqSsPb",&b,&w,&d,&q,&s,&s1,(size_t)7,&s2,&b);
    assert_int_equal(rc, SSH_ERROR);

    assert_null(s);
    assert_null(s1);
    assert_null(s2);
}

static void torture_buffer_pack_badformat(void **state){
    ssh_buffer buffer = *state;
    uint8_t b = 42;
    int rc;

    /* first with missing format */
    rc = ssh_buffer_pack(buffer, "b", b, b);
    assert_int_equal(rc, SSH_ERROR);
    ssh_buffer_reinit(buffer);

    /* with additional format */
    rc = ssh_buffer_pack(buffer, "bb", b);
    /* check that we detect the missing parameter */
    assert_int_equal(rc, SSH_ERROR);

    /* unpack with missing format */
    ssh_buffer_reinit(buffer);
    rc = ssh_buffer_pack(buffer, "bb", 42, 43);
    assert_int_equal(rc, SSH_OK);
    rc = ssh_buffer_unpack(buffer, "b", &b, &b);
    assert_int_equal(rc, SSH_ERROR);

    /* not doing the test with additional format as
     * it could crash the process */
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_growing_buffer, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_growing_buffer_shifting, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_buffer_prepend, setup, teardown),
        cmocka_unit_test(torture_ssh_buffer_get_ssh_string),
        cmocka_unit_test_setup_teardown(torture_ssh_buffer_add_format, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_ssh_buffer_get_format, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_ssh_buffer_get_format_error, setup, teardown),
        cmocka_unit_test_setup_teardown(torture_buffer_pack_badformat, setup, teardown)
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
