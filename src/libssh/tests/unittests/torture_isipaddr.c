#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"

#include "misc.c"
#include "error.c"

/*
 * Test the behavior of ssh_is_ipaddr()
 */
static void torture_ssh_is_ipaddr(void **state)
{
    (void)state;

    assert_int_equal(ssh_is_ipaddr("127.0.0.1"),1);
    assert_int_equal(ssh_is_ipaddr("0.0.0.0"),1);
    assert_int_equal(ssh_is_ipaddr("1.1.1.1"),1);
    assert_int_equal(ssh_is_ipaddr("255.255.255.255"),1);
    assert_int_equal(ssh_is_ipaddr("128.128.128.128"),1);
    assert_int_equal(ssh_is_ipaddr("1.10.100.1"),1);
    assert_int_equal(ssh_is_ipaddr("0.1.10.100"),1);

    assert_int_equal(ssh_is_ipaddr("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),1);
    assert_int_equal(ssh_is_ipaddr("fe80:0000:0000:0000:0202:b3ff:fe1e:8329"),1);
    assert_int_equal(ssh_is_ipaddr("fe80:0:0:0:202:b3ff:fe1e:8329"),1);
    assert_int_equal(ssh_is_ipaddr("fe80::202:b3ff:fe1e:8329"),1);
    assert_int_equal(ssh_is_ipaddr("::1"),1);

    assert_int_equal(ssh_is_ipaddr("::ffff:192.0.2.128"),1);

    assert_int_equal(ssh_is_ipaddr("0.0.0.0.0"),0);
    assert_int_equal(ssh_is_ipaddr("0.0.0.0.a"),0);
    assert_int_equal(ssh_is_ipaddr("a.0.0.0"),0);
    assert_int_equal(ssh_is_ipaddr("0a.0.0.0.0"),0);
    assert_int_equal(ssh_is_ipaddr(""),0);
    assert_int_equal(ssh_is_ipaddr("0.0.0."),0);
    assert_int_equal(ssh_is_ipaddr("0.0"),0);
    assert_int_equal(ssh_is_ipaddr("0"),0);

    /*
     * FIXME: Temporary workaround for Wine bug
     */
#ifndef _WIN32
    assert_int_equal(ssh_is_ipaddr("255.255.255"),0);
#endif

    assert_int_equal(ssh_is_ipaddr("2001:0db8:85a3:0000:0000:8a2e:0370:7334:1002"), 0);
    assert_int_equal(ssh_is_ipaddr("fe80:x:202:b3ff:fe1e:8329"), 0);
    assert_int_equal(ssh_is_ipaddr("fe80:x:202:b3ff:fe1e:8329"), 0);
    assert_int_equal(ssh_is_ipaddr(":1"), 0);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_ssh_is_ipaddr)
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
