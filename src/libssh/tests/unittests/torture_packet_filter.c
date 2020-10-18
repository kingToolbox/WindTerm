/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
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

/*
 * This test checks if the messages accepted by the packet filter were intented
 * to be accepted.
 *
 * The process consists in 2 steps:
 *   - Try the filter with a message type in an arbitrary state
 *   - If the message is accepted by the filter, check if the message is in the
 *     set of accepted states.
 *
 * Only the values selected by the flag (COMPARE_*) are considered.
 * */

#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/priv.h"
#include "libssh/libssh.h"
#include "libssh/session.h"
#include "libssh/auth.h"
#include "libssh/ssh2.h"
#include "libssh/packet.h"

#include "packet.c"

#define COMPARE_SESSION_STATE       1
#define COMPARE_ROLE                (1 << 1)
#define COMPARE_DH_STATE            (1 << 2)
#define COMPARE_AUTH_STATE          (1 << 3)
#define COMPARE_GLOBAL_REQ_STATE    (1 << 4)
#define COMPARE_CURRENT_METHOD      (1 << 5)

#define SESSION_STATE_COUNT 11
#define DH_STATE_COUNT 4
#define AUTH_STATE_COUNT 15
#define GLOBAL_REQ_STATE_COUNT 5
#define MESSAGE_COUNT 100 // from 1 to 100

#define ROLE_CLIENT 0
#define ROLE_SERVER 1

/*
 * This is the list of currently unfiltered message types.
 * Only unrecognized types should be in this list.
 * */
static uint8_t unfiltered[] = {
    8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    22, 23, 24, 25, 26, 27, 28, 29,
    35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    54, 55, 56, 57, 58, 59,
    62,
    67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    83, 84, 85, 86, 87, 88, 89,
};

typedef struct global_state_st {
    /* If the bit in this flag is zero, the corresponding state is not
     * considered, working as a wildcard (meaning any value is accepted) */
    uint32_t flags;
    uint8_t role;
    enum ssh_session_state_e session;
    enum ssh_dh_state_e dh;
    enum ssh_auth_state_e auth;
    enum ssh_channel_request_state_e global_req;
} global_state;

static int cmp_state(const void *e1, const void *e2)
{
    global_state *s1 = (global_state *) e1;
    global_state *s2 = (global_state *) e2;

    /* Compare role (client == 0 or server == 1)*/
    if (s1->role < s2->role) {
        return -1;
    }
    else if (s1->role > s2->role) {
        return 1;
    }

    /* Compare session state */
    if (s1->session < s2->session) {
        return -1;
    }
    else if (s1->session > s2->session) {
        return 1;
    }

    /* Compare DH state */
    if (s1->dh < s2->dh) {
        return -1;
    }
    else if (s1->dh > s2->dh) {
        return 1;
    }

    /* Compare auth */
    if (s1->auth < s2->auth) {
        return -1;
    }
    else if (s1->auth > s2->auth) {
        return 1;
    }

    /* Compare global_req */
    if (s1->global_req < s2->global_req) {
        return -1;
    }
    else if (s1->global_req > s2->global_req) {
        return 1;
    }

    /* If all equal, they are equal */
    return 0;
}

static int cmp_state_search(const void *key, const void *array_element)
{
    global_state *s1 = (global_state *) key;
    global_state *s2 = (global_state *) array_element;

    int result = 0;

    if (s2->flags & COMPARE_ROLE) {
        /* Compare role (client == 0 or server == 1)*/
        if (s1->role < s2->role) {
            return -1;
        }
        else if (s1->role > s2->role) {
            return 1;
        }
    }

    if (s2->flags & COMPARE_SESSION_STATE) {
        /* Compare session state */
        if (s1->session < s2->session) {
            result = -1;
            goto end;
        }
        else if (s1->session > s2->session) {
            result = 1;
            goto end;
        }
    }

    if (s2->flags & COMPARE_DH_STATE) {
        /* Compare DH state */
        if (s1->dh < s2->dh) {
            result = -1;
            goto end;
        }
        else if (s1->dh > s2->dh) {
            result = 1;
            goto end;
        }
    }

    if (s2->flags & COMPARE_AUTH_STATE) {
        /* Compare auth */
        if (s1->auth < s2->auth) {
            result = -1;
            goto end;
        }
        else if (s1->auth > s2->auth) {
            result = 1;
            goto end;
        }
    }

    if (s2->flags & COMPARE_GLOBAL_REQ_STATE) {
        /* Compare global_req */
        if (s1->global_req < s2->global_req) {
            result = -1;
            goto end;
        }
        else if (s1->global_req > s2->global_req) {
            result = 1;
            goto end;
        }
    }

end:
    return result;
}

static int is_state_accepted(global_state *tested, global_state *accepted,
                             int accepted_len)
{
    global_state *found = NULL;

    found = bsearch(tested, accepted, accepted_len, sizeof(global_state),
                    cmp_state_search);

    if (found != NULL) {
        return 1;
    }

    return 0;
}

static int cmp_uint8(const void *i, const void *j)
{
    uint8_t e1 = *((uint8_t *)i);
    uint8_t e2 = *((uint8_t *)j);

    if (e1 < e2) {
        return -1;
    }
    else if (e1 > e2) {
        return 1;
    }

    return 0;
}

static int check_unfiltered(uint8_t msg_type)
{
    uint8_t *found;

    found = bsearch(&msg_type, unfiltered, sizeof(unfiltered)/sizeof(uint8_t),
                    sizeof(uint8_t), cmp_uint8);

    if (found != NULL) {
        return 1;
    }

    return 0;
}

static void torture_packet_filter_check_unfiltered(void **state)
{
    ssh_session session;

    int role_c;
    int auth_c;
    int session_c;
    int dh_c;
    int global_req_c;

    uint8_t msg_type;

    enum ssh_packet_filter_result_e rc;
    int in_unfiltered;

    (void)state;

    session = ssh_new();

    for (msg_type = 1; msg_type <= MESSAGE_COUNT; msg_type++) {
        session->in_packet.type = msg_type;
        for (role_c = 0; role_c < 2; role_c++) {
            session->server = role_c;
            for (session_c = 0; session_c < SESSION_STATE_COUNT; session_c++) {
                session->session_state = session_c;
                for (dh_c = 0; dh_c < DH_STATE_COUNT; dh_c++) {
                    session->dh_handshake_state = dh_c;
                    for (auth_c = 0; auth_c < AUTH_STATE_COUNT; auth_c++) {
                        session->auth.state = auth_c;
                        for (global_req_c = 0;
                                global_req_c < GLOBAL_REQ_STATE_COUNT;
                                global_req_c++)
                        {
                            session->global_req_state = global_req_c;

                            rc = ssh_packet_incoming_filter(session);

                            if (rc == SSH_PACKET_UNKNOWN) {
                                in_unfiltered = check_unfiltered(msg_type);

                                if (!in_unfiltered) {
                                    fprintf(stderr, "Message type %d UNFILTERED "
                                            "in state: role %d, session %d, dh %d, auth %d\n",
                                            msg_type, role_c, session_c, dh_c, auth_c);
                                }
                                assert_int_equal(in_unfiltered, 1);
                            }
                            else {
                                in_unfiltered = check_unfiltered(msg_type);

                                if (in_unfiltered) {
                                    fprintf(stderr, "Message type %d NOT UNFILTERED "
                                            "in state: role %d, session %d, dh %d, auth %d\n",
                                            msg_type, role_c, session_c, dh_c, auth_c);
                                }
                                assert_int_equal(in_unfiltered, 0);
                            }
                        }
                    }
                }
            }
        }
    }
    ssh_free(session);
}

static int check_message_in_all_states(global_state accepted[],
                                       int accepted_count, uint8_t msg_type)
{
    ssh_session session;

    int role_c;
    int auth_c;
    int session_c;
    int dh_c;
    int global_req_c;

    enum ssh_packet_filter_result_e rc;
    int in_accepted;

    global_state key;

    session = ssh_new();

    /* Sort the accepted array so that the elements can be searched using
     * bsearch */
    qsort(accepted, accepted_count, sizeof(global_state), cmp_state);

    session->in_packet.type = msg_type;

    for (role_c = 0; role_c < 2; role_c++) {
        session->server = role_c;
        key.role = role_c;
        for (session_c = 0; session_c < SESSION_STATE_COUNT; session_c++) {
            session->session_state = session_c;
            key.session = session_c;
            for (dh_c = 0; dh_c < DH_STATE_COUNT; dh_c++) {
                session->dh_handshake_state = dh_c;
                key.dh = dh_c;
                for (auth_c = 0; auth_c < AUTH_STATE_COUNT; auth_c++) {
                    session->auth.state = auth_c;
                    key.auth = auth_c;
                    for (global_req_c = 0;
                         global_req_c < GLOBAL_REQ_STATE_COUNT;
                         global_req_c++)
                    {
                        session->global_req_state = global_req_c;
                        key.global_req = global_req_c;

                        rc = ssh_packet_incoming_filter(session);

                        if (rc == SSH_PACKET_ALLOWED) {
                            in_accepted = is_state_accepted(&key, accepted,
                                                         accepted_count);

                            if (!in_accepted) {
                                fprintf(stderr, "Message type %d ALLOWED "
                                        "in state: role %d, session %d, dh %d, auth %d\n",
                                        msg_type, role_c, session_c, dh_c, auth_c);
                            }
                            assert_int_equal(in_accepted, 1);
                        }
                        else if (rc == SSH_PACKET_DENIED) {
                            in_accepted = is_state_accepted(&key, accepted, accepted_count);

                            if (in_accepted) {
                                fprintf(stderr, "Message type %d DENIED "
                                        "in state: role %d, session %d, dh %d, auth %d\n",
                                        msg_type, role_c, session_c, dh_c, auth_c);
                            }
                            assert_int_equal(in_accepted, 0);
                        }
                        else {
                            fprintf(stderr, "Message type %d UNFILTERED "
                                    "in state: role %d, session %d, dh %d, auth %d\n",
                                    msg_type, role_c, session_c, dh_c, auth_c);
                        }
                    }
                }
            }
        }
    }

    ssh_free(session);
    return 0;
}

static void torture_packet_filter_check_auth_success(void **state)
{
    int rc;

    global_state accepted[] = {
        {
            .flags = (COMPARE_SESSION_STATE |
                    COMPARE_ROLE |
                    COMPARE_AUTH_STATE |
                    COMPARE_DH_STATE),
            .role = ROLE_CLIENT,
            .session = SSH_SESSION_STATE_AUTHENTICATING,
            .dh = DH_STATE_FINISHED,
            .auth = SSH_AUTH_STATE_PUBKEY_AUTH_SENT,
        },
        {
            .flags = (COMPARE_SESSION_STATE |
                    COMPARE_ROLE |
                    COMPARE_AUTH_STATE |
                    COMPARE_DH_STATE),
            .role = ROLE_CLIENT,
            .session = SSH_SESSION_STATE_AUTHENTICATING,
            .dh = DH_STATE_FINISHED,
            .auth = SSH_AUTH_STATE_PASSWORD_AUTH_SENT,
        },
        {
            .flags = (COMPARE_SESSION_STATE |
                    COMPARE_ROLE |
                    COMPARE_AUTH_STATE |
                    COMPARE_DH_STATE),
            .role = ROLE_CLIENT,
            .session = SSH_SESSION_STATE_AUTHENTICATING,
            .dh = DH_STATE_FINISHED,
            .auth = SSH_AUTH_STATE_GSSAPI_MIC_SENT,
        },
        {
            .flags = (COMPARE_SESSION_STATE |
                    COMPARE_ROLE |
                    COMPARE_AUTH_STATE |
                    COMPARE_DH_STATE),
            .role = ROLE_CLIENT,
            .session = SSH_SESSION_STATE_AUTHENTICATING,
            .dh = DH_STATE_FINISHED,
            .auth = SSH_AUTH_STATE_KBDINT_SENT,
        },
        {
            .flags = (COMPARE_SESSION_STATE |
                    COMPARE_ROLE |
                    COMPARE_AUTH_STATE |
                    COMPARE_DH_STATE |
                    COMPARE_CURRENT_METHOD),
            .role = ROLE_CLIENT,
            .session = SSH_SESSION_STATE_AUTHENTICATING,
            .dh = DH_STATE_FINISHED,
            .auth = SSH_AUTH_STATE_AUTH_NONE_SENT,
        }
    };

    int accepted_count = 5;

    /* Unused */
    (void) state;

    rc = check_message_in_all_states(accepted, accepted_count,
            SSH2_MSG_USERAUTH_SUCCESS);

    assert_int_equal(rc, 0);
}

static void torture_packet_filter_check_msg_ext_info(void **state)
{
    int rc;

    global_state accepted[] = {
        {
            .flags = (COMPARE_SESSION_STATE |
                    COMPARE_DH_STATE),
            .session = SSH_SESSION_STATE_AUTHENTICATING,
            .dh = DH_STATE_FINISHED,
        },
        {
            .flags = (COMPARE_SESSION_STATE |
                    COMPARE_DH_STATE),
            .session = SSH_SESSION_STATE_AUTHENTICATED,
            .dh = DH_STATE_FINISHED,
        },
    };

    int accepted_count = 2;

    /* Unused */
    (void) state;

    rc = check_message_in_all_states(accepted, accepted_count,
            SSH2_MSG_EXT_INFO);

    assert_int_equal(rc, 0);
}

static void torture_packet_filter_check_channel_open(void **state)
{
    int rc;

    /* The only condition to accept a CHANNEL_OPEN is to be authenticated */
    global_state accepted[] = {
        {
            .flags = COMPARE_SESSION_STATE,
            .session = SSH_SESSION_STATE_AUTHENTICATED,
        }
    };

    int accepted_count = 1;

    /* Unused */
    (void) state;

    rc = check_message_in_all_states(accepted, accepted_count,
            SSH2_MSG_CHANNEL_OPEN);

    assert_int_equal(rc, 0);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_packet_filter_check_auth_success),
        cmocka_unit_test(torture_packet_filter_check_channel_open),
        cmocka_unit_test(torture_packet_filter_check_unfiltered),
        cmocka_unit_test(torture_packet_filter_check_msg_ext_info)
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
