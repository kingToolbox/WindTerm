/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2019 by Red Hat, Inc.
 *
 * Author: Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
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

#define LIBSSH_STATIC

#include "config.h"

#include "torture.h"
#include "libssh/scp.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>

#define BUF_SIZE 1024

#define TEMPLATE BINARYDIR "/tests/home/alice/temp_dir_XXXXXX"
#define ALICE_HOME BINARYDIR "/tests/home/alice"

struct scp_st {
    struct torture_state *s;
    char *tmp_dir;
    char *tmp_dir_basename;
};

static int sshd_setup(void **state)
{
    struct scp_st *ts = NULL;
    struct torture_state *s = NULL;

    ts = (struct scp_st *)calloc(1, sizeof(struct scp_st));
    assert_non_null(ts);

    torture_setup_sshd_server((void **)&s, false);
    assert_non_null(s);

    ts->s = s;

    *state = ts;

    return 0;
}

static int sshd_teardown(void **state)
{
    struct scp_st *ts = NULL;

    ts = *((struct scp_st **)state);
    assert_non_null(ts);
    assert_non_null(ts->s);

    torture_teardown_sshd_server((void **)&(ts->s));

    SAFE_FREE(ts);

    return 0;
}

static int session_setup(void **state)
{
    struct scp_st *ts = NULL;
    struct torture_state *s = NULL;

    char *tmp_dir = NULL;
    char *tmp_dir_basename = NULL;

    struct passwd *pwd;

    int rc;

    assert_non_null(state);

    ts = *state;

    assert_non_null(ts);
    assert_non_null(ts->s);

    s = ts->s;

    /* Create temporary directory for alice */
    tmp_dir = torture_make_temp_dir(TEMPLATE);
    assert_non_null(tmp_dir);
    ts->tmp_dir = tmp_dir;

    tmp_dir_basename = ssh_basename(tmp_dir);
    assert_non_null(tmp_dir_basename);
    ts->tmp_dir_basename = tmp_dir_basename;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = torture_ssh_session(s,
                                         TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    return 0;
}

static int session_teardown(void **state)
{
    struct scp_st *ts = NULL;
    struct torture_state *s = NULL;

    assert_non_null(state);
    ts = *((struct scp_st **)state);

    assert_non_null(ts->s);
    s = ts->s;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    assert_non_null(ts->tmp_dir);
    torture_rmdirs(ts->tmp_dir);

    SAFE_FREE(ts->tmp_dir);
    SAFE_FREE(ts->tmp_dir_basename);

    return 0;
}

static void torture_scp_upload(void **state)
{
    struct scp_st *ts = NULL;
    struct torture_state *s = NULL;

    ssh_session session = NULL;
    ssh_scp scp = NULL;

    char expected_a[BUF_SIZE];
    char buf[BUF_SIZE];
    FILE *file = NULL;
    size_t len = 0;
    int rc;

    assert_non_null(state);
    ts = *state;

    assert_non_null(ts->s);
    s = ts->s;

    session = s->ssh.session;
    assert_non_null(session);

    assert_non_null(ts->tmp_dir_basename);
    assert_non_null(ts->tmp_dir);

    /* Upload file "a" to alice's temp dir */

    /* When writing the file_name must be the directory name */
    scp = ssh_scp_new(session, SSH_SCP_WRITE, ts->tmp_dir_basename);
    assert_non_null(scp);

    rc = ssh_scp_init(scp);
    assert_ssh_return_code(session, rc);

    /* Init buffer content to be written */
    memset(expected_a, 'A', BUF_SIZE);

    /* For ssh_scp_push_file(), the file_name is the name of the file without
     * path */
    rc = ssh_scp_push_file(scp, "a", BUF_SIZE, 0644);
    assert_ssh_return_code(session, rc);

    rc = ssh_scp_write(scp, expected_a, BUF_SIZE);
    assert_ssh_return_code(session, rc);

    /* Cleanup */
    ssh_scp_close(scp);
    ssh_scp_free(scp);

    /* Open file and check content */
    snprintf(buf, BUF_SIZE, "%s/a", ts->tmp_dir);

    file = fopen(buf, "r");
    assert_non_null(file);

    len = fread(buf, BUF_SIZE, 1, file);
    assert_int_equal(len, 1);
    assert_memory_equal(buf, expected_a, BUF_SIZE);

    fclose(file);
}

static void torture_scp_upload_recursive(void **state)
{
    struct scp_st *ts = NULL;
    struct torture_state *s = NULL;

    ssh_session session = NULL;
    ssh_scp scp = NULL;

    char expected_b[BUF_SIZE];
    char buf[BUF_SIZE];
    FILE *file = NULL;
    size_t len = 0;

    int rc;

    assert_non_null(state);
    ts = *state;

    assert_non_null(ts->s);
    s = ts->s;

    session = s->ssh.session;
    assert_non_null(session);

    assert_non_null(ts->tmp_dir_basename);
    assert_non_null(ts->tmp_dir);

    /* Upload directory "test_dir" containing file "b" to alice's temp dir */

    /* When writing the file_name must be the directory name */
    scp = ssh_scp_new(session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE,
                      ts->tmp_dir_basename);
    assert_non_null(scp);

    rc = ssh_scp_init(scp);
    assert_ssh_return_code(session, rc);

    /* Push directory where the new file will be copied */
    rc = ssh_scp_push_directory(scp, "test_dir", 0755);
    assert_ssh_return_code(session, rc);

    memset(expected_b, 'B', BUF_SIZE);

    /* For ssh_scp_push_file(), the file_name is the name of the file without
     * path */
    rc = ssh_scp_push_file(scp, "b", BUF_SIZE, 0644);
    assert_ssh_return_code(session, rc);

    rc = ssh_scp_write(scp, expected_b, BUF_SIZE);
    assert_ssh_return_code(session, rc);

    /* Leave the directory */
    rc = ssh_scp_leave_directory(scp);
    assert_ssh_return_code(session, rc);

    /* Cleanup */
    ssh_scp_close(scp);
    ssh_scp_free(scp);

    /* Open file and check content */
    snprintf(buf, BUF_SIZE, "%s/test_dir/b", ts->tmp_dir);

    file = fopen(buf, "r");
    assert_non_null(file);

    len = fread(buf, BUF_SIZE, 1, file);
    assert_int_equal(len, 1);
    assert_memory_equal(buf, expected_b, BUF_SIZE);

    fclose(file);
}

static void torture_scp_download(void **state)
{
    struct scp_st *ts = NULL;
    struct torture_state *s = NULL;

    ssh_session session = NULL;
    ssh_scp scp = NULL;

    char expected_a[BUF_SIZE];
    char buf[BUF_SIZE];
    const char *remote_file = NULL;

    FILE *file = NULL;
    int fd = 0;

    size_t size;

    int mode;
    int rc;

    assert_non_null(state);

    ts = *state;

    assert_non_null(ts);
    assert_non_null(ts->s);

    s = ts->s;

    session = s->ssh.session;
    assert_non_null(session);

    assert_non_null(ts->tmp_dir_basename);
    assert_non_null(ts->tmp_dir);

    /* Create file "a" for alice */
    memset(expected_a, 'A', BUF_SIZE);

    snprintf(buf, BUF_SIZE, "%s/a", ts->tmp_dir);

    fd = open(buf, O_WRONLY | O_CREAT, 0644);
    assert_true(fd > 0);

    file = fdopen(fd, "w");
    assert_non_null(file);

    size = fwrite(expected_a, 1, BUF_SIZE, file);
    assert_int_equal(size, BUF_SIZE);
    fclose(file);

    /* Construct the file path */
    snprintf(buf, BUF_SIZE, "%s/a", ts->tmp_dir_basename);

    /* When reading, the location is the file path */
    scp = ssh_scp_new(session, SSH_SCP_READ, buf);
    assert_non_null(scp);

    rc = ssh_scp_init(scp);
    assert_ssh_return_code(session, rc);

    rc = ssh_scp_pull_request(scp);
    assert_int_equal(rc, SSH_SCP_REQUEST_NEWFILE);

    size = ssh_scp_request_get_size(scp);
    assert_int_equal(size, BUF_SIZE);

    mode = ssh_scp_request_get_permissions(scp);
    assert_int_equal(mode, 0644);

    remote_file = ssh_scp_request_get_filename(scp);
    assert_non_null(remote_file);
    assert_string_equal(remote_file, "a");

    rc = ssh_scp_accept_request(scp);
    assert_ssh_return_code(session, rc);

    rc = ssh_scp_read(scp, buf, BUF_SIZE);
    assert_int_equal(rc, size);

    assert_memory_equal(expected_a, buf, BUF_SIZE);

    /* Cleanup */
    ssh_scp_close(scp);
    ssh_scp_free(scp);
}

static void torture_scp_download_recursive(void **state)
{
    struct scp_st *ts = NULL;
    struct torture_state *s = NULL;

    ssh_session session = NULL;
    ssh_scp scp = NULL;

    char expected_b[BUF_SIZE];
    char buf[BUF_SIZE];
    const char *remote_file = NULL;
    FILE *file = NULL;
    int fd = 0;

    size_t size;

    int mode;
    int rc;

    assert_non_null(state);
    ts = *state;

    assert_non_null(ts->s);
    s = ts->s;

    session = s->ssh.session;
    assert_non_null(session);

    assert_non_null(ts->tmp_dir_basename);
    assert_non_null(ts->tmp_dir);

    /* Create file "b" for alice */
    memset(expected_b, 'B', BUF_SIZE);

    snprintf(buf, BUF_SIZE, "%s/b", ts->tmp_dir);

    fd = open(buf, O_WRONLY | O_CREAT, 0644);
    assert_true(fd > 0);

    file = fdopen(fd, "w");
    assert_non_null(file);

    size = fwrite(expected_b, 1, BUF_SIZE, file);
    assert_int_equal(size, BUF_SIZE);
    fclose(file);

    /* Copy the directory containing the file "b" */
    scp = ssh_scp_new(session, SSH_SCP_READ | SSH_SCP_RECURSIVE,
                      ts->tmp_dir_basename);
    assert_non_null(scp);

    rc = ssh_scp_init(scp);
    assert_ssh_return_code(session, rc);

    /* Receive the directory */
    rc = ssh_scp_pull_request(scp);
    assert_int_equal(rc, SSH_SCP_REQUEST_NEWDIR);

    mode = ssh_scp_request_get_permissions(scp);
    assert_int_equal(mode, 0700);

    remote_file = ssh_scp_request_get_filename(scp);
    assert_non_null(remote_file);
    assert_string_equal(remote_file, ts->tmp_dir_basename);

    rc = ssh_scp_accept_request(scp);
    assert_ssh_return_code(session, rc);

    /* Receive the file "b" */
    rc = ssh_scp_pull_request(scp);
    assert_int_equal(rc, SSH_SCP_REQUEST_NEWFILE);

    size = ssh_scp_request_get_size(scp);
    assert_int_equal(size, BUF_SIZE);

    mode = ssh_scp_request_get_permissions(scp);
    assert_int_equal(mode, 0644);

    remote_file = ssh_scp_request_get_filename(scp);
    assert_non_null(remote_file);
    assert_string_equal(remote_file, "b");

    rc = ssh_scp_accept_request(scp);
    assert_ssh_return_code(session, rc);

    rc = ssh_scp_read(scp, buf, BUF_SIZE);
    assert_int_equal(rc, size);

    /* Check if the content was the expected */
    assert_memory_equal(expected_b, buf, BUF_SIZE);

    /* Receive end of directory */
    rc = ssh_scp_pull_request(scp);
    assert_int_equal(rc, SSH_SCP_REQUEST_ENDDIR);

    /* Receive end of communication */
    rc = ssh_scp_pull_request(scp);
    assert_int_equal(rc, SSH_SCP_REQUEST_EOF);

    /* Cleanup */
    ssh_scp_close(scp);
    ssh_scp_free(scp);
}

static void torture_scp_upload_newline(void **state)
{
    struct scp_st *ts = NULL;
    struct torture_state *s = NULL;

    ssh_session session = NULL;
    ssh_scp scp = NULL;

    FILE *file = NULL;

    char buf[1024];
    char *rs = NULL;
    int rc;

    assert_non_null(state);
    ts = *state;

    assert_non_null(ts->s);
    s = ts->s;

    session = s->ssh.session;
    assert_non_null(session);

    assert_non_null(ts->tmp_dir_basename);
    assert_non_null(ts->tmp_dir);

    /* Upload recursively trying to inject protocol messages */

    /* When writing the file_name must be the directory name */
    scp = ssh_scp_new(session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE,
                      ts->tmp_dir_basename);
    assert_non_null(scp);

    rc = ssh_scp_init(scp);
    assert_ssh_return_code(session, rc);

    /* Push directory where the new file will be copied */
    rc = ssh_scp_push_directory(scp, "test_inject", 0755);
    assert_ssh_return_code(session, rc);

    /* Try to push file with injected protocol messages */
    rc = ssh_scp_push_file(scp, "original\nreplacedC0777 8 injected", 8, 0644);
    assert_ssh_return_code(session, rc);

    rc = ssh_scp_write(scp, "original", 8);
    assert_ssh_return_code(session, rc);

    /* Leave the directory */
    rc = ssh_scp_leave_directory(scp);
    assert_ssh_return_code(session, rc);

    /* Cleanup */
    ssh_scp_close(scp);
    ssh_scp_free(scp);

    /* Open the file and check content */
    snprintf(buf, BUF_SIZE, "%s/test_inject/"
             "original\\nreplacedC0777 8 injected",
             ts->tmp_dir);
    file = fopen(buf, "r");
    assert_non_null(file);

    rs = fgets(buf, 1024, file);
    assert_non_null(rs);
    assert_string_equal(buf, "original");

    fclose(file);
}

static void torture_scp_upload_appended_command(void **state)
{
    struct scp_st *ts = NULL;
    struct torture_state *s = NULL;

    ssh_session session = NULL;
    ssh_scp scp = NULL;

    FILE *file = NULL;

    char buf[1024];
    char *rs = NULL;
    int rc;

    assert_non_null(state);
    ts = *state;

    assert_non_null(ts->s);
    s = ts->s;

    session = s->ssh.session;
    assert_non_null(session);

    assert_non_null(ts->tmp_dir_basename);
    assert_non_null(ts->tmp_dir);

    /* Upload a file path with a command appended */

    /* Append a command to the file path */
    snprintf(buf, BUF_SIZE, "%s"
             "/;touch hack",
             ts->tmp_dir);

    /* When writing the file_name must be the directory name */
    scp = ssh_scp_new(session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE,
                      buf);
    assert_non_null(scp);

    rc = ssh_scp_init(scp);
    assert_ssh_return_code(session, rc);

    /* Push directory where the new file will be copied */
    rc = ssh_scp_push_directory(scp, ";touch hack", 0755);
    assert_ssh_return_code(session, rc);

    /* Try to push file */
    rc = ssh_scp_push_file(scp, "original", 8, 0644);
    assert_ssh_return_code(session, rc);

    rc = ssh_scp_write(scp, "original", 8);
    assert_ssh_return_code(session, rc);

    /* Leave the directory */
    rc = ssh_scp_leave_directory(scp);
    assert_ssh_return_code(session, rc);

    /* Cleanup */
    ssh_scp_close(scp);
    ssh_scp_free(scp);

    /* Make sure the command was not executed */
    snprintf(buf, BUF_SIZE, ALICE_HOME "/hack");
    file = fopen(buf, "r");
    assert_null(file);

    /* Open the file and check content */
    snprintf(buf, BUF_SIZE, "%s"
             "/;touch hack/original",
             ts->tmp_dir);

    file = fopen(buf, "r");
    assert_non_null(file);

    rs = fgets(buf, 1024, file);
    assert_non_null(rs);
    assert_string_equal(buf, "original");

    fclose(file);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_scp_upload,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_scp_upload_recursive,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_scp_download,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_scp_download_recursive,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_scp_upload_newline,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_scp_upload_appended_command,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
