/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2022 (c) Kai Huebl
 */

#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/certstore_default.h>

#include <check.h>

UA_PKIStore pkiStore;
UA_NodeId certificateGroupId;

static void setup(void) {
}

static void teardown(void) {
}

START_TEST(certstore_create) {
	UA_StatusCode retval = UA_STATUSCODE_GOOD;

	/* Check NULL pointer parameter */
	retval = UA_PKIStore_File(NULL, NULL);
	ck_assert_uint_eq(retval, UA_STATUSCODE_BADINTERNALERROR);

	retval = UA_PKIStore_File(&pkiStore, NULL);
	ck_assert_uint_eq(retval, UA_STATUSCODE_BADINTERNALERROR);

	retval = UA_PKIStore_File(NULL, &certificateGroupId);
	ck_assert_uint_eq(retval, UA_STATUSCODE_BADINTERNALERROR);

	certificateGroupId = UA_NODEID("ns=0;i=4711");
	retval = UA_PKIStore_File(&pkiStore, &certificateGroupId);
	ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
}
END_TEST

static Suite* testSuite_certstore_file(void) {
    Suite *s = suite_create("Certstore File");
    TCase *tc_cert = tcase_create("Certstore File");
    tcase_add_checked_fixture(tc_cert, setup, teardown);
    tcase_add_test(tc_cert, certstore_create);
    suite_add_tcase(s,tc_cert);
    return s;
}

int main(void) {
    Suite *s = testSuite_certstore_file();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr,CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
