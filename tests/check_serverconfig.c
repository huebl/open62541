/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/pki_default.h>

#include "check.h"
#include "encryption/certificates.h"

START_TEST(Server_add_configuration_capabilities) {

	static char validServerConfigCapabilities[][16] = {
	    "NA", "DA", "HD", "AC", "HE", "GDS", "LDS", "DI", "ADI", "FDI",
	    "FDIC", "PLC", "S95", "RCP", "PUB", "AUTOID", "MDIS", "CNC", "PLK", "FDT",
	    "TMC", "CSPP", "61850", "PACKML", "MTC", "AUTOML", "SERCOS", "MIMOSA", "WITSML", "DEXPI",
	    "IOLINK", "VROBOT", "PNO", "PADIM"
	};

	const size_t validServerConfigCapabilitiesCount =
			     sizeof(validServerConfigCapabilities)/sizeof(validServerConfigCapabilities[0]);

	UA_Server *server = UA_Server_new();
	UA_ServerConfig_setDefault(UA_Server_getConfig(server));

	UA_StatusCode retval;
	UA_StatusCode_init(&retval);

	UA_Variant capabilities;
    UA_Variant_init(&capabilities);
    retval = UA_Server_readValue(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_SERVERCAPABILITIES),
                                 &capabilities);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    ck_assert(capabilities.type == &UA_TYPES[UA_TYPES_STRING]);
    size_t sizeBeforeAdd = capabilities.arrayLength;  /* inital array length before adding */

    /* Try to add an capability by null pointer */
    retval = UA_Server_configAddCapability(server, NULL);
    ck_assert_uint_eq(retval, UA_STATUSCODE_BADINVALIDARGUMENT);

    /* Try to add an empty (invalid) capability */
    UA_String strEmpty = UA_String_fromChars("");
    retval = UA_Server_configAddCapability(server, &strEmpty);
    ck_assert_uint_eq(retval, UA_STATUSCODE_BADINVALIDARGUMENT);

    /* Try to add a valid capability but server pointer is null */
    UA_String str = UA_String_fromChars(validServerConfigCapabilities[0]);
    retval = UA_Server_configAddCapability(NULL, &str);
    ck_assert_uint_eq(retval, UA_STATUSCODE_BADINVALIDARGUMENT);

    /* Try to add a non valid capability */
    str = UA_String_fromChars("_XYZ_");
    retval = UA_Server_configAddCapability(server, &str);
    ck_assert_uint_eq(retval, UA_STATUSCODE_BADINVALIDARGUMENT);

    /* Add all valid capabilities */
    size_t i = 0;
    for (i = 0; i < validServerConfigCapabilitiesCount; i++) {
        UA_String_init(&str);
        str = UA_String_fromChars(validServerConfigCapabilities[i]);
        retval = UA_Server_configAddCapability(server, &str);
        UA_String_clear(&str);
    }

    /* Add a valid capability twice, should be ignored, no error */
    str = UA_String_fromChars(validServerConfigCapabilities[0]);
    retval = UA_Server_configAddCapability(server, &str);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    UA_String_clear(&str);

    /* Read configuration capability variable after adding */
    UA_Variant_init(&capabilities);
    retval = UA_Server_readValue(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_SERVERCAPABILITIES),
                                 &capabilities);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    ck_assert(capabilities.type == &UA_TYPES[UA_TYPES_STRING]);
    size_t sizeAfterAdd = capabilities.arrayLength;  /* array length after adding */

    /* Check that all the capabilities have been added and only once */
    ck_assert_uint_eq((sizeAfterAdd - sizeBeforeAdd), validServerConfigCapabilitiesCount);

    /* Check capabilities for the right values */
    for (i = 0; i < validServerConfigCapabilitiesCount; i++) {
        UA_String *s = ((UA_String *)capabilities.data) + sizeBeforeAdd + i;
        ck_assert(s->length == strlen(validServerConfigCapabilities[i]));
        ck_assert_int_eq(strncmp((const char *)(s->data), validServerConfigCapabilities[i], s->length), 0);
    }

    UA_String_clear(&strEmpty);
    UA_Variant_clear(&capabilities);
    UA_Server_delete(server);

}
END_TEST

START_TEST(Server_add_configuration_keyformats) {

    static char validServerConfigKeyFormats[][4] = {"PFX", "PEM"};

    const size_t validServerConfigKeyFormatsCount = sizeof(validServerConfigKeyFormats)/sizeof(validServerConfigKeyFormats[0]);

    UA_Server *server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));

    UA_StatusCode retval;
    UA_StatusCode_init(&retval);

    UA_Variant keyFormats;
    UA_Variant_init(&keyFormats);
    retval = UA_Server_readValue(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_SUPPORTEDPRIVATEKEYFORMATS),
                                 &keyFormats);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    ck_assert(keyFormats.type == &UA_TYPES[UA_TYPES_STRING]);
    size_t anzBeforeAdd = keyFormats.arrayLength;  /* inital array length before adding */

    /* Try to add an key format by a null pointer */
    retval = UA_Server_configAddKeyFormat(server, NULL);
    ck_assert_uint_eq(retval, UA_STATUSCODE_BADINVALIDARGUMENT);

    /* Try to add an empty (invalid) key format */
    UA_String strEmpty = UA_String_fromChars("");
    retval = UA_Server_configAddKeyFormat(server, &strEmpty);
    ck_assert_uint_eq(retval, UA_STATUSCODE_BADINVALIDARGUMENT);

    /* Try to add a valid key format but server pointer is null */
    UA_String str = UA_String_fromChars(validServerConfigKeyFormats[0]);
    retval = UA_Server_configAddKeyFormat(NULL, &str);
    ck_assert_uint_eq(retval, UA_STATUSCODE_BADINVALIDARGUMENT);

    /* Try to add a non valid key format */
    str = UA_String_fromChars("XYZ");
    retval = UA_Server_configAddKeyFormat(server, &str);
    ck_assert_uint_eq(retval, UA_STATUSCODE_BADINVALIDARGUMENT);

    /* Add all valid keyFormats */
    size_t i = 0;
    for (i = 0; i < validServerConfigKeyFormatsCount; i++) {
        UA_String_init(&str);
        str = UA_String_fromChars(validServerConfigKeyFormats[i]);
        retval = UA_Server_configAddKeyFormat(server, &str);
        UA_String_clear(&str);
    }

    /* Add a valid key format twice, should be ignored, no error */
    str = UA_String_fromChars(validServerConfigKeyFormats[0]);
    retval = UA_Server_configAddKeyFormat(server, &str);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    UA_String_clear(&str);

    /* Read configuration key format variable after adding */
    UA_Variant_init(&keyFormats);
    retval = UA_Server_readValue(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_SUPPORTEDPRIVATEKEYFORMATS),
                                 &keyFormats);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    ck_assert(keyFormats.type == &UA_TYPES[UA_TYPES_STRING]);
    size_t anzAfterAdd = keyFormats.arrayLength;  /* array length after adding */

    /* Check that all the keyFormats have been added and only once */
    ck_assert_uint_eq((anzAfterAdd - anzBeforeAdd), validServerConfigKeyFormatsCount);

    /* Check added keyFormats for the right values */
    for (i = 0; i < validServerConfigKeyFormatsCount; i++) {
        UA_String *s = ((UA_String *)keyFormats.data) + anzBeforeAdd + i;
        ck_assert(s->length == strlen(validServerConfigKeyFormats[i]));
        ck_assert_int_eq(strncmp((const char *)(s->data), validServerConfigKeyFormats[i], s->length), 0);
    }

    UA_String_clear(&strEmpty);
    UA_Variant_clear(&keyFormats);
    UA_Server_delete(server);
}
END_TEST

START_TEST(Server_set_max_trust_list_size) {

    const UA_UInt32 cSize = 4711UL;

    UA_Server *server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));

    UA_StatusCode retval;
    UA_StatusCode_init(&retval);

    /* Check pointer is null */
    retval = UA_Server_configSetMaxTrustListSize(NULL, cSize);
    ck_assert_uint_eq(retval, UA_STATUSCODE_BADINVALIDARGUMENT);

    /* Set max trust list size variable */
    retval = UA_Server_configSetMaxTrustListSize(server, cSize);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    /* Read max trust list size variable after adding */
    UA_Variant sizeVar;
    UA_Variant_init(&sizeVar);
    retval = UA_Server_readValue(server,
                 UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_MAXTRUSTLISTSIZE), &sizeVar);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    /* Check for right type */
    ck_assert(sizeVar.type == &UA_TYPES[UA_TYPES_UINT32]);
    /* Check for the right value */
    ck_assert_uint_eq(*(UA_UInt32 *)sizeVar.data, cSize);

    UA_Variant_clear(&sizeVar);
    UA_Server_delete(server);
}
END_TEST

static Suite* testSuite_ServerConfiguration(void) {
    Suite *s = suite_create("ServerConfiguration");
    TCase *tc = tcase_create("ServerConfiguration");
    tcase_add_test(tc, Server_add_configuration_capabilities);
#if 0
    tcase_add_test(tc, Server_create_csr);
#endif
    tcase_add_test(tc, Server_add_configuration_keyformats);
    tcase_add_test(tc, Server_set_max_trust_list_size);
#if 0
    tcase_add_test(tc, Server_rejected_list);
#endif
    suite_add_tcase(s,tc);
    return s;
}

int main(void) {
    Suite *s = testSuite_ServerConfiguration();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr,CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


