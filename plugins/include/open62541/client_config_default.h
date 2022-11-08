/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 */

#ifndef UA_CLIENT_CONFIG_DEFAULT_H_
#define UA_CLIENT_CONFIG_DEFAULT_H_

#include <open62541/client.h>

_UA_BEGIN_DECLS

UA_Client UA_EXPORT * UA_Client_new(void);

UA_StatusCode UA_EXPORT
UA_ClientConfig_setDefault(UA_ClientConfig *config);

#ifdef UA_ENABLE_ENCRYPTION
UA_StatusCode UA_EXPORT
UA_ClientConfig_setDefaultEncryption(UA_ClientConfig *config, const UA_ByteString *pkiDir);
#endif

_UA_END_DECLS

#endif /* UA_CLIENT_CONFIG_DEFAULT_H_ */
