/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2017-2020 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017-2019 (c) Fraunhofer IOSB (Author: Mark Giraud)
 */

#include <open62541/transport_generated.h>
#include <open62541/transport_generated_handling.h>

#include "ua_client_internal.h"
#include "ua_types_encoding_binary.h"

#define UA_MINMESSAGESIZE 8192
#define UA_SESSION_LOCALNONCELENGTH 32
#define MAX_DATA_SIZE 4096

static UA_StatusCode initConnect(UA_Client *client);
static UA_StatusCode createSessionAsync(UA_Client *client);

static UA_SecurityPolicy *
getSecurityPolicy(UA_Client *client, UA_String policyUri) {
    for(size_t i = 0; i < client->config.securityPoliciesSize; i++) {
        if(UA_String_equal(&policyUri, &client->config.securityPolicies[i].policyUri))
            return &client->config.securityPolicies[i];
    }
    return NULL;
}

static UA_Boolean
endpointUnconfigured(UA_Client *client) {
    char test = 0;
    char *pos = (char *)&client->config.endpointDescription;
    for(size_t i = 0; i < sizeof(UA_EndpointDescription); i++)
        test = test | *(pos + i);
    pos = (char *)&client->config.userTokenPolicy;
    for(size_t i = 0; i < sizeof(UA_UserTokenPolicy); i++)
        test = test | *(pos + i);
    return (test == 0);
}

#ifdef UA_ENABLE_ENCRYPTION

/* Function to create a signature using remote certificate and nonce */
static UA_StatusCode
signActivateSessionRequest(UA_Client *client, UA_SecureChannel *channel,
                           UA_ActivateSessionRequest *request) {
    if(channel->securityMode != UA_MESSAGESECURITYMODE_SIGN &&
       channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_GOOD;

    const UA_SecurityPolicy *sp = channel->endpoint->securityPolicy;
    UA_SignatureData *sd = &request->clientSignature;

    /* Prepare the signature */
    size_t signatureSize = sp->certificateSigningAlgorithm.
        getLocalSignatureSize(channel->channelContext);
    UA_StatusCode retval = UA_String_copy(&sp->certificateSigningAlgorithm.uri,
                                          &sd->algorithm);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_ByteString_allocBuffer(&sd->signature, signatureSize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Allocate a temporary buffer */
    size_t dataToSignSize = channel->remoteCertificate.length + client->remoteNonce.length;
    if(dataToSignSize > MAX_DATA_SIZE)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_ByteString dataToSign;
    retval = UA_ByteString_allocBuffer(&dataToSign, dataToSignSize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval; /* sd->signature is cleaned up with the response */

    /* Sign the signature */
    memcpy(dataToSign.data, channel->remoteCertificate.data,
           channel->remoteCertificate.length);
    memcpy(dataToSign.data + channel->remoteCertificate.length,
           client->remoteNonce.data, client->remoteNonce.length);
    retval = sp->certificateSigningAlgorithm.sign(channel->channelContext,
                                                  &dataToSign, &sd->signature);

    /* Clean up */
    UA_ByteString_clear(&dataToSign);
    return retval;
}

static UA_StatusCode
encryptUserIdentityToken(UA_Client *client, const UA_String *userTokenSecurityPolicy,
                         UA_ExtensionObject *userIdentityToken) {
    UA_IssuedIdentityToken *iit = NULL;
    UA_UserNameIdentityToken *unit = NULL;
    UA_ByteString *tokenData;
    const UA_DataType *tokenType = userIdentityToken->content.decoded.type;
    if(tokenType == &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN]) {
        iit = (UA_IssuedIdentityToken*)userIdentityToken->content.decoded.data;
        tokenData = &iit->tokenData;
    } else if(tokenType == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
        unit = (UA_UserNameIdentityToken*)userIdentityToken->content.decoded.data;
        tokenData = &unit->password;
    } else {
        return UA_STATUSCODE_GOOD;
    }

    /* No encryption */
    const UA_String none = UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#None");
    if(userTokenSecurityPolicy->length == 0 ||
       UA_String_equal(userTokenSecurityPolicy, &none)) {
        return UA_STATUSCODE_GOOD;
    }

    UA_SecurityPolicy *sp = getSecurityPolicy(client, *userTokenSecurityPolicy);
    if(!sp) {
        UA_LOG_WARNING(&client->config.logger, UA_LOGCATEGORY_NETWORK,
                       "Could not find the required SecurityPolicy for the UserToken");
        return UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
    }

    /* Create a temp channel context */

    void *channelContext;
    UA_StatusCode retval = sp->channelModule.
        newContext(sp, client->channel.endpoint->pkiStore, &client->config.endpointDescription.serverCertificate, &channelContext);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(&client->config.logger, UA_LOGCATEGORY_NETWORK,
                       "Could not instantiate the SecurityPolicy for the UserToken");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Compute the encrypted length (at least one byte padding) */
    size_t plainTextBlockSize = sp->asymmetricModule.cryptoModule.
        encryptionAlgorithm.getRemotePlainTextBlockSize(channelContext);
    size_t encryptedBlockSize = sp->asymmetricModule.cryptoModule.
        encryptionAlgorithm.getRemoteBlockSize(channelContext);
    UA_UInt32 length = (UA_UInt32)(tokenData->length + client->remoteNonce.length);
    UA_UInt32 totalLength = length + 4; /* Including the length field */
    size_t blocks = totalLength / plainTextBlockSize;
    if(totalLength % plainTextBlockSize != 0)
        blocks++;
    size_t encryptedLength = blocks * encryptedBlockSize;

    /* Allocate memory for encryption overhead */
    UA_ByteString encrypted;
    retval = UA_ByteString_allocBuffer(&encrypted, encryptedLength);
    if(retval != UA_STATUSCODE_GOOD) {
        sp->channelModule.deleteContext(channelContext);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    UA_Byte *pos = encrypted.data;
    const UA_Byte *end = &encrypted.data[encrypted.length];
    retval = UA_UInt32_encodeBinary(&length, &pos, end);
    memcpy(pos, tokenData->data, tokenData->length);
    memcpy(&pos[tokenData->length], client->remoteNonce.data, client->remoteNonce.length);
    UA_assert(retval == UA_STATUSCODE_GOOD);

    /* Add padding
     *
     * 7.36.2.2 Legacy Encrypted Token Secret Format: A Client should not add any
     * padding after the secret. If a Client adds padding then all bytes shall
     * be zero. A Server shall check for padding added by Clients and ensure
     * that all padding bytes are zeros. */
    size_t paddedLength = plainTextBlockSize * blocks;
    for(size_t i = totalLength; i < paddedLength; i++)
        encrypted.data[i] = 0;
    encrypted.length = paddedLength;

    retval = sp->asymmetricModule.cryptoModule.encryptionAlgorithm.
        encrypt(channelContext, &encrypted);
    encrypted.length = encryptedLength;

    if(iit) {
        retval |= UA_String_copy(&sp->asymmetricModule.cryptoModule.encryptionAlgorithm.uri,
                                 &iit->encryptionAlgorithm);
    } else {
        retval |= UA_String_copy(&sp->asymmetricModule.cryptoModule.encryptionAlgorithm.uri,
                                 &unit->encryptionAlgorithm);
    }

    UA_ByteString_clear(tokenData);
    *tokenData = encrypted;

    /* Delete the temp channel context */
    sp->channelModule.deleteContext(channelContext);

    return retval;
}

/* Function to verify the signature corresponds to ClientNonce
 * using the local certificate */
static UA_StatusCode
checkCreateSessionSignature(UA_Client *client, const UA_SecureChannel *channel,
                            const UA_CreateSessionResponse *response) {
    if(channel->securityMode != UA_MESSAGESECURITYMODE_SIGN &&
       channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_GOOD;

    if(!channel->endpoint)
        return UA_STATUSCODE_BADINTERNALERROR;

    const UA_SecurityPolicy *sp = channel->endpoint->securityPolicy;
    UA_ByteString localCertificate;
    UA_ByteString_init(&localCertificate);
    sp->getLocalCertificate(sp, channel->endpoint->pkiStore, &localCertificate);

    size_t dataToVerifySize = localCertificate.length + client->localNonce.length;
    UA_ByteString dataToVerify = UA_BYTESTRING_NULL;
    UA_StatusCode retval = UA_ByteString_allocBuffer(&dataToVerify, dataToVerifySize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    memcpy(dataToVerify.data, localCertificate.data, localCertificate.length);
    memcpy(dataToVerify.data + localCertificate.length,
           client->localNonce.data, client->localNonce.length);

    retval = sp->certificateSigningAlgorithm.verify(channel->channelContext, &dataToVerify,
                                                    &response->serverSignature.signature);
    UA_ByteString_clear(&dataToVerify);
    return retval;
}

#endif

/***********************/
/* Open the Connection */
/***********************/

void
processERRResponse(UA_Client *client, const UA_ByteString *chunk) {
    client->channel.state = UA_SECURECHANNELSTATE_CLOSING;

    size_t offset = 0;
    UA_TcpErrorMessage errMessage;
    UA_StatusCode res =
        UA_decodeBinaryInternal(chunk, &offset, &errMessage,
                                &UA_TRANSPORT[UA_TRANSPORT_TCPERRORMESSAGE], NULL);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "Received an ERR response that could not be decoded "
                             "with StatusCode %s", UA_StatusCode_name(res));
        client->connectStatus = res;
        return;
    }

    UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                         "Received an ERR response with StatusCode %s and the following "
                         "reason: %.*s", UA_StatusCode_name(errMessage.error),
                         (int)errMessage.reason.length, errMessage.reason.data);
    client->connectStatus = errMessage.error;
    UA_TcpErrorMessage_clear(&errMessage);
}

void
processACKResponse(UA_Client *client, const UA_ByteString *chunk) {
    UA_SecureChannel *channel = &client->channel;
    if(channel->state != UA_SECURECHANNELSTATE_HEL_SENT) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, channel,
                             "SecureChannel not in the HEL-sent state");
        closeSecureChannel(client);
        client->connectStatus = UA_STATUSCODE_BADSECURECHANNELCLOSED;
        return;
    }

    /* Decode the message */
    size_t offset = 0;
    UA_TcpAcknowledgeMessage ackMessage;
    client->connectStatus =
        UA_decodeBinaryInternal(chunk, &offset, &ackMessage,
                                &UA_TRANSPORT[UA_TRANSPORT_TCPACKNOWLEDGEMESSAGE], NULL);
    if(client->connectStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_NETWORK,
                     "Decoding ACK message failed");
        closeSecureChannel(client);
        return;
    }

    client->connectStatus =
        UA_SecureChannel_processHELACK(channel, &ackMessage);
    if(client->connectStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_NETWORK,
                     "Processing the ACK message failed with StatusCode %s",
                     UA_StatusCode_name(client->connectStatus));
        closeSecureChannel(client);
        return;
    }

    client->channel.state = UA_SECURECHANNELSTATE_ACK_RECEIVED;
}

static UA_StatusCode
sendHELMessage(UA_Client *client) {
    UA_ConnectionManager *cm = client->channel.connectionManager;
    if(!UA_SecureChannel_isConnected(&client->channel))
        return UA_STATUSCODE_BADNOTCONNECTED;

    /* Get a buffer */
    UA_ByteString message;
    UA_StatusCode retval = cm->allocNetworkBuffer(cm, client->channel.connectionId,
                                                  &message, UA_MINMESSAGESIZE);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Prepare the HEL message and encode at offset 8 */
    UA_TcpHelloMessage hello;
    hello.protocolVersion = 0;
    hello.receiveBufferSize = client->config.localConnectionConfig.recvBufferSize;
    hello.sendBufferSize = client->config.localConnectionConfig.sendBufferSize;
    hello.maxMessageSize = client->config.localConnectionConfig.localMaxMessageSize;
    hello.maxChunkCount = client->config.localConnectionConfig.localMaxChunkCount;
    hello.endpointUrl = client->endpointUrl;

    UA_Byte *bufPos = &message.data[8]; /* skip the header */
    const UA_Byte *bufEnd = &message.data[message.length];
    client->connectStatus =
        UA_encodeBinaryInternal(&hello, &UA_TRANSPORT[UA_TRANSPORT_TCPHELLOMESSAGE],
                                &bufPos, &bufEnd, NULL, NULL);

    /* Encode the message header at offset 0 */
    UA_TcpMessageHeader messageHeader;
    messageHeader.messageTypeAndChunkType = UA_CHUNKTYPE_FINAL + UA_MESSAGETYPE_HEL;
    messageHeader.messageSize = (UA_UInt32) ((uintptr_t)bufPos - (uintptr_t)message.data);
    bufPos = message.data;
    retval = UA_encodeBinaryInternal(&messageHeader,
                                     &UA_TRANSPORT[UA_TRANSPORT_TCPMESSAGEHEADER],
                                     &bufPos, &bufEnd, NULL, NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        cm->freeNetworkBuffer(cm, client->channel.connectionId, &message);
        return retval;
    }

    /* Send the HEL message */
    message.length = messageHeader.messageSize;
    retval = cm->sendWithConnection(cm, client->channel.connectionId,
                                    &UA_KEYVALUEMAP_NULL, &message);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT, "Sending HEL failed");
        closeSecureChannel(client);
        return retval;
    }

    UA_LOG_DEBUG(&client->config.logger, UA_LOGCATEGORY_CLIENT, "Sent HEL message");
    client->channel.state = UA_SECURECHANNELSTATE_HEL_SENT;
    return UA_STATUSCODE_GOOD;
}

void
processOPNResponse(UA_Client *client, const UA_ByteString *message) {
    /* Is the content of the expected type? */
    size_t offset = 0;
    UA_NodeId responseId;
    UA_NodeId expectedId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_OPENSECURECHANNELRESPONSE_ENCODING_DEFAULTBINARY);
    UA_StatusCode retval = UA_NodeId_decodeBinary(message, &offset, &responseId);
    if(retval != UA_STATUSCODE_GOOD) {
        closeSecureChannel(client);
        return;
    }

    if(!UA_NodeId_equal(&responseId, &expectedId)) {
        UA_NodeId_clear(&responseId);
        closeSecureChannel(client);
        return;
    }

    /* Decode the response */
    UA_OpenSecureChannelResponse response;
    retval = UA_decodeBinaryInternal(message, &offset, &response,
                                     &UA_TYPES[UA_TYPES_OPENSECURECHANNELRESPONSE], NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        closeSecureChannel(client);
        return;
    }

    /* Check whether the nonce was reused */
    if(client->channel.securityMode != UA_MESSAGESECURITYMODE_NONE &&
       UA_ByteString_equal(&client->channel.remoteNonce,
                           &response.serverNonce)) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "The server reused the last nonce");
        client->connectStatus = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        closeSecureChannel(client);
        return;
    }

    /* Response.securityToken.revisedLifetime is UInt32 we need to cast it to
     * DateTime=Int64 we take 75% of lifetime to start renewing as described in
     * standard */
    client->nextChannelRenewal = UA_DateTime_nowMonotonic()
            + (UA_DateTime) (response.securityToken.revisedLifetime
                    * (UA_Double) UA_DATETIME_MSEC * 0.75);

    /* Move the nonce out of the response */
    UA_ByteString_clear(&client->channel.remoteNonce);
    client->channel.remoteNonce = response.serverNonce;
    UA_ByteString_init(&response.serverNonce);
    UA_ResponseHeader_clear(&response.responseHeader);

    /* Replace the token. Keep the current token as the old token. Messages
     * might still arrive for the old token. */
    client->channel.altSecurityToken = client->channel.securityToken;
    client->channel.securityToken = response.securityToken;
    client->channel.renewState = UA_SECURECHANNELRENEWSTATE_NEWTOKEN_CLIENT;

    /* Compute the new local keys. The remote keys are updated when a message
     * with the new SecurityToken is received. */
    retval = UA_SecureChannel_generateLocalKeys(&client->channel);
    if(retval != UA_STATUSCODE_GOOD) {
        closeSecureChannel(client);
        return;
    }

    UA_Float lifetime = (UA_Float)response.securityToken.revisedLifetime / 1000;
    UA_Boolean renew = (client->channel.state == UA_SECURECHANNELSTATE_OPEN);
    if(renew) {
        UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel, "SecureChannel "
                            "renewed with a revised lifetime of %.2fs", lifetime);
    } else {
        UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel,
                            "SecureChannel opened with SecurityPolicy %.*s "
                            "and a revised lifetime of %.2fs",
                            (int)client->channel.endpoint->securityPolicy->policyUri.length,
                            client->channel.endpoint->securityPolicy->policyUri.data, lifetime);
    }

    client->channel.state = UA_SECURECHANNELSTATE_OPEN;
}

/* OPN messges to renew the channel are sent asynchronous */
static UA_StatusCode
sendOPNAsync(UA_Client *client, UA_Boolean renew) {
    if(!UA_SecureChannel_isConnected(&client->channel))
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_SecureChannel_generateLocalNonce(&client->channel);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Prepare the OpenSecureChannelRequest */
    UA_OpenSecureChannelRequest opnSecRq;
    UA_OpenSecureChannelRequest_init(&opnSecRq);
    opnSecRq.requestHeader.timestamp = UA_DateTime_now();
    opnSecRq.requestHeader.authenticationToken = client->authenticationToken;
    opnSecRq.securityMode = client->channel.securityMode;
    opnSecRq.clientNonce = client->channel.localNonce;
    opnSecRq.requestedLifetime = client->config.secureChannelLifeTime;
    if(renew) {
        opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_RENEW;
        UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                             "Requesting to renew the SecureChannel");
    } else {
        opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_ISSUE;
        UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                             "Requesting to open a SecureChannel");
    }

    /* Prepare the entry for the linked list */
    UA_UInt32 requestId = ++client->requestId;

    /* Send the OPN message */
    UA_LOG_DEBUG(&client->config.logger, UA_LOGCATEGORY_SECURECHANNEL,
                 "Requesting to open a SecureChannel");
    retval =
        UA_SecureChannel_sendAsymmetricOPNMessage(&client->channel, requestId, &opnSecRq,
                                                  &UA_TYPES[UA_TYPES_OPENSECURECHANNELREQUEST]);
    if(retval != UA_STATUSCODE_GOOD) {
        client->connectStatus = retval;
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_SECURECHANNEL,
                      "Sending OPN message failed with error %s",
                      UA_StatusCode_name(retval));
        closeSecureChannel(client);
        return retval;
    }

    client->channel.renewState = UA_SECURECHANNELRENEWSTATE_SENT;
    if(client->channel.state < UA_SECURECHANNELSTATE_OPN_SENT)
        client->channel.state = UA_SECURECHANNELSTATE_OPN_SENT;
    UA_LOG_DEBUG(&client->config.logger, UA_LOGCATEGORY_SECURECHANNEL, "OPN message sent");
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
__Client_renewSecureChannel(UA_Client *client) {
    /* Check if OPN has been sent or the SecureChannel is still valid */
    if(client->channel.state != UA_SECURECHANNELSTATE_OPEN ||
       client->channel.renewState == UA_SECURECHANNELRENEWSTATE_SENT ||
       client->nextChannelRenewal > UA_DateTime_nowMonotonic())
        return UA_STATUSCODE_GOODCALLAGAIN;
    sendOPNAsync(client, true);
    return client->connectStatus;
}

UA_StatusCode
UA_Client_renewSecureChannel(UA_Client *client) {
    UA_LOCK(&client->clientMutex);
    UA_StatusCode res = __Client_renewSecureChannel(client);
    UA_UNLOCK(&client->clientMutex);
    return res;
}

static void
responseActivateSession(UA_Client *client, void *userdata,
                        UA_UInt32 requestId, void *response) {
    UA_LOCK(&client->clientMutex);

    UA_ActivateSessionResponse *ar = (UA_ActivateSessionResponse*)response;
    if(ar->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "ActivateSession failed with error code %s",
                     UA_StatusCode_name(ar->responseHeader.serviceResult));
        if(ar->responseHeader.serviceResult == UA_STATUSCODE_BADSESSIONIDINVALID ||
           ar->responseHeader.serviceResult == UA_STATUSCODE_BADSESSIONCLOSED) {
            /* The session is no longer usable. Create a brand new one. */
            cleanupSession(client);
            UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                         "Session cannot be activated. Create a new Session.");
            client->connectStatus = createSessionAsync(client);
        } else {
            /* Something else is wrong. Give up. */
            client->connectStatus = ar->responseHeader.serviceResult;
        }
        UA_UNLOCK(&client->clientMutex);
        return;
    }

    /* Replace the nonce */
    UA_ByteString_clear(&client->remoteNonce);
    client->remoteNonce = ar->serverNonce;
    UA_ByteString_init(&ar->serverNonce);

    client->sessionState = UA_SESSIONSTATE_ACTIVATED;
    notifyClientState(client);

    /* Immediately check if publish requests are outstanding - for example when
     * an existing Session has been reattached / activated. */
#ifdef UA_ENABLE_SUBSCRIPTIONS
    __Client_Subscriptions_backgroundPublish(client);
#endif

    UA_UNLOCK(&client->clientMutex);
}

static UA_StatusCode
activateSessionAsync(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    UA_ActivateSessionRequest request;
    UA_ActivateSessionRequest_init(&request);
    request.requestHeader.requestHandle = ++client->requestHandle;
    request.requestHeader.timestamp = UA_DateTime_now ();
    request.requestHeader.timeoutHint = 600000;
    UA_StatusCode retval =
        UA_ExtensionObject_copy(&client->config.userIdentityToken,
                                &request.userIdentityToken);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    if (client->config.sessionLocaleIdsSize && client->config.sessionLocaleIds) {
        retval = UA_Array_copy(client->config.sessionLocaleIds,
                               client->config.sessionLocaleIdsSize,
                               (void **)&request.localeIds, &UA_TYPES[UA_TYPES_LOCALEID]);
        if (retval != UA_STATUSCODE_GOOD)
            return retval;

        request.localeIdsSize = client->config.sessionLocaleIdsSize;
    }

    /* If not token is set, use anonymous */
    if(request.userIdentityToken.encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY) {
        UA_AnonymousIdentityToken *t = UA_AnonymousIdentityToken_new();
        if(!t) {
            UA_ActivateSessionRequest_clear(&request);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        request.userIdentityToken.content.decoded.data = t;
        request.userIdentityToken.content.decoded.type =
            &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN];
        request.userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
    }

    /* Set the policy-Id from the endpoint. Every IdentityToken starts with a
     * string. */
    retval = UA_String_copy(&client->config.userTokenPolicy.policyId,
                            (UA_String*)request.userIdentityToken.content.decoded.data);

#ifdef UA_ENABLE_ENCRYPTION
    /* Encrypt the UserIdentityToken */
    const UA_String *userTokenPolicy = &client->channel.endpoint->securityPolicy->policyUri;
    if(client->config.userTokenPolicy.securityPolicyUri.length > 0)
        userTokenPolicy = &client->config.userTokenPolicy.securityPolicyUri;
    retval |= encryptUserIdentityToken(client, userTokenPolicy, &request.userIdentityToken);
    retval |= signActivateSessionRequest(client, &client->channel, &request);
#endif

    if(retval == UA_STATUSCODE_GOOD)
        retval = __Client_AsyncServiceEx(client, &request,
                                         &UA_TYPES[UA_TYPES_ACTIVATESESSIONREQUEST],
                                         (UA_ClientAsyncServiceCallback)responseActivateSession,
                                         &UA_TYPES[UA_TYPES_ACTIVATESESSIONRESPONSE],
                                         NULL, NULL, client->config.timeout);

    UA_ActivateSessionRequest_clear(&request);
    if(retval == UA_STATUSCODE_GOOD)
        client->sessionState = UA_SESSIONSTATE_ACTIVATE_REQUESTED;
    else
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "ActivateSession failed when sending the request with error code %s",
                     UA_StatusCode_name(retval));

    return retval;
}

/* Combination of UA_Client_getEndpointsInternal and getEndpoints */
static void
responseGetEndpoints(UA_Client *client, void *userdata,
                     UA_UInt32 requestId, void *response) {
    UA_LOCK(&client->clientMutex);

    client->endpointsHandshake = false;

    UA_GetEndpointsResponse *resp = (UA_GetEndpointsResponse*)response;

    /* GetEndpoints not possible. Fail the connection */
    if(resp->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        /* Fail the connection attempt if the SecureChannel is still connected.
         * If the SecureChannel is (intentionally or unintentionally) closed,
         * the connectStatus should come from there. */
        if(UA_SecureChannel_isConnected(&client->channel)) {
           client->connectStatus = resp->responseHeader.serviceResult;
           UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "GetEndpointRequest failed with error code %s",
                        UA_StatusCode_name(client->connectStatus));
        }

        UA_GetEndpointsResponse_clear(resp);
        UA_UNLOCK(&client->clientMutex);
        return;
    }

    UA_Boolean endpointFound = false;
    UA_Boolean tokenFound = false;
    const UA_String binaryTransport = UA_STRING("http://opcfoundation.org/UA-Profile/"
                                                "Transport/uatcp-uasc-uabinary");

    // TODO: compare endpoint information with client->endpointUri
    UA_EndpointDescription* endpointArray = resp->endpoints;
    size_t endpointArraySize = resp->endpointsSize;
    for(size_t i = 0; i < endpointArraySize; ++i) {
        UA_EndpointDescription* endpointDescription = &endpointArray[i];
        /* Look out for binary transport endpoints.
         * Note: Siemens returns empty ProfileUrl, we will accept it as binary. */
        if(endpointDescription->transportProfileUri.length != 0 &&
           !UA_String_equal (&endpointDescription->transportProfileUri, &binaryTransport))
            continue;

        /* Valid SecurityMode? */
        if(endpointDescription->securityMode < 1 || endpointDescription->securityMode > 3) {
            UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: invalid security mode",
                        (long unsigned)i);
            continue;
        }

        /* Selected SecurityMode? */
        if(client->config.securityMode > 0 &&
           client->config.securityMode != endpointDescription->securityMode) {
            UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: security mode doesn't match",
                        (long unsigned)i);
            continue;
        }

        /* Matching SecurityPolicy? */
        if(client->config.securityPolicyUri.length > 0 &&
           !UA_String_equal(&client->config.securityPolicyUri,
                            &endpointDescription->securityPolicyUri)) {
            UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: security policy doesn't match",
                        (long unsigned)i);
            continue;
        }

        /* SecurityPolicy available? */
        if(!getSecurityPolicy(client, endpointDescription->securityPolicyUri)) {
            UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: security policy not available",
                        (long unsigned)i);
            continue;
        }

        endpointFound = true;

        /* Look for a user token policy with an anonymous token */
        for(size_t j = 0; j < endpointDescription->userIdentityTokensSize; ++j) {
            UA_UserTokenPolicy* tokenPolicy = &endpointDescription->userIdentityTokens[j];
            const UA_DataType *tokenType =
                client->config.userIdentityToken.content.decoded.type;

            /* Usertokens also have a security policy... */
            if(tokenPolicy->tokenType != UA_USERTOKENTYPE_ANONYMOUS &&
               tokenPolicy->securityPolicyUri.length > 0 &&
               !getSecurityPolicy(client, tokenPolicy->securityPolicyUri)) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu in endpoint %lu: "
                            "security policy '%.*s' not available",
                            (long unsigned)j, (long unsigned)i,
                            (int)tokenPolicy->securityPolicyUri.length,
                            tokenPolicy->securityPolicyUri.data);
                continue;
            }

            if(tokenPolicy->tokenType > 3) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu in endpoint %lu: "
                            "invalid token type",
                            (long unsigned)j, (long unsigned)i);
                continue;
            }

            if(tokenPolicy->tokenType == UA_USERTOKENTYPE_ANONYMOUS &&
               tokenType != &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN] &&
               tokenType != NULL) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (anonymous) in endpoint %lu: "
                            "configuration doesn't match",
                            (long unsigned)j, (long unsigned)i);
                continue;
            }
            if(tokenPolicy->tokenType == UA_USERTOKENTYPE_USERNAME &&
               tokenType != &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (username) in endpoint %lu: "
                            "configuration doesn't match",
                            (long unsigned)j, (long unsigned)i);
                continue;
            }
            if(tokenPolicy->tokenType == UA_USERTOKENTYPE_CERTIFICATE &&
               tokenType != &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN]) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (certificate) in endpoint %lu: "
                            "configuration doesn't match",
                            (long unsigned)j, (long unsigned)i);
                continue;
            }
            if(tokenPolicy->tokenType == UA_USERTOKENTYPE_ISSUEDTOKEN &&
               tokenType != &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN]) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (token) in endpoint %lu: "
                            "configuration doesn't match",
                            (long unsigned)j, (long unsigned)i);
                continue;
            }

            /* Endpoint with matching usertokenpolicy found */

#if UA_LOGLEVEL <= 300
            const char *securityModeNames[3] = {"None", "Sign", "SignAndEncrypt"};
            const char *userTokenTypeNames[4] = {"Anonymous", "UserName",
                                                 "Certificate", "IssuedToken"};
            UA_String *securityPolicyUri = &tokenPolicy->securityPolicyUri;
            if(securityPolicyUri->length == 0)
                securityPolicyUri = &endpointDescription->securityPolicyUri;

            /* Log the selected endpoint */
            UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "Selected endpoint %lu in URL %.*s with SecurityMode "
                        "%s and SecurityPolicy %.*s", (long unsigned)i,
                        (int)endpointDescription->endpointUrl.length, endpointDescription->endpointUrl.data,
                        securityModeNames[endpointDescription->securityMode - 1],
                        (int)endpointDescription->securityPolicyUri.length,
                        endpointDescription->securityPolicyUri.data);

            /* Log the selected UserTokenPolicy */
            UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "Selected UserTokenPolicy %.*s with UserTokenType %s "
                        "and SecurityPolicy %.*s",
                        (int)tokenPolicy->policyId.length, tokenPolicy->policyId.data,
                        userTokenTypeNames[tokenPolicy->tokenType],
                        (int)securityPolicyUri->length, securityPolicyUri->data);
#endif

            /* Move to the client config */
            tokenFound = true;
            UA_EndpointDescription_clear(&client->config.endpointDescription);
            client->config.endpointDescription = *endpointDescription;
            UA_EndpointDescription_init(endpointDescription);
            UA_UserTokenPolicy_clear(&client->config.userTokenPolicy);
            client->config.userTokenPolicy = *tokenPolicy;
            UA_UserTokenPolicy_init(tokenPolicy);

            break;
        }

        if(tokenFound)
            break;
    }

    if(!endpointFound) {
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "No suitable endpoint found");
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
    } else if(!tokenFound) {
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "No suitable UserTokenPolicy found for the possible endpoints");
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Close the SecureChannel if a different SecurityPolicy is defined by the Endpoint */
    if(client->config.endpointDescription.securityMode != client->channel.securityMode ||
       !UA_String_equal(&client->config.endpointDescription.securityPolicyUri,
                        &client->channel.endpoint->securityPolicy->policyUri))
        closeSecureChannel(client);
    UA_UNLOCK(&client->clientMutex);
}

static UA_StatusCode
requestGetEndpoints(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    UA_GetEndpointsRequest request;
    UA_GetEndpointsRequest_init(&request);
    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;
    request.endpointUrl = client->endpointUrl;
    UA_StatusCode retval =
        __Client_AsyncServiceEx(client, &request, &UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST],
                                (UA_ClientAsyncServiceCallback) responseGetEndpoints,
                                &UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE], NULL, NULL,
                                client->config.timeout);
    if(retval == UA_STATUSCODE_GOOD)
        client->endpointsHandshake = true;
    else
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "RequestGetEndpoints failed when sending the request with error code %s",
                     UA_StatusCode_name(retval));
    return retval;
}

static void
responseSessionCallback(UA_Client *client, void *userdata,
                        UA_UInt32 requestId, void *response) {
    UA_LOCK(&client->clientMutex);

    UA_CreateSessionResponse *sessionResponse = (UA_CreateSessionResponse*)response;
    UA_StatusCode res = sessionResponse->responseHeader.serviceResult;
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

#ifdef UA_ENABLE_ENCRYPTION
    if(client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        /* Verify the session response was created with the same certificate as
         * the SecureChannel */
        if(!UA_ByteString_equal(&sessionResponse->serverCertificate,
                                &client->channel.remoteCertificate)) {
            res = UA_STATUSCODE_BADCERTIFICATEINVALID;
            goto cleanup;
        }

        /* Verify the client signature */
        res = checkCreateSessionSignature(client, &client->channel, sessionResponse);
        if(res != UA_STATUSCODE_GOOD)
            goto cleanup;
    }
#endif

    /* Copy nonce and AuthenticationToken */
    UA_ByteString_clear(&client->remoteNonce);
    UA_NodeId_clear(&client->authenticationToken);
    res |= UA_ByteString_copy(&sessionResponse->serverNonce, &client->remoteNonce);
    res |= UA_NodeId_copy(&sessionResponse->authenticationToken,
                          &client->authenticationToken);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    /* Activate the new Session */
    client->sessionState = UA_SESSIONSTATE_CREATED;

 cleanup:
    client->connectStatus = res;
    if(client->connectStatus != UA_STATUSCODE_GOOD)
        client->sessionState = UA_SESSIONSTATE_CLOSED;

    UA_UNLOCK(&client->clientMutex);
}

static UA_StatusCode
createSessionAsync(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    /* Generate the local nonce for the session */
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        if(client->localNonce.length != UA_SESSION_LOCALNONCELENGTH) {
           UA_ByteString_clear(&client->localNonce);
            res = UA_ByteString_allocBuffer(&client->localNonce,
                                            UA_SESSION_LOCALNONCELENGTH);
            if(res != UA_STATUSCODE_GOOD)
                return res;
        }
        res = client->channel.endpoint->securityPolicy->symmetricModule.
                 generateNonce(client->channel.endpoint->securityPolicy->policyContext,
                               &client->localNonce);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    /* Prepare and send the request */
    UA_CreateSessionRequest request;
    UA_CreateSessionRequest_init(&request);
    request.requestHeader.requestHandle = ++client->requestHandle;
    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;
    request.clientNonce = client->localNonce;
    request.requestedSessionTimeout = client->config.requestedSessionTimeout;
    request.maxResponseMessageSize = UA_INT32_MAX;
    request.endpointUrl = client->config.endpointDescription.endpointUrl;
    request.clientDescription = client->config.clientDescription;
    if(client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        client->channel.endpoint->securityPolicy->getLocalCertificate(client->channel.endpoint->securityPolicy,
                                                                      client->channel.endpoint->pkiStore,
                                                                      &request.clientCertificate);
    }

    res = __Client_AsyncServiceEx(client, &request,
                                  &UA_TYPES[UA_TYPES_CREATESESSIONREQUEST],
                                  (UA_ClientAsyncServiceCallback)responseSessionCallback,
                                  &UA_TYPES[UA_TYPES_CREATESESSIONRESPONSE], NULL, NULL,
                                  client->config.timeout);

    if(res == UA_STATUSCODE_GOOD)
        client->sessionState = UA_SESSIONSTATE_CREATE_REQUESTED;
    else
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "CreateSession failed when sending the request with "
                     "error code %s", UA_StatusCode_name(res));

    return res;
}

static UA_StatusCode
initSecurityPolicy(UA_Client *client) {

    client->channel.securityMode = client->config.endpointDescription.securityMode;

    if(client->channel.securityMode == UA_MESSAGESECURITYMODE_INVALID) {
        client->channel.securityMode = UA_MESSAGESECURITYMODE_NONE;
    }
    
    /* Lookup the pki store */
    UA_PKIStore *pkiStore = NULL;
    for(size_t i = 0; i < client->config.pkiStoresSize; ++i) {
        if(UA_NodeId_equal(&client->config.certificateGroupId, &client->config.pkiStores[i].certificateGroupId)) {
            pkiStore = &client->config.pkiStores[i];
        }
    }

    /* Get Security Policy */
    UA_SecurityPolicy *sp = NULL;
    if(client->config.endpointDescription.securityPolicyUri.length == 0) {
        sp = getSecurityPolicy(client,
                               UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#None"));
    } else {
        sp = getSecurityPolicy(client, client->config.endpointDescription.securityPolicyUri);
    }

    /* set remote certificate */
    UA_ByteString_copy(
        &client->config.endpointDescription.serverCertificate,
		&client->channel.remoteCertificate
	);

    /* Create new Context */
    UA_StatusCode retVal = sp->channelModule.
        newContext(sp, pkiStore, &client->channel.remoteCertificate, &client->channel.channelContext);
    UA_CHECK_STATUS_WARN(retVal, return retVal, sp->logger,
                         UA_LOGCATEGORY_SECURITYPOLICY,
                         "Could not set up the SecureChannel context");

    UA_ByteString remoteCertificateThumbprint =
        {20, client->channel.remoteCertificateThumbprint};
    retVal = sp->asymmetricModule.
        makeCertificateThumbprint(sp, &client->channel.remoteCertificate,
                                  &remoteCertificateThumbprint);
    UA_CHECK_STATUS_WARN(retVal, return retVal, sp->logger,
                         UA_LOGCATEGORY_SECURITYPOLICY,
                         "Could not create the certificate thumbprint");

    /* Check if endpoint already exist */
    UA_Endpoint* endpoint = (UA_Endpoint*)(unsigned long)client->channel.endpoint;
    if (endpoint != NULL) {
    	UA_Endpoint_clear(endpoint);
    	UA_free(endpoint);
    	client->channel.endpoint = NULL;
    }

    /* Create Endpoint */
    endpoint = (UA_Endpoint*)UA_malloc(sizeof(UA_Endpoint));
    if (endpoint == NULL) {
    	return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    retVal = UA_Endpoint_init(endpoint);
    if (retVal != UA_STATUSCODE_GOOD) {
    	return retVal;
    }

    retVal = UA_Endpoint_setValues(
    	endpoint,
		&client->config.endpointDescription.endpointUrl,
        pkiStore,
        sp,
		false,
		false,
		false,
		client->config.endpointDescription.server,
		&client->config.userTokenPolicy,
		1
	);
    if (retVal != UA_STATUSCODE_GOOD) {
    	return retVal;
    }

    client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
    if(sp) {
        client->connectStatus =
            UA_SecureChannel_setEndpoint(&client->channel, endpoint);
    }

    return UA_STATUSCODE_GOOD;
}

static void
connectActivity(UA_Client *client) {
    UA_LOG_TRACE(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                 "Client connect iterate");

    /* Could not connect with an error that canot be recovered from */
    if(client->connectStatus != UA_STATUSCODE_GOOD)
        return;

    /* Already connected */
    if(client->sessionState == UA_SESSIONSTATE_ACTIVATED)
        return;

    /* Switch on the SecureChannel state */
    switch(client->channel.state) {
        /* Nothing to do if the connection has not opened fully */
    case UA_SECURECHANNELSTATE_CONNECTING:
    case UA_SECURECHANNELSTATE_CLOSING:
        return;

        /* Send HEL */
    case UA_SECURECHANNELSTATE_CONNECTED:
        client->connectStatus = sendHELMessage(client);
        return;

        /* ACK receieved. Send OPN. */
    case UA_SECURECHANNELSTATE_ACK_RECEIVED:
        if(client->connectStatus == UA_STATUSCODE_GOOD)
            client->connectStatus = sendOPNAsync(client, false); /* Send OPN */
        return;

        /* The channel is open -> continue with the Session handling */
    case UA_SECURECHANNELSTATE_OPEN:
        break;

        /* The connection is closed. Reset the SecureChannel and open a new TCP
         * connection */
    case UA_SECURECHANNELSTATE_CLOSED:
        client->connectStatus = initConnect(client);
        return;

        /* These states should never occur for the client */
    default:
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
        return;
    }

    /* <-- The SecureChannel is open --> */

    /* Ongoing endpoints handshake? */
    if(client->endpointsHandshake)
        return;

    /* Get the endpoints in order to reset the SecureChannel with encryption */
    if(endpointUnconfigured(client)) {
        client->connectStatus = requestGetEndpoints(client);
        return;
    }

    /* Do we want to open a session? */
    if(client->noSession)
        return;

    /* Create and Activate the Session */
    switch(client->sessionState) {
        /* Send a CreateSessionRequest */
    case UA_SESSIONSTATE_CLOSED:
        client->connectStatus = createSessionAsync(client);
        return;

        /* Activate the Session */
    case UA_SESSIONSTATE_CREATED:
        client->connectStatus = activateSessionAsync(client);
        return;

    case UA_SESSIONSTATE_CREATE_REQUESTED:
    case UA_SESSIONSTATE_ACTIVATE_REQUESTED:
    case UA_SESSIONSTATE_ACTIVATED:
    case UA_SESSIONSTATE_CLOSING:
        return; /* Nothing to do */

        /* These states should never occur for the client */
    default:
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
        break;
    }
}

static UA_StatusCode
verifyClientSecurechannelHeader(void *application, UA_SecureChannel *channel,
                                const UA_AsymmetricAlgorithmSecurityHeader *asymHeader) {
    /* TODO: Verify if certificate is the same as configured in the client
     * endpoint config */
    return UA_STATUSCODE_GOOD;
}

/* The local ApplicationURI has to match the certificates of the
 * SecurityPolicies */
static void
verifyClientApplicationURI(UA_Client *client) {

	if (client->channel.endpoint == NULL) return;
	if (client->channel.endpoint->securityPolicy == NULL) return;
	if (client->channel.endpoint->securityPolicy->getLocalCertificate == NULL) return;

#if defined(UA_ENABLE_ENCRYPTION) && (UA_LOGLEVEL <= 400)
    for(size_t i = 0; i < client->config.securityPoliciesSize; i++) {
        UA_SecurityPolicy *sp = &client->config.securityPolicies[i];
        
        UA_ByteString localCertificate;
        UA_ByteString_init(&localCertificate);
        client->channel.endpoint->securityPolicy->getLocalCertificate(
        	client->channel.endpoint->securityPolicy,
            client->channel.endpoint->pkiStore,
            &localCertificate
	    );
      
        if(!localCertificate.data) {
                UA_LOG_WARNING(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                "skip verifying ApplicationURI for the SecurityPolicy %.*s",
                (int)sp->policyUri.length, sp->policyUri.data);
                continue;
        }

        UA_StatusCode retval =
            client->config.certificateManager.
                verifyApplicationURI(&client->config.certificateManager,
                                     client->channel.endpoint->pkiStore,
                                     &localCertificate,
                                     &client->config.clientDescription.applicationUri);
        UA_ByteString_clear(&localCertificate);

        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                           "The configured ApplicationURI does not match the URI "
                           "specified in the certificate for the SecurityPolicy %.*s",
                           (int)sp->policyUri.length, sp->policyUri.data);
        }
    }
#endif
}

static void
__Client_networkCallback(UA_ConnectionManager *cm, uintptr_t connectionId,
                         void *application, void **connectionContext,
                         UA_ConnectionState state, const UA_KeyValueMap *params,
                         UA_ByteString msg) {
    /* Take the client lock */
    UA_Client *client = (UA_Client*)application;
    UA_LOCK(&client->clientMutex);

    UA_LOG_TRACE(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                 "Client network callback");

    /* A new connection is not yet registered */
    if(!*connectionContext) {
        /* Opening the connection failed. The client cannot recover from this. */
        if(state != UA_CONNECTIONSTATE_OPENING &&
           state != UA_CONNECTIONSTATE_ESTABLISHED) {
            goto refuse_connection;
        }

        /* Inconsistent SecureChannel state. Has to be fresh for a new
         * connection. */
        if(client->channel.state != UA_SECURECHANNELSTATE_FRESH) {
            UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                         "Cannot open a connection for SecureChannel that is already used");
            client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
            printf("RESUSE CONNECTION\n");
            goto refuse_connection;
        }

        /* Initialize the client connection and attach to the EventLoop connection */
        client->channel.connectionManager = cm;
        client->channel.connectionId = connectionId;
        *connectionContext = &client->channel;

        /* If the connection is not fully established we still save the
         * connectionId in the client now so that the connection can be closed
         * before it fully opens. Wait for the connection to be established
         * before sending the HEL message. */
        if(state == UA_CONNECTIONSTATE_OPENING)
            client->channel.state = UA_SECURECHANNELSTATE_CONNECTING;
        else /* state == UA_CONNECTIONSTATE_ESTABLISHED */
            client->channel.state = UA_SECURECHANNELSTATE_CONNECTED;
        
        goto continue_connect;
    }
    /* The connection is closing in the EventLoop. This is the last callback
     * from that connection. Clean up the SecureChannel in the client. */
    if(state == UA_CONNECTIONSTATE_CLOSING) {
        /* Set to closing (could be done already in UA_SecureChannel_shutdown).
         * This impacts the handling of cancelled requests below. */
        UA_SecureChannelState oldState = client->channel.state;
        client->channel.state = UA_SECURECHANNELSTATE_CLOSING;

        /* Set the Session to CREATED if it was ACTIVATED */
        if(client->sessionState == UA_SESSIONSTATE_ACTIVATED)
            client->sessionState = UA_SESSIONSTATE_CREATED;

        /* Delete outstanding async services - the RequestId is no longer valid. Do
         * this after setting the Session state. Otherwise we send out new Publish
         * Requests immediately. */
        __Client_AsyncService_removeAll(client, UA_STATUSCODE_BADSECURECHANNELCLOSED);

        /* clean endpoint from secure channel */
        UA_Endpoint* endpoint = (UA_Endpoint*)(unsigned long)client->channel.endpoint;
        if (endpoint != NULL) {
        	UA_Endpoint_clear(endpoint);
        	UA_free(endpoint);
        	client->channel.endpoint = NULL;
        }

        /* Clean up the channel and set the status to CLOSED */
        UA_SecureChannel_clear(&client->channel);

        /* The connection closed before it actually opened. Since we are
         * connecting asynchronously, this happens when the server does not
         * exist or is unresponsive. */
        if(oldState == UA_SECURECHANNELSTATE_CONNECTING) {
            UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel,
                                "Could not open the connection");
            goto refuse_connection; /* The client cannot recover from this */
        }

        UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel,
                            "Closed the SecureChannel");

        /* Try to reconnect */
        goto continue_connect;
    }

    /* The connection has oepened, set the SecureChannel state to reflect this.
     * Otherwise later consistency checks for the received messages fail. */
    if(client->channel.state < UA_SECURECHANNELSTATE_CONNECTED)
        client->channel.state = UA_SECURECHANNELSTATE_CONNECTED;

    /* Received a message. Process the message with the SecureChannel. */
    UA_StatusCode res =
        UA_SecureChannel_processBuffer(&client->channel, client,
                                       processServiceResponse, &msg);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                       "Processing the message returned the error code %s",
                       UA_StatusCode_name(res));

        /* Close the SecureChannel, but don't notify the client right away.
         * Return immediately. notifyClientState will be called in the next
         * callback from the ConnectionManager when the connection closes with a
         * StatusCode. */
        closeSecureChannel(client);
        UA_UNLOCK(&client->clientMutex);
        return;
    }

    /* Trigger the next action from our end to fully open up the connection */
 continue_connect:
    if((client->noSession && client->channel.state != UA_SECURECHANNELSTATE_OPEN) ||
       client->sessionState < UA_SESSIONSTATE_ACTIVATED) {
        connectActivity(client);
    }

    /* Notify the application if the client state has changed */
    notifyClientState(client);
    UA_UNLOCK(&client->clientMutex);
    return;

 refuse_connection:
    client->connectStatus = UA_STATUSCODE_BADCONNECTIONREJECTED;
    notifyClientState(client);
    UA_UNLOCK(&client->clientMutex);
}

/* Initialize a TCP connection. Writes the result to client->connectStatus. */
static UA_StatusCode
initConnect(UA_Client *client) {
    if(client->noReconnect)
        return UA_STATUSCODE_BADNOTCONNECTED;

    if(client->channel.state != UA_SECURECHANNELSTATE_FRESH &&
       client->channel.state != UA_SECURECHANNELSTATE_CLOSED) {
        UA_LOG_WARNING(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                       "Client connection already initiated");
        return UA_STATUSCODE_GOOD;
    }

    /* Start the EventLoop if not already started */
    UA_StatusCode res = __UA_Client_startup(client);
    UA_CHECK_STATUS(res, return res);

    /* Reset the connect status */
    client->connectStatus = UA_STATUSCODE_GOOD;
    client->channel.renewState = UA_SECURECHANNELRENEWSTATE_NORMAL;

    /* Initialize the SecureChannel */
    UA_SecureChannel_init(&client->channel);
    client->channel.config = client->config.localConnectionConfig;
    client->channel.certificateManager = &client->config.certificateManager;
    client->channel.processOPNHeader = verifyClientSecurechannelHeader;

    /* Initialize the SecurityPolicy */
    initSecurityPolicy(client);

    /* Consistency check the client's own ApplicationURI */
    verifyClientApplicationURI(client);

    /* Extract hostname and port from the URL */
    UA_String hostname = UA_STRING_NULL;
    UA_String path = UA_STRING_NULL;
    UA_UInt16 port = 4840;

    res = UA_parseEndpointUrl(&client->endpointUrl, &hostname, &port, &path);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(&client->config.logger, UA_LOGCATEGORY_NETWORK,
                       "OPC UA URL is invalid: %.*s",
                       (int)client->endpointUrl.length, client->endpointUrl.data);
        return res;
    }

    /* Initialize the TCP connection */
    UA_String tcpString = UA_STRING("tcp");
    res = UA_STATUSCODE_BADINTERNALERROR;
    for(UA_EventSource *es = client->config.eventLoop->eventSources;
        es != NULL; es = es->next) {
        /* Is this a usable connection manager? */
        if(es->eventSourceType != UA_EVENTSOURCETYPE_CONNECTIONMANAGER)
            continue;
        UA_ConnectionManager *cm = (UA_ConnectionManager*)es;
        if(!UA_String_equal(&tcpString, &cm->protocol))
            continue;

        /* Set up the parameters */
        UA_KeyValuePair params[2];
        params[0].key = UA_QUALIFIEDNAME(0, "port");
        UA_Variant_setScalar(&params[0].value, &port, &UA_TYPES[UA_TYPES_UINT16]);
        params[1].key = UA_QUALIFIEDNAME(0, "hostname");
        UA_Variant_setScalar(&params[1].value, &hostname, &UA_TYPES[UA_TYPES_STRING]);

        UA_KeyValueMap paramMap;
        paramMap.map = params;
        paramMap.mapSize = 2;

        /* Open the client TCP connection */
        UA_UNLOCK(&client->clientMutex);
        res = cm->openConnection(cm, &paramMap, client, NULL, __Client_networkCallback);
        UA_LOCK(&client->clientMutex);
        if(res == UA_STATUSCODE_GOOD)
            break;
    }

    /* Opening the TCP connection failed */
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                       "Could not open a TCP connection to %.*s",
                       (int)client->endpointUrl.length, client->endpointUrl.data);
        res = UA_STATUSCODE_BADCONNECTIONCLOSED;
    }
    return res;
}

UA_StatusCode
UA_Client_connectAsync(UA_Client *client, const char *endpointUrl) {
    UA_LOCK(&client->clientMutex);
    client->noReconnect = false;

    /* Set the endpoint URL the client connects to */
    UA_String_clear(&client->endpointUrl);
    client->endpointUrl = UA_STRING_ALLOC(endpointUrl);

    /* Open a Session when possible */
    client->noSession = false;

    /* Connect Async */
    client->connectStatus = initConnect(client);
    notifyClientState(client);

    UA_UNLOCK(&client->clientMutex);
    return client->connectStatus;
}

UA_StatusCode
UA_Client_connectSecureChannelAsync(UA_Client *client, const char *endpointUrl) {
    UA_LOCK(&client->clientMutex);
    client->noReconnect = false;

    /* Set the endpoint URL the client connects to */
    UA_String_clear(&client->endpointUrl);
    client->endpointUrl = UA_STRING_ALLOC(endpointUrl);

    /* Don't open a Session */
    client->noSession = true;

    /* Connect Async */
    client->connectStatus = initConnect(client);
    notifyClientState(client);

    UA_UNLOCK(&client->clientMutex);
    return client->connectStatus;
}

void
connectSync(UA_Client *client) {
    UA_LOCK_ASSERT(&client->clientMutex, 1);

    UA_DateTime now = UA_DateTime_nowMonotonic();
    UA_DateTime maxDate = now + ((UA_DateTime)client->config.timeout * UA_DATETIME_MSEC);

    /* Initialize the connection */
    client->connectStatus = initConnect(client);
    notifyClientState(client);
    if(client->connectStatus != UA_STATUSCODE_GOOD)
        return;

    /* EventLoop is started. Otherwise initConnect would have failed. */
    UA_EventLoop *el = client->config.eventLoop;
    UA_assert(el);

    /* Run the EventLoop until connected, connect fail or timeout. Write the
     * iterate result to the connectStatus. So we do not attempt to restore a
     * failed connection during the sync connect. */
    while(client->connectStatus == UA_STATUSCODE_GOOD) {
        if(client->sessionState == UA_SESSIONSTATE_ACTIVATED)
            break;
        if(client->noSession && client->channel.state == UA_SECURECHANNELSTATE_OPEN)
            break;
        now = UA_DateTime_nowMonotonic();
        if(maxDate < now) {
            /* TODO: Close the SecureChannel properly */
            client->connectStatus = UA_STATUSCODE_BADTIMEOUT;
            return;
        }
        UA_UNLOCK(&client->clientMutex);
        UA_StatusCode res = el->run(el, (UA_UInt32)((maxDate - now) / UA_DATETIME_MSEC));
        UA_LOCK(&client->clientMutex);
        if(res != UA_STATUSCODE_GOOD) {
            closeSecureChannel(client);
            client->connectStatus = res;
        }
    }
}

UA_StatusCode
UA_Client_connect(UA_Client *client, const char *endpointUrl) {
    UA_LOCK(&client->clientMutex);
    client->noReconnect = false;

    /* Set the endpoint URL the client connects to */
    UA_String_clear(&client->endpointUrl);
    client->endpointUrl = UA_STRING_ALLOC(endpointUrl);

    /* Open a Session when possible */
    client->noSession = false;

    /* Connect Synchronous */
    connectSync(client);

    UA_UNLOCK(&client->clientMutex);
    return client->connectStatus;
}

UA_StatusCode
UA_Client_connectSecureChannel(UA_Client *client, const char *endpointUrl) {
    UA_LOCK(&client->clientMutex);

    client->noReconnect = false;

    /* Set the endpoint URL the client connects to */
    UA_String_clear(&client->endpointUrl);
    client->endpointUrl = UA_STRING_ALLOC(endpointUrl);

    /* Don't open a Session */
    client->noSession = true;

    /* Connect Synchronous */
    connectSync(client);

    UA_UNLOCK(&client->clientMutex);
    return client->connectStatus;
}

/************************/
/* Close the Connection */
/************************/

void
closeSecureChannel(UA_Client *client) {
    /* Prevent recursion */
    if(client->channel.state == UA_SECURECHANNELSTATE_CLOSING ||
       client->channel.state == UA_SECURECHANNELSTATE_CLOSED)
        return;

    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                         "Closing the channel");

    /* Send CLO if the SecureChannel is open */
    if(client->channel.state == UA_SECURECHANNELSTATE_OPEN) {
        UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                             "Sending the CLO message");
        UA_CloseSecureChannelRequest request;
        UA_CloseSecureChannelRequest_init(&request);
        request.requestHeader.requestHandle = ++client->requestHandle;
        request.requestHeader.timestamp = UA_DateTime_now();
        request.requestHeader.timeoutHint = 10000;
        request.requestHeader.authenticationToken = client->authenticationToken;
        UA_SecureChannel_sendSymmetricMessage(&client->channel, ++client->requestId,
                                              UA_MESSAGETYPE_CLO, &request,
                                              &UA_TYPES[UA_TYPES_CLOSESECURECHANNELREQUEST]);
    }

    /* The connection is eventually closed in the next callback from the
     * ConnectionManager with the appropriate status code. Don't set the
     * connection closed right away! */
    UA_SecureChannel_shutdown(&client->channel);
}

static void
sendCloseSession(UA_Client *client) {
    UA_CloseSessionRequest request;
    UA_CloseSessionRequest_init(&request);
    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;
    request.deleteSubscriptions = true;
    UA_CloseSessionResponse response;
    __Client_Service(client, &request, &UA_TYPES[UA_TYPES_CLOSESESSIONREQUEST],
                        &response, &UA_TYPES[UA_TYPES_CLOSESESSIONRESPONSE]);
    UA_CloseSessionRequest_clear(&request);
    UA_CloseSessionResponse_clear(&response);

    /* Set after sending the message to prevent immediate reoping during the
     * service call */
    client->sessionState = UA_SESSIONSTATE_CLOSING;
}

void
cleanupSession(UA_Client *client) {
    UA_NodeId_clear(&client->authenticationToken);
    client->requestHandle = 0;

#ifdef UA_ENABLE_SUBSCRIPTIONS
    /* We need to clean up the subscriptions */
    __Client_Subscriptions_clean(client);
#endif

    /* Reset so the next async connect creates a session by default */
    client->noSession = false;

    /* Delete outstanding async services */
    __Client_AsyncService_removeAll(client, UA_STATUSCODE_BADSESSIONCLOSED);

#ifdef UA_ENABLE_SUBSCRIPTIONS
    client->currentlyOutStandingPublishRequests = 0;
#endif

    client->sessionState = UA_SESSIONSTATE_CLOSED;
}

static void
closeSessionCallback(UA_Client *client, void *userdata,
                     UA_UInt32 requestId, void *response) {
    UA_LOCK(&client->clientMutex);
    cleanupSession(client);
    closeSecureChannel(client);
    notifyClientState(client);
    UA_UNLOCK(&client->clientMutex);
}

UA_StatusCode
UA_Client_disconnectAsync(UA_Client *client) {
    UA_LOCK(&client->clientMutex);

    client->noReconnect = true;

    if(client->sessionState == UA_SESSIONSTATE_CLOSED ||
       client->sessionState == UA_SESSIONSTATE_CLOSING) {
        closeSecureChannel(client);
        UA_UNLOCK(&client->clientMutex);
        return UA_STATUSCODE_GOOD;
    }

    /* Set before sending the message to prevent recursion */
    client->sessionState = UA_SESSIONSTATE_CLOSING;

    UA_CloseSessionRequest request;
    UA_CloseSessionRequest_init(&request);
    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;
    request.deleteSubscriptions = true;
    UA_StatusCode res =
        __Client_AsyncServiceEx(client, &request, &UA_TYPES[UA_TYPES_CLOSESESSIONREQUEST],
                                (UA_ClientAsyncServiceCallback)closeSessionCallback,
                                &UA_TYPES[UA_TYPES_CLOSESESSIONRESPONSE], NULL, NULL,
                                client->config.timeout);
    if(res != UA_STATUSCODE_GOOD) {
        /* Sending the close request failed. Continue to close the connection
         * anyway. */
        cleanupSession(client);
        closeSecureChannel(client);
    }
    notifyClientState(client);

    UA_UNLOCK(&client->clientMutex);
    return res;
}

UA_StatusCode
UA_Client_disconnectSecureChannel(UA_Client *client) {
    UA_LOCK(&client->clientMutex);

    client->noReconnect = true;
    closeSecureChannel(client);

    /* Manually set the status to closed to prevent an automatic reconnection */
    client->connectStatus = UA_STATUSCODE_BADCONNECTIONCLOSED;

    /* Closing is async. Loop until the client has actually closed. */
    UA_EventLoop *el = client->config.eventLoop;
    if(el &&
       el->state != UA_EVENTLOOPSTATE_FRESH &&
       el->state != UA_EVENTLOOPSTATE_STOPPED) {
        UA_UNLOCK(&client->clientMutex);
        while(client->channel.state != UA_SECURECHANNELSTATE_CLOSED) {
            el->run(el, 100);
        }
        UA_LOCK(&client->clientMutex);
    }

    notifyClientState(client);

    UA_UNLOCK(&client->clientMutex);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Client_disconnect(UA_Client *client) {
    UA_LOCK(&client->clientMutex);
    client->noReconnect = true;
    if(client->sessionState == UA_SESSIONSTATE_ACTIVATED)
        sendCloseSession(client);
    cleanupSession(client);
    UA_UNLOCK(&client->clientMutex);
    UA_StatusCode res = UA_Client_disconnectSecureChannel(client);
    return res;
}
