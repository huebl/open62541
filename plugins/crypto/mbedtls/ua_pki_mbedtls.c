/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2019 (c) Kalycito Infotech Private Limited
 *    Copyright 2019 (c) Julius Pfrommer, Fraunhofer IOSB
 */

#include <open62541/util.h>
#include <open62541/plugin/pki_default.h>
#include <open62541/plugin/log_stdout.h>
#include "san_mbedtls.h"

#ifdef UA_ENABLE_ENCRYPTION_MBEDTLS

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#define REMOTECERTIFICATETRUSTED 1
#define ISSUERKNOWN              2
#define DUALPARENT               3
#define PARENTFOUND              4

/* Find binary substring. Taken and adjusted from
 * http://tungchingkai.blogspot.com/2011/07/binary-strstr.html */

static const unsigned char *
bstrchr(const unsigned char *s, const unsigned char ch, size_t l) {
    /* find first occurrence of c in char s[] for length l*/
    for(; l > 0; ++s, --l) {
        if(*s == ch)
            return s;
    }
    return NULL;
}

static const unsigned char *
UA_Bstrstr(const unsigned char *s1, size_t l1, const unsigned char *s2, size_t l2) {
    /* find first occurrence of s2[] in s1[] for length l1*/
    const unsigned char *ss1 = s1;
    const unsigned char *ss2 = s2;
    /* handle special case */
    if(l1 == 0)
        return (NULL);
    if(l2 == 0)
        return s1;

    /* match prefix */
    for (; (s1 = bstrchr(s1, *s2, (uintptr_t)ss1-(uintptr_t)s1+(uintptr_t)l1)) != NULL &&
             (uintptr_t)ss1-(uintptr_t)s1+(uintptr_t)l1 != 0; ++s1) {

        /* match rest of prefix */
        const unsigned char *sc1, *sc2;
        for (sc1 = s1, sc2 = s2; ;)
            if (++sc2 >= ss2+l2)
                return s1;
            else if (*++sc1 != *sc2)
                break;
    }
    return NULL;
}

// mbedTLS expects PEM data to be null terminated
// The data length parameter must include the null terminator
static UA_ByteString copyDataFormatAware(const UA_ByteString *data)
{
    UA_ByteString result;
    UA_ByteString_init(&result);

    if (!data->length)
        return result;

    if (data->length && data->data[0] == '-') {
        UA_ByteString_allocBuffer(&result, data->length + 1);
        memcpy(result.data, data->data, data->length);
        result.data[data->length] = '\0';
    } else {
        UA_ByteString_copy(data, &result);
    }

    return result;
}

typedef struct {
    mbedtls_x509_crt trustedCertificates;
    mbedtls_x509_crt trustedIssuers;
    mbedtls_x509_crl trustedCertificateCrls;
    mbedtls_x509_crl trustedIssuerCrls;
} CertInfo;

#ifdef __linux__ /* Linux only so far */

#include <dirent.h>
#include <limits.h>
#include "open62541/plugin/certstore.h"

//static UA_StatusCode
//fileNamesFromFolder(const UA_String *folder, size_t *pathsSize, UA_String **paths) {
//    char buf[PATH_MAX + 1];
//    if(folder->length > PATH_MAX)
//        return UA_STATUSCODE_BADINTERNALERROR;
//
//    memcpy(buf, folder->data, folder->length);
//    buf[folder->length] = 0;
//
//    DIR *dir = opendir(buf);
//    if(!dir)
//        return UA_STATUSCODE_BADINTERNALERROR;
//
//    *paths = (UA_String*)UA_Array_new(256, &UA_TYPES[UA_TYPES_STRING]);
//    if(*paths == NULL) {
//        closedir(dir);
//        return UA_STATUSCODE_BADOUTOFMEMORY;
//    }
//
//    struct dirent *ent;
//    char buf2[PATH_MAX + 1];
//    char *res = realpath(buf, buf2);
//    if(!res) {
//        closedir(dir);
//        return UA_STATUSCODE_BADINTERNALERROR;
//    }
//    size_t pathlen = strlen(buf2);
//    *pathsSize = 0;
//    while((ent = readdir (dir)) != NULL && *pathsSize < 256) {
//        if(ent->d_type != DT_REG)
//            continue;
//        buf2[pathlen] = '/';
//        buf2[pathlen+1] = 0;
//        strcat(buf2, ent->d_name);
//        (*paths)[*pathsSize] = UA_STRING_ALLOC(buf2);
//        *pathsSize += 1;
//    }
//    closedir(dir);
//
//    if(*pathsSize == 0) {
//        UA_free(*paths);
//        *paths = NULL;
//    }
//    return UA_STATUSCODE_GOOD;
//}

static UA_StatusCode
reloadCertificates(CertInfo *ci, UA_PKIStore *pkiStore) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    int err = 0;

    UA_ByteString data;
    UA_ByteString_init(&data);

    UA_TrustListDataType trustList; /* FIXME: HUK Speicher freigeben */
    memset((char*)&trustList, 0x00, sizeof(UA_TrustListDataType));
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    retval = pkiStore->loadTrustList(pkiStore, &trustList);
    if(!UA_StatusCode_isGood(retval))
        goto error;

    for(size_t i = 0; i < trustList.trustedCertificatesSize; ++i) {
        data = copyDataFormatAware(&trustList.trustedCertificates[i]);
        err = mbedtls_x509_crt_parse(&ci->trustedCertificates,
                                     data.data,
                                     data.length);
        UA_ByteString_clear(&data);
        if(err)
            goto error;
    }
    for(size_t i = 0; i < trustList.issuerCertificatesSize; ++i) {
        data = copyDataFormatAware(&trustList.issuerCertificates[i]);
        err = mbedtls_x509_crt_parse(&ci->trustedIssuers,
                                     data.data,
                                     data.length);
        UA_ByteString_clear(&data);
        if(err)
            goto error;
    }
    for(size_t i = 0; i < trustList.trustedCrlsSize; i++) {
        data = copyDataFormatAware(&trustList.trustedCrls[i]);
        err = mbedtls_x509_crl_parse(&ci->trustedCertificateCrls,
                                     data.data,
                                     data.length);
        UA_ByteString_clear(&data);
        if(err)
            goto error;
    }
    for(size_t i = 0; i < trustList.issuerCrlsSize; i++) {
        data = copyDataFormatAware(&trustList.issuerCrls[i]);
        err = mbedtls_x509_crl_parse(&ci->trustedIssuerCrls,
                                     data.data,
                                     data.length);
        UA_ByteString_clear(&data);
        if(err)
            goto error;
    }

//    /* Load the trustlists */
//    if(ci->trustListFolder.length > 0) {
//        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Reloading the trust-list");
//        mbedtls_x509_crt_free(&ci->trustedCertificates);
//        mbedtls_x509_crt_init(&ci->trustedCertificates);
//
//        char f[PATH_MAX];
//        memcpy(f, ci->trustListFolder.data, ci->trustListFolder.length);
//        f[ci->trustListFolder.length] = 0;
//        err = mbedtls_x509_crt_parse_path(&ci->trustedCertificates, f);
//        if(err == 0) {
//            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
//                        "Loaded certificate from %s", f);
//        } else {
//            char errBuff[300];
//            mbedtls_strerror(err, errBuff, 300);
//            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
//                        "Failed to load certificate from %s, mbedTLS error: %s (error code: %d)", f, errBuff, err);
//            internalErrorFlag = 1;
//        }
//    }
//
//    /* Load the revocationlists */
//    if(ci->revocationListFolder.length > 0) {
//        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Reloading the revocation-list");
//        size_t pathsSize = 0;
//        UA_String *paths = NULL;
//        retval = fileNamesFromFolder(&ci->revocationListFolder, &pathsSize, &paths);
//        if(retval != UA_STATUSCODE_GOOD)
//            return retval;
//        mbedtls_x509_crl_free(&ci->trustedCertificateCrls);
//        mbedtls_x509_crl_init(&ci->trustedCertificateCrls);
//        for(size_t i = 0; i < pathsSize; i++) {
//            char f[PATH_MAX];
//            memcpy(f, paths[i].data, paths[i].length);
//            f[paths[i].length] = 0;
//            err = mbedtls_x509_crl_parse_file(&ci->trustedCertificateCrls, f);
//            if(err == 0) {
//                UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
//                            "Loaded certificate from %.*s",
//                            (int)paths[i].length, paths[i].data);
//            } else {
//                char errBuff[300];
//                mbedtls_strerror(err, errBuff, 300);
//                UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
//                            "Failed to load certificate from %.*s, mbedTLS error: %s (error code: %d)",
//                            (int)paths[i].length, paths[i].data, errBuff, err);
//                internalErrorFlag = 1;
//            }
//        }
//        UA_Array_delete(paths, pathsSize, &UA_TYPES[UA_TYPES_STRING]);
//        paths = NULL;
//        pathsSize = 0;
//    }
//
//    /* Load the issuerlists */
//    if(ci->issuerListFolder.length > 0) {
//        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Reloading the issuer-list");
//        mbedtls_x509_crt_free(&ci->trustedIssuers);
//        mbedtls_x509_crt_init(&ci->trustedIssuers);
//        char f[PATH_MAX];
//        memcpy(f, ci->issuerListFolder.data, ci->issuerListFolder.length);
//        f[ci->issuerListFolder.length] = 0;
//        err = mbedtls_x509_crt_parse_path(&ci->trustedIssuers, f);
//        if(err == 0) {
//            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
//                        "Loaded certificate from %s", f);
//        } else {
//            char errBuff[300];
//            mbedtls_strerror(err, errBuff, 300);
//            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
//                        "Failed to load certificate from %s, mbedTLS error: %s (error code: %d)",
//                        f, errBuff, err);
//            internalErrorFlag = 1;
//        }
//    }

error:
    if(err) {
        retval = UA_STATUSCODE_BADINTERNALERROR;
    }
    return retval;
}

#endif

/* Create a ByteString filled with 'data' */
static UA_ByteString *byteStrNew(const unsigned char *data, size_t len) {
    UA_ByteString *dupstr = UA_ByteString_new();
    if (dupstr == NULL) {
        return NULL;
    }
    UA_ByteString_init(dupstr);
    if (UA_ByteString_allocBuffer(dupstr, len) != UA_STATUSCODE_GOOD) {
        return NULL;
    }
    memcpy(dupstr->data, data, len);
    return dupstr;
}

/* Create a copy of a ByteString */
static inline UA_ByteString *byteStrDup(const UA_ByteString *bstr) {
    return byteStrNew(bstr->data, bstr->length);
}


/* Add a rejected certificate and its signature to the list */
static UA_StatusCode rejectedList_add(const UA_ByteString *certificate,
                                      const mbedtls_x509_crt *remoteCertificate,
                                      UA_CertificateManager* certificateManager) {

#if 0 /* FIXME: HUK */
	if (certificate == NULL || remoteCertificate == NULL ||
	    certificateManager == NULL || certificateManager->context == NULL) {
	    return UA_STATUSCODE_BADINVALIDARGUMENT;
	}

	CertInfo *ci = (CertInfo *)certificateManager->context;
	UA_ByteString *sign = byteStrNew(remoteCertificate->sig.p, remoteCertificate->sig.len);
	if (sign == NULL) {
	    return UA_STATUSCODE_BADOUTOFMEMORY;
	}
	/* Ignore certificate if already in list */
	if (rejectedList_isDuplicate(sign, ci)) {
	    UA_ByteString_delete(sign);
	    return UA_STATUSCODE_GOOD;  /* Signature (and certificate) already in list */
	}
	UA_ByteString *cert = byteStrDup(certificate);
	if (cert == NULL) {
		UA_ByteString_delete(sign);
	    return UA_STATUSCODE_BADOUTOFMEMORY;
	}

	size_t offset = ci->certRejectListAddCount % ci->certRejectListSizeMax;

	if (ci->certRejectListSize < ci->certRejectListSizeMax) {
	    /* Extend the list */
	    ci->certRejectList = (CertRejectListItem *)UA_realloc(ci->certRejectList,
	                         (ci->certRejectListSize + 1) * sizeof(CertRejectListItem));
	    if (ci->certRejectList == NULL) {
	    	UA_ByteString_delete(sign);
	        UA_ByteString_delete(cert);
	        return UA_STATUSCODE_BADOUTOFMEMORY;
	    }
	    /* New empty list item created */
	    ci->certRejectListSize++;
	    ci->certRejectList[offset].cert = NULL;
	    ci->certRejectList[offset].sign = NULL;
	}

	/* store data in list item at position 'offset', delete former value if exists */
	certListItem_clear(offset, ci);
	ci->certRejectList[offset].cert = cert;
	ci->certRejectList[offset].sign = sign;
	ci->certRejectListAddCount++;
#endif
	return UA_STATUSCODE_GOOD;
}

/* Non static wrapper for unit (module) testing only */
UA_StatusCode rejectedList_add_for_testing(const UA_ByteString *certificate,
                                           UA_CertificateManager* certificateManager) {
#if 0 /* FIXME: HUK */
    if (certificate == NULL || certificateManager == NULL ||
        certificateManager->context == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    CertInfo *ci = (CertInfo *)certificateManager->context;

    /* Parse the certificate */
    mbedtls_x509_crt remoteCertificate;
    mbedtls_x509_crt_init(&remoteCertificate);
    int mbedStatus = mbedtls_x509_crt_parse(&remoteCertificate, certificate->data,
                                            certificate->length);

    if (mbedStatus) {
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }
    ci->certRejectListSizeMax = 3;
    UA_StatusCode retval = rejectedList_add(certificate, &remoteCertificate, certificateManager);
    mbedtls_x509_crt_free(&remoteCertificate);
    return retval;
#endif
    return UA_STATUSCODE_GOOD;
}

/* Get the rejected certificate list as a ByteString array */
UA_StatusCode rejectedList_get(UA_ByteString **byteStringArray, size_t *arraySize,
                               UA_CertificateManager* certificateManager) {
#if 0 /* FIXME: HUK */
    if (certificateManager == NULL || certificateManager->context) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    CertInfo *ci = (CertInfo *)certificateManager->context;
    if (arraySize == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    *arraySize = 0;
    if (byteStringArray == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    *byteStringArray =
        (UA_ByteString *)UA_Array_new(ci->certRejectListSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if (*byteStringArray == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    for (size_t i = 0; i < ci->certRejectListSize; i++) {
        UA_ByteString_init(*byteStringArray + i);
        if (UA_ByteString_allocBuffer(*byteStringArray + i,
                             ci->certRejectList[i].cert->length) != UA_STATUSCODE_GOOD) {
            *arraySize = i;  /* only i elements are copied */
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        memcpy(((*byteStringArray)+i)->data,
                ci->certRejectList[i].cert->data, ci->certRejectList[i].cert->length);
    }
    *arraySize = ci->certRejectListSize;
#endif
    return UA_STATUSCODE_GOOD;
}



static UA_StatusCode
do_certificateVerification_verify(UA_CertificateManager *certificateManager,
                                  UA_PKIStore *pkiStore,
                                  const UA_ByteString *certificate) {
    if(certificateManager == NULL || pkiStore == NULL || certificate == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    CertInfo *ci = (CertInfo *)certificateManager->context;
    if(!ci) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode certFlag = reloadCertificates(ci, pkiStore);
    if(certFlag != UA_STATUSCODE_GOOD) {
        return certFlag;
    }

    mbedtls_x509_crt remoteCertificate;
    mbedtls_x509_crt *tempCert = NULL;
    mbedtls_x509_crl *tempCrl = NULL;
    /* Temporary Object to identify the parent CA when there is no intermediate CA */
    mbedtls_x509_crt *parentCert = NULL;
    /* Temporary Object to identify the parent CA when there is intermediate CA */
    mbedtls_x509_crt *parentCert_2 = NULL;

    int issuerKnown = 0;
    int parentFound = 0;

    mbedtls_x509_crt_init(&remoteCertificate);
    int mbedErr = mbedtls_x509_crt_parse(&remoteCertificate, certificate->data,
                                         certificate->length);
    if(mbedErr) {
        /* char errBuff[300]; */
        /* mbedtls_strerror(mbedErr, errBuff, 300); */
        /* UA_LOG_WARNING(data->policyContext->securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY, */
        /*                "Could not parse the remote certificate with error: %s", errBuff); */
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    UA_StatusCode addResult = UA_STATUSCODE_GOOD;

    /* Verify */
    mbedtls_x509_crt_profile crtProfile = {
        MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1) | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256),
        0xFFFFFF, 0x000000, 128 * 8 // in bits
    }; // TODO: remove magic numbers

    uint32_t flags = 0;
    mbedErr = mbedtls_x509_crt_verify_with_profile(&remoteCertificate,
                                                   &ci->trustedCertificates,
                                                   &ci->trustedCertificateCrls,
                                                   &crtProfile, NULL, &flags, NULL, NULL);

    /* Flag to check if the remote certificate is trusted or not */
    int TRUSTED = 0;

    /* Check if the remoteCertificate is present in the trustList while mbedErr value is not zero */
    if(mbedErr && !(flags & MBEDTLS_X509_BADCERT_EXPIRED) && !(flags & MBEDTLS_X509_BADCERT_FUTURE)) {
        for(tempCert = &ci->trustedCertificates; tempCert != NULL; tempCert = tempCert->next) {
            if(remoteCertificate.raw.len == tempCert->raw.len &&
               memcmp(remoteCertificate.raw.p, tempCert->raw.p, remoteCertificate.raw.len) == 0) {
                TRUSTED = REMOTECERTIFICATETRUSTED;
                break;
            }
        }
    }

    /* If the remote certificate is present in the trustList then check if the issuer certificate
     * of remoteCertificate is present in issuerList */
    if(TRUSTED && mbedErr) {
        mbedErr = mbedtls_x509_crt_verify_with_profile(&remoteCertificate,
                                                       &ci->trustedIssuers,
                                                       &ci->trustedCertificateCrls,
                                                       &crtProfile, NULL, &flags, NULL, NULL);

        /* Check if the parent certificate has a CRL file available */
        if(!mbedErr) {
            /* Flag value to identify if that there is an intermediate CA present */
            int dualParent = 0;

            /* Identify the topmost parent certificate for the remoteCertificate */
            for(parentCert = &ci->trustedIssuers; parentCert != NULL; parentCert = parentCert->next) {
                if(memcmp(remoteCertificate.issuer_raw.p, parentCert->subject_raw.p, parentCert->subject_raw.len) ==
                   0) {
                    for(parentCert_2 = &ci->trustedCertificates;
                        parentCert_2 != NULL; parentCert_2 = parentCert_2->next) {
                        if(memcmp(parentCert->issuer_raw.p, parentCert_2->subject_raw.p,
                                  parentCert_2->subject_raw.len) == 0) {
                            dualParent = DUALPARENT;
                            break;
                        }
                    }
                    parentFound = PARENTFOUND;
                }

                if(parentFound == PARENTFOUND)
                    break;
            }

            /* Check if there is an intermediate certificate between the topmost parent
             * certificate and child certificate
             * If yes the topmost parent certificate is to be checked whether it has a
             * CRL file avaiable */
            if(dualParent == DUALPARENT && parentFound == PARENTFOUND) {
                parentCert = parentCert_2;
            }

            /* If a parent certificate is found traverse the revocationList and identify
             * if there is any CRL file that corresponds to the parentCertificate */
            if(parentFound == PARENTFOUND) {
                tempCrl = &ci->trustedCertificateCrls;
                while(tempCrl != NULL) {
                    if(tempCrl->version != 0 &&
                       tempCrl->issuer_raw.len == parentCert->subject_raw.len &&
                       memcmp(tempCrl->issuer_raw.p,
                              parentCert->subject_raw.p,
                              tempCrl->issuer_raw.len) == 0) {
                        issuerKnown = ISSUERKNOWN;
                        break;
                    }

                    tempCrl = tempCrl->next;
                }

                /* If the CRL file corresponding to the parent certificate is not present
                 * then return UA_STATUSCODE_BADCERTIFICATEISSUERREVOCATIONUNKNOWN */
                if(!issuerKnown) {
                	addResult = rejectedList_add(certificate, &remoteCertificate, certificateManager);
                	if (addResult != UA_STATUSCODE_GOOD) {
                		return addResult;
                	}
                    return UA_STATUSCODE_BADCERTIFICATEISSUERREVOCATIONUNKNOWN;
                }

            }

        }

    }
    else if(!mbedErr && !TRUSTED) {
        /* This else if section is to identify if the parent certificate which is present in trustList
         * has CRL file corresponding to it */

        /* Identify the parent certificate of the remoteCertificate */
        for(parentCert = &ci->trustedCertificates; parentCert != NULL; parentCert = parentCert->next) {
            if(memcmp(remoteCertificate.issuer_raw.p, parentCert->subject_raw.p, parentCert->subject_raw.len) == 0) {
                parentFound = PARENTFOUND;
                break;
            }

        }

        /* If the parent certificate is found traverse the revocationList and identify
         * if there is any CRL file that corresponds to the parentCertificate */
        if(parentFound == PARENTFOUND &&
            memcmp(remoteCertificate.issuer_raw.p, remoteCertificate.subject_raw.p, remoteCertificate.subject_raw.len) != 0) {
            tempCrl = &ci->trustedCertificateCrls;
            while(tempCrl != NULL) {
                if(tempCrl->version != 0 &&
                   tempCrl->issuer_raw.len == parentCert->subject_raw.len &&
                   memcmp(tempCrl->issuer_raw.p,
                          parentCert->subject_raw.p,
                          tempCrl->issuer_raw.len) == 0) {
                    issuerKnown = ISSUERKNOWN;
                    break;
                }

                tempCrl = tempCrl->next;
            }

            /* If the CRL file corresponding to the parent certificate is not present
             * then return UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN */
            if(!issuerKnown) {
            	addResult = rejectedList_add(certificate, &remoteCertificate, certificateManager);
            	if (addResult != UA_STATUSCODE_GOOD) {
            	    return addResult;
            	}
                return UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN;
            }

        }

    }

    // TODO: Extend verification

    /* This condition will check whether the certificate is a User certificate
     * or a CA certificate. If the MBEDTLS_X509_KU_KEY_CERT_SIGN and
     * MBEDTLS_X509_KU_CRL_SIGN of key_usage are set, then the certificate
     * shall be condidered as CA Certificate and cannot be used to establish a
     * connection. Refer the test case CTT/Security/Security Certificate Validation/029.js
     * for more details */
#if MBEDTLS_VERSION_NUMBER >= 0x02060000 && MBEDTLS_VERSION_NUMBER < 0x03000000
    if((remoteCertificate.key_usage & MBEDTLS_X509_KU_KEY_CERT_SIGN) &&
       (remoteCertificate.key_usage & MBEDTLS_X509_KU_CRL_SIGN)) {
        return UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED;
    }
#else
    if((remoteCertificate.private_key_usage & MBEDTLS_X509_KU_KEY_CERT_SIGN) &&
       (remoteCertificate.private_key_usage & MBEDTLS_X509_KU_CRL_SIGN)) {
    	addResult = rejectedList_add(certificate, &remoteCertificate, verificationContext);
    	if (addResult != UA_STATUSCODE_GOOD) {
    		return addResult;
    	}
        return UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED;
    }
#endif


    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(mbedErr) {
#if UA_LOGLEVEL <= 400
        char buff[100];
        int len = mbedtls_x509_crt_verify_info(buff, 100, "", flags);
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                       "Verifying the certificate failed with error: %.*s", len-1, buff);
#endif
        if(flags & (uint32_t)MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
            retval = UA_STATUSCODE_BADCERTIFICATEUNTRUSTED;
        } else if(flags & (uint32_t)MBEDTLS_X509_BADCERT_FUTURE ||
                  flags & (uint32_t)MBEDTLS_X509_BADCERT_EXPIRED) {
            retval = UA_STATUSCODE_BADCERTIFICATETIMEINVALID;
        } else if(flags & (uint32_t)MBEDTLS_X509_BADCERT_REVOKED ||
                  flags & (uint32_t)MBEDTLS_X509_BADCRL_EXPIRED) {
            retval = UA_STATUSCODE_BADCERTIFICATEREVOKED;
        } else {
            retval = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        }
    }

    mbedtls_x509_crt_free(&remoteCertificate);
    return retval;
}

static UA_StatusCode
certificateVerification_verify(UA_CertificateManager *certificateManager,
                               UA_PKIStore *pkiStore,
                               const UA_ByteString *certificate) {
    UA_StatusCode retval = do_certificateVerification_verify(certificateManager, pkiStore, certificate);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_StatusCode retval2 = pkiStore->appendRejectedList(pkiStore, certificate);
        if(retval2 != UA_STATUSCODE_GOOD) {
            // TODO: Log error
        }
    }
    return retval;
}

static UA_StatusCode
certificateVerification_verifyApplicationURI(UA_CertificateManager *certificateManager,
                                             UA_PKIStore *pkiStore,
                                             const UA_ByteString *certificate,
                                             const UA_String *applicationURI) {
	CertInfo *ci = (CertInfo *)certificateManager->context;
    if(!ci)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Parse the certificate */
    mbedtls_x509_crt remoteCertificate;
    mbedtls_x509_crt_init(&remoteCertificate);
    int mbedErr = mbedtls_x509_crt_parse(&remoteCertificate, certificate->data,
                                         certificate->length);
    if(mbedErr)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    /* Poor man's ApplicationUri verification. mbedTLS does not parse all fields
     * of the Alternative Subject Name. Instead test whether the URI-string is
     * present in the v3_ext field in general.
     *
     * TODO: Improve parsing of the Alternative Subject Name */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(UA_Bstrstr(remoteCertificate.v3_ext.p, remoteCertificate.v3_ext.len,
               applicationURI->data, applicationURI->length) == NULL)
        retval = UA_STATUSCODE_BADCERTIFICATEURIINVALID;

    mbedtls_x509_crt_free(&remoteCertificate);
    return retval;
}

/* Create the CSR using mbedTLS */
static UA_StatusCode CertificateManager_createCSR(
	UA_CertificateManager* certificateManager,
	UA_PKIStore* pkiStore,
	const UA_NodeId certificateTypeId,
    const UA_String *subject,
    const UA_ByteString *entropy,
    UA_ByteString **csr)
{
	UA_StatusCode retval = UA_STATUSCODE_GOOD;
	int ret = 0;
	*csr = NULL;

	/* Check parameter */
	if (certificateManager == NULL || pkiStore == NULL) {
		return UA_STATUSCODE_BADINVALIDARGUMENT;
	}

	/* Load own certificate from PKI Store */
	UA_ByteString certificateStr = UA_BYTESTRING_NULL;
	UA_ByteString_init(&certificateStr);
	retval = pkiStore->loadCertificate(pkiStore, certificateTypeId, &certificateStr);
	if (retval != UA_STATUSCODE_GOOD) {
		return retval;
	}

	/* Load own private key from PKI Store */
	UA_ByteString privateKeyStr = UA_BYTESTRING_NULL;
    UA_ByteString_init(&privateKeyStr);
	retval = pkiStore->loadPrivateKey(pkiStore, certificateTypeId, &privateKeyStr);
	if (retval != UA_STATUSCODE_GOOD) {
		return retval;
	}

	/* Get X509 certificate */
	mbedtls_x509_crt x509Cert;
	mbedtls_x509_crt_init(&x509Cert);
    UA_ByteString certificateStr0 = copyDataFormatAware(&certificateStr);
    UA_ByteString_clear(&certificateStr);
    ret = mbedtls_x509_crt_parse(&x509Cert, certificateStr0.data, certificateStr0.length);
    UA_ByteString_clear(&certificateStr0);
    if(ret) {
    	return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Get private key */
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    UA_ByteString privateKeyStr0 = copyDataFormatAware(&privateKeyStr);
    UA_ByteString_clear(&privateKeyStr);
    ret = mbedtls_pk_parse_key(&pk, privateKeyStr0.data, privateKeyStr0.length, NULL, 0);
    UA_ByteString_clear(&privateKeyStr0);
    if(ret) {
    	return UA_STATUSCODE_BADINTERNALERROR;
    }

	mbedtls_x509write_csr  request;
	mbedtls_entropy_context entropy_ctx;
	mbedtls_ctr_drbg_context ctrDrbg;

	mbedtls_x509write_csr_init(&request);
	mbedtls_entropy_init(&entropy_ctx);
	mbedtls_ctr_drbg_init(&ctrDrbg);

	/* Set message digest algorithms in CSR context */
	mbedtls_x509write_csr_set_md_alg(&request, MBEDTLS_MD_SHA256);

	/* Set key usage in CSR context */
	if (mbedtls_x509write_csr_set_key_usage(&request, MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
	                                                  MBEDTLS_X509_KU_DATA_ENCIPHERMENT |
	                                                  MBEDTLS_X509_KU_NON_REPUDIATION |
												      MBEDTLS_X509_KU_KEY_ENCIPHERMENT) != 0) {
	    mbedtls_x509write_csr_free(&request);
	    mbedtls_entropy_free(&entropy_ctx);
	    return UA_STATUSCODE_BADINTERNALERROR;
	}

	/* Add entropy */
	if (entropy != NULL && entropy->length > 0) {
	    if (mbedtls_entropy_update_manual(&entropy_ctx, (const unsigned char*)(entropy->data),
	                                      entropy->length) != 0) {
	        mbedtls_x509write_csr_free(&request);
	        mbedtls_entropy_free(&entropy_ctx);
	        return UA_STATUSCODE_BADINTERNALERROR;
	    }
	}

	/* Get subject from argument or read it from certificate */
	char *subj = NULL;
	if (subject != NULL && subject->length > 0) {
	    /* subject from argument */
	    subj = (char *)UA_malloc(subject->length + 1);
	    if (subj == NULL) {
	        mbedtls_x509write_csr_free(&request);
	        mbedtls_entropy_free(&entropy_ctx);
	        return UA_STATUSCODE_BADOUTOFMEMORY;
	    }
	    strncpy(subj, (char *)subject->data, subject->length);
	    strcat(subj, "\0");
	    /* search for / in subject and replace it by comma */
	    char *p = subj;
	    for (size_t i = 0; i < subject->length; i++) {
	        if (*p == '/' ) {
	            *p = ',';
	        }
	        ++p;
	    }
	}
    else {
	    /* read subject from certificate */
    	const size_t subjectMaxSize = 512;
    	mbedtls_x509_name s = x509Cert.subject;
        subj = (char *)UA_malloc(subjectMaxSize);
        if (subj == NULL) {
            mbedtls_x509write_csr_free(&request);
    		mbedtls_entropy_free(&entropy_ctx);
    		return UA_STATUSCODE_BADOUTOFMEMORY;
        }
    	if ((ret = mbedtls_x509_dn_gets(subj, subjectMaxSize, &s)) <= 0) {
    		mbedtls_x509write_csr_free(&request);
    		mbedtls_entropy_free(&entropy_ctx);
    		return UA_STATUSCODE_BADINTERNALERROR;
        }
    }

	/* Set the subject in CSR context */
	if((ret = mbedtls_x509write_csr_set_subject_name(&request, subj)) != 0) {
	    if (ret != 0) {
	        mbedtls_x509write_csr_free(&request);
	        mbedtls_entropy_free(&entropy_ctx);
	        UA_free(subj);
	        return UA_STATUSCODE_BADINTERNALERROR;
	    }
	}

	/* Get the subject alternate names from certificate and set them in CSR context*/
	san_mbedtls_san_list_entry_t* san_list = NULL;
    san_list = san_mbedtls_get_san_list_from_cert(&x509Cert);
	if (san_list != NULL) {
	    if (san_mbedtls_set_san_list_to_csr(&request, san_list) <= 0) {
	    	san_mbedtls_san_list_entry_free(san_list);
	    	mbedtls_x509write_csr_free(&request);
	    	mbedtls_entropy_free(&entropy_ctx);
	    	UA_free(subj);
	    	return UA_STATUSCODE_BADINTERNALERROR;
	    }
	}
	san_mbedtls_san_list_entry_free(san_list);

	/* Set private key in CSR context */
	mbedtls_x509write_csr_set_key(&request, &pk);

	printf("AAAAA\n");
	unsigned char requestBuf[4096];
	memset(requestBuf, 0, sizeof(requestBuf));
	ret = mbedtls_x509write_csr_der(&request, requestBuf, sizeof(requestBuf), 0, 0); /* mbedtls_ctr_drbg_random, &ctrDrbg);*/
	if(ret <= 0 ) {
		printf("AAAAA %d %s\n", ret, mbedtls_high_level_strerr(ret));

	    mbedtls_x509write_csr_free(&request);
	    mbedtls_entropy_free(&entropy_ctx);
	    UA_free(subj);
	    return UA_STATUSCODE_BADINTERNALERROR;
	}
	printf("AAAAA\n");

	size_t byteCount = (size_t)ret;  /* number of CSR data bytes located at the end of the request buffer */
	size_t offset = sizeof(requestBuf) - byteCount;

	/* copy return parameter into a ByteString */
	UA_ByteString *csrByteString = UA_ByteString_new();
	UA_ByteString_init(csrByteString);
	UA_ByteString_allocBuffer(csrByteString, byteCount);
	memcpy(csrByteString->data, requestBuf + offset, byteCount);
	*csr = csrByteString;

    mbedtls_x509write_csr_free(&request);
	mbedtls_entropy_free(&entropy_ctx);
	UA_free (subj);

    return UA_STATUSCODE_GOOD;
}

static void
UA_CertificateManager_clear(UA_CertificateManager *certificateManager) {
	if (certificateManager->context == NULL) {
		return; /* FIXME: HUK TODO - Kann weg */
	}

    CertInfo *ci = (CertInfo *)certificateManager->context;
    if (ci != NULL) {
    	mbedtls_x509_crt_free(&ci->trustedCertificates);
    	mbedtls_x509_crl_free(&ci->trustedCertificateCrls);
    	mbedtls_x509_crt_free(&ci->trustedIssuers);
    	mbedtls_x509_crl_free(&ci->trustedIssuerCrls);
    	UA_free(ci);
    }
    certificateManager->context = NULL;
}

static UA_StatusCode
getCertificate_ExpirationDate(UA_DateTime *expiryDateTime, 
                              UA_ByteString *certificate) {
    mbedtls_x509_crt publicKey;
    mbedtls_x509_crt_init(&publicKey);
    int mbedErr = mbedtls_x509_crt_parse(&publicKey, certificate->data, certificate->length);
    if(mbedErr)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_DateTimeStruct ts;
    ts.year = (UA_Int16)publicKey.valid_to.year;
    ts.month = (UA_UInt16)publicKey.valid_to.mon;
    ts.day = (UA_UInt16)publicKey.valid_to.day;
    ts.hour = (UA_UInt16)publicKey.valid_to.hour;
    ts.min = (UA_UInt16)publicKey.valid_to.min;
    ts.sec = (UA_UInt16)publicKey.valid_to.sec;
    ts.milliSec = 0;
    ts.microSec = 0;
    ts.nanoSec = 0;

    *expiryDateTime = UA_DateTime_fromStruct(ts);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_CertificateManager_create(UA_CertificateManager *certificateManager) {

	if (certificateManager == NULL) {
	    return UA_STATUSCODE_BADINVALIDARGUMENT;
	}

    CertInfo *ci = (CertInfo *)UA_malloc(sizeof(CertInfo));
    if(!ci)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    memset(ci, 0, sizeof(CertInfo));

    certificateManager->context = (void *)ci;
    certificateManager->verifyCertificate = certificateVerification_verify;
    certificateManager->verifyApplicationURI = certificateVerification_verifyApplicationURI;
	certificateManager->createCertificateSigningRequest =  CertificateManager_createCSR;
	certificateManager->clear = UA_CertificateManager_clear;

	return UA_STATUSCODE_GOOD;
}

#endif
