/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2020 (c) Wind River Systems, Inc.
 *    Copyright 2020 (c) basysKom GmbH

 */

#include <open62541/util.h>
#include <open62541/plugin/pki_default.h>
#include <open62541/plugin/log_stdout.h>

#include "securitypolicy_openssl_common.h"

#if defined(UA_ENABLE_ENCRYPTION_OPENSSL) || defined(UA_ENABLE_ENCRYPTION_LIBRESSL)
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "ua_openssl_version_abstraction.h"
#include "libc_time.h"

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

/* Store rejected certificates in a list */
typedef struct {
    UA_ByteString *sign; /* Signature */
    UA_ByteString *cert; /* Certificate */
} CertRejectListItem;

typedef struct {
    /*
     * If the folders are defined, we use them to reload the certificates during
     * runtime
     */

    UA_String             trustListFolder;
    UA_String             issuerListFolder;
    UA_String             revocationListFolder;
    /* Used with mbedTLS and UA_ENABLE_CERT_REJECTED_DIR option */
    UA_String             rejectedListFolder;

    STACK_OF(X509) *      skIssue;
    STACK_OF(X509) *      skTrusted;
    STACK_OF(X509_CRL) *  skCrls; /* Revocation list*/

    /* Rejected certificates list */
     CertRejectListItem *certRejectList;
     size_t certRejectListSize;
     size_t certRejectListSizeMax;
     size_t certRejectListAddCount;
} CertContext;

static UA_StatusCode
UA_CertContext_sk_Init (CertContext * context) {
    context->skTrusted = sk_X509_new_null();
    context->skIssue = sk_X509_new_null();
    context->skCrls = sk_X509_CRL_new_null();
    if (context->skTrusted == NULL || context->skIssue == NULL ||
        context->skCrls == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    return UA_STATUSCODE_GOOD;
}

static void
UA_CertContext_sk_free (CertContext* context) {
    sk_X509_pop_free(context->skTrusted, X509_free);
    sk_X509_pop_free(context->skIssue, X509_free);
    sk_X509_CRL_pop_free(context->skCrls, X509_CRL_free);
}

static UA_StatusCode
UA_CertContext_Init (CertContext * context) {
    (void) memset (context, 0, sizeof (CertContext));
    return UA_CertContext_sk_Init (context);
}

static UA_StatusCode
UA_skTrusted_Cert2X509 (const UA_ByteString *   certificateTrustList,
                        size_t                  certificateTrustListSize,
                        CertContext *           ctx) {
    size_t                i;

    for (i = 0; i < certificateTrustListSize; i++) {
        X509 * x509 = UA_OpenSSL_LoadCertificate(&certificateTrustList[i]);

        if (x509 == NULL) {
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        sk_X509_push (ctx->skTrusted, x509);
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_skIssuer_Cert2X509 (const UA_ByteString *   certificateIssuerList,
                       size_t                  certificateIssuerListSize,
                       CertContext *           ctx) {
    size_t                i;

    for (i = 0; i < certificateIssuerListSize; i++) {
        X509 * x509 = UA_OpenSSL_LoadCertificate(&certificateIssuerList[i]);

        if (x509 == NULL) {
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        sk_X509_push (ctx->skIssue, x509);
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_skCrls_Cert2X509 (const UA_ByteString *   certificateRevocationList,
                     size_t                  certificateRevocationListSize,
                     CertContext *           ctx) {
    size_t                i;
    const unsigned char * pData;

    for (i = 0; i < certificateRevocationListSize; i++) {
        pData = certificateRevocationList[i].data;
        X509_CRL * crl = NULL;

        if (certificateRevocationList[i].length > 1 && pData[0] == 0x30 && pData[1] == 0x82) { // Magic number for DER encoded files
            crl = d2i_X509_CRL (NULL, &pData, (long) certificateRevocationList[i].length);
        } else {
            BIO* bio = NULL;
            bio = BIO_new_mem_buf((void *) certificateRevocationList[i].data,
                                  (int) certificateRevocationList[i].length);
            crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
            BIO_free(bio);
        }

        if (crl == NULL) {
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        sk_X509_CRL_push (ctx->skCrls, crl);
    }

    return UA_STATUSCODE_GOOD;
}

#ifdef __linux__
#include <dirent.h>

#if 0 /* FIXME: HUK */
static int UA_Certificate_Filter_der_pem (const struct dirent * entry) {
    /* ignore hidden files */
    if (entry->d_name[0] == '.') return 0;

    /* check file extension */
    const char *pszFind = strrchr(entry->d_name, '.');
    if (pszFind == 0)
        return 0;
    pszFind++;
    if (strcmp (pszFind, "der") == 0 || strcmp (pszFind, "pem") == 0)
        return 1;

    return 0;
}
#endif

#if 0 /* FIXME: HUK */
static int UA_Certificate_Filter_crl (const struct dirent * entry) {

    /* ignore hidden files */
    if (entry->d_name[0] == '.') return 0;

    /* check file extension */
    const char *pszFind = strrchr(entry->d_name, '.');
    if (pszFind == 0)
        return 0;
    pszFind++;
    if (strcmp (pszFind, "crl") == 0)
        return 1;

    return 0;
}
#endif

#if 0 /* FIXME: HUK */
static UA_StatusCode
UA_BuildFullPath (const char * path,
                  const char * fileName,
                  size_t       fullPathBufferLength,
                  char *       fullPath) {
    size_t  pathLen = strlen (path);
    size_t  fileNameLen = strlen (fileName);
    if ((pathLen + fileNameLen + 2) > fullPathBufferLength) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    strcpy (fullPath, path);
    strcat (fullPath, "/");
    strcat (fullPath, fileName);

    return UA_STATUSCODE_GOOD;
}
#endif

#if 0 /* FIXME: HUK */
static UA_StatusCode
UA_loadCertFromFile (const char *     fileName,
                     UA_ByteString *  cert) {

    FILE * fp = fopen(fileName, "rb");

    if (fp == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    fseek(fp, 0, SEEK_END);
    cert->length = (size_t)  ftell(fp);
    if (UA_ByteString_allocBuffer (cert, cert->length) != UA_STATUSCODE_GOOD) {
        fclose (fp);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    fseek(fp, 0, SEEK_SET);
    size_t readLen = fread (cert->data, 1, cert->length, fp);
    if (readLen != cert->length) {
        UA_ByteString_clear (cert);
        cert->length = 0;
        fclose (fp);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    fclose (fp);

    return UA_STATUSCODE_GOOD;
}
#endif

#if 0 /* FIXME: HUK */
static UA_StatusCode
UA_ReloadCertFromFolder (CertContext * ctx) {
    UA_StatusCode    ret;
    struct dirent ** dirlist = NULL;
    int              i;
    int              numCertificates;
    char             certFile[PATH_MAX];
    UA_ByteString    strCert;
    char             folderPath[PATH_MAX];

    UA_ByteString_init (&strCert);

    if (ctx->trustListFolder.length > 0) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Reloading the trust-list");

        sk_X509_pop_free (ctx->skTrusted, X509_free);
        ctx->skTrusted = sk_X509_new_null();
        if (ctx->skTrusted == NULL) {
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }

        (void) memcpy (folderPath, ctx->trustListFolder.data,
                       ctx->trustListFolder.length);
        folderPath[ctx->trustListFolder.length] = 0;
        numCertificates = scandir(folderPath, &dirlist,
                                  UA_Certificate_Filter_der_pem,
                                  alphasort);
        for (i = 0; i < numCertificates; i++) {
            if (UA_BuildFullPath (folderPath, dirlist[i]->d_name,
                                  PATH_MAX, certFile) != UA_STATUSCODE_GOOD) {
                continue;
            }
            ret = UA_loadCertFromFile (certFile, &strCert);
            if (ret != UA_STATUSCODE_GOOD) {
                UA_LOG_INFO (UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                            "Failed to load the certificate file %s", certFile);
                continue;  /* continue or return ? */
            }
            if (UA_skTrusted_Cert2X509 (&strCert, 1, ctx) != UA_STATUSCODE_GOOD) {
                UA_LOG_INFO (UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                            "Failed to decode the certificate file %s", certFile);
                UA_ByteString_clear (&strCert);
                continue;  /* continue or return ? */
            }
            UA_ByteString_clear (&strCert);
        }
    }

    if (ctx->issuerListFolder.length > 0) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Reloading the issuer-list");

        sk_X509_pop_free (ctx->skIssue, X509_free);
        ctx->skIssue = sk_X509_new_null();
        if (ctx->skIssue == NULL) {
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }

        memcpy (folderPath, ctx->issuerListFolder.data, ctx->issuerListFolder.length);
        folderPath[ctx->issuerListFolder.length] = 0;
        numCertificates = scandir(folderPath, &dirlist,
                                  UA_Certificate_Filter_der_pem,
                                  alphasort);
        for (i = 0; i < numCertificates; i++) {
            if (UA_BuildFullPath (folderPath, dirlist[i]->d_name,
                                  PATH_MAX, certFile) != UA_STATUSCODE_GOOD) {
                continue;
            }
            ret = UA_loadCertFromFile (certFile, &strCert);
            if (ret != UA_STATUSCODE_GOOD) {
                UA_LOG_INFO (UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                            "Failed to load the certificate file %s", certFile);
                continue;  /* continue or return ? */
            }
            if (UA_skIssuer_Cert2X509 (&strCert, 1, ctx) != UA_STATUSCODE_GOOD) {
                UA_LOG_INFO (UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                            "Failed to decode the certificate file %s", certFile);
                UA_ByteString_clear (&strCert);
                continue;  /* continue or return ? */
            }
            UA_ByteString_clear (&strCert);
        }
    }

    if (ctx->revocationListFolder.length > 0) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Reloading the revocation-list");

        sk_X509_CRL_pop_free (ctx->skCrls, X509_CRL_free);
        ctx->skCrls = sk_X509_CRL_new_null();
        if (ctx->skCrls == NULL) {
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }

        memcpy (folderPath, ctx->revocationListFolder.data, ctx->revocationListFolder.length);
        folderPath[ctx->revocationListFolder.length] = 0;
        numCertificates = scandir(folderPath, &dirlist,
                                  UA_Certificate_Filter_crl,
                                  alphasort);
        for (i = 0; i < numCertificates; i++) {
            if (UA_BuildFullPath (folderPath, dirlist[i]->d_name,
                                  PATH_MAX, certFile) != UA_STATUSCODE_GOOD) {
                continue;
            }
            ret = UA_loadCertFromFile (certFile, &strCert);
            if (ret != UA_STATUSCODE_GOOD) {
                UA_LOG_INFO (UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                            "Failed to load the revocation file %s", certFile);
                continue;  /* continue or return ? */
            }
            if (UA_skCrls_Cert2X509 (&strCert, 1, ctx) != UA_STATUSCODE_GOOD) {
                UA_LOG_INFO (UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                            "Failed to decode the revocation file %s", certFile);
                UA_ByteString_clear (&strCert);
                continue;  /* continue or return ? */
            }
            UA_ByteString_clear (&strCert);
        }
    }

    ret = UA_STATUSCODE_GOOD;
    return ret;
}
#endif

#endif  /* end of __linux__ */

static UA_StatusCode
UA_X509_Store_CTX_Error_To_UAError (int opensslErr) {
    UA_StatusCode ret;

    switch (opensslErr) {
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_CRL_HAS_EXPIRED:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
        case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
            ret = UA_STATUSCODE_BADCERTIFICATETIMEINVALID;
            break;
        case X509_V_ERR_CERT_REVOKED:
            ret = UA_STATUSCODE_BADCERTIFICATEREVOKED;
            break;
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            ret = UA_STATUSCODE_BADCERTIFICATEUNTRUSTED;
            break;
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            ret = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
            break;
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            ret = UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN;
            break;
        default:
            ret = UA_STATUSCODE_BADCERTIFICATEINVALID;
            break;
        }
    return ret;
    }

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

#if 0 /* FIXME: HUK */
static void certListItem_clear(size_t offset, CertContext *ctx)
{
    if (ctx->certRejectList != NULL) {
        if (ctx->certRejectList[offset].cert != NULL) {
            UA_ByteString_delete(ctx->certRejectList[offset].cert);
        }
        if (ctx->certRejectList[offset].sign != NULL) {
            UA_ByteString_delete(ctx->certRejectList[offset].sign);
        }
    }
}
#endif

#if 0 /* FIXME: HUK */
/* Check for signature already in rejected list */
static UA_Boolean rejectedList_isDuplicate(const UA_ByteString *sign, CertContext *ctx) {
    if (sign != NULL) {
        for (size_t i = 0; i < ctx->certRejectListSize; i++) {
            if (UA_ByteString_equal(sign, ctx->certRejectList[i].sign)) {
                return true;  /* duplicate */
            }
        }
    }
    return false; /* not yet in reject list */
}
#endif

#if 0 /* FIXME: TODO */
/* Add a rejected certificate and its signature to the list */
static UA_StatusCode rejectedList_add(const UA_ByteString *certificate,
                                      const X509 *remoteCertificate,
                                      void *verificationContext) {
	if (certificate == NULL || remoteCertificate == NULL ||  verificationContext == NULL) {
	    return UA_STATUSCODE_BADINVALIDARGUMENT;
	}

	CertContext *ctx = (CertContext *)verificationContext;

	/* get signature from X509 certificate */
	const ASN1_BIT_STRING *psig = NULL;
	X509_get0_signature(&psig, NULL, remoteCertificate);
	if (psig->data == NULL  || psig->length < 1) {
		return UA_STATUSCODE_BADINVALIDARGUMENT;
	}
	UA_ByteString *sign = byteStrNew(psig->data, (size_t)psig->length);
	if (sign == NULL) {
	    return UA_STATUSCODE_BADOUTOFMEMORY;
	}
	/* Ignore certificate if already in list */
	if (rejectedList_isDuplicate(sign, ctx)) {
	    UA_ByteString_delete(sign);
	    return UA_STATUSCODE_GOOD;  /* Signature (and certificate) already in list */
	}

	UA_ByteString *cert = byteStrDup(certificate);
	if (cert == NULL) {
		UA_ByteString_delete(sign);
	    return UA_STATUSCODE_BADOUTOFMEMORY;
	}

	size_t offset = ctx->certRejectListAddCount % ctx->certRejectListSizeMax;

	if (ctx->certRejectListSize < ctx->certRejectListSizeMax) {
	    /* Extend the list */
		ctx->certRejectList = (CertRejectListItem *)UA_realloc(ctx->certRejectList,
	                         (ctx->certRejectListSize + 1) * sizeof(CertRejectListItem));
	    if (ctx->certRejectList == NULL) {
	    	UA_ByteString_delete(sign);
	        UA_ByteString_delete(cert);
	        return UA_STATUSCODE_BADOUTOFMEMORY;
	    }
	    /* New empty list item created */
	    ctx->certRejectListSize++;
	    ctx->certRejectList[offset].cert = NULL;
	    ctx->certRejectList[offset].sign = NULL;
	}

	/* store data in list item at position 'offset', delete former value if exists */
	certListItem_clear(offset, ctx);
	ctx->certRejectList[offset].cert = cert;
	ctx->certRejectList[offset].sign = sign;
	ctx->certRejectListAddCount++;

	return UA_STATUSCODE_GOOD;
}
#endif

#if 0 /* FIXME: HUK */
/* Non static wrapper for unit (module) testing only */
UA_StatusCode rejectedList_add_for_testing(
	const UA_ByteString *certificate,
    void *verificationContext
) {
    if (certificate == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    if (verificationContext == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    CertContext *ctx = (CertContext *)verificationContext;

    /* Parse the certificate (DER format) */
    X509* remoteCertificate = NULL;
    const unsigned char* data = certificate->data;
    remoteCertificate = d2i_X509(NULL, &data, (long)certificate->length);
    if (remoteCertificate == NULL) {
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }
    ctx->certRejectListSizeMax = 3;
    UA_StatusCode retval = rejectedList_add(certificate, remoteCertificate, verificationContext);
    X509_free(remoteCertificate);
    return retval;
}

/* Get the rejected certificate list as a ByteString array */
UA_StatusCode rejectedList_get(UA_ByteString **byteStringArray, size_t *arraySize,
                               void *verificationContext) {
    if (verificationContext == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    CertContext *ctx = (CertContext *)verificationContext;
    if (arraySize == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    *arraySize = 0;
    if (byteStringArray == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    *byteStringArray =
        (UA_ByteString *)UA_Array_new(ctx->certRejectListSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if (*byteStringArray == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    for (size_t i = 0; i < ctx->certRejectListSize; i++) {
        UA_ByteString_init(*byteStringArray + i);
        if (UA_ByteString_allocBuffer(*byteStringArray + i,
                             ctx->certRejectList[i].cert->length) != UA_STATUSCODE_GOOD) {
            *arraySize = i;  /* only i elements are copied */
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        memcpy(((*byteStringArray)+i)->data,
                ctx->certRejectList[i].cert->data, ctx->certRejectList[i].cert->length);
    }
    *arraySize = ctx->certRejectListSize;
    return UA_STATUSCODE_GOOD;
}
#endif

static UA_StatusCode
reloadCertificates(
	CertContext* ctx,
	UA_PKIStore* pkiStore
) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_ByteString data;
    UA_ByteString_init(&data);

    /* Read certificates */
    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    retval = pkiStore->loadTrustList(pkiStore, &trustList);
    if(!UA_StatusCode_isGood(retval))
        goto error;

    /* Decode trusted certificates */
    if (trustList.trustedCertificatesSize >  0) {
    	retval = UA_skTrusted_Cert2X509(
    		trustList.trustedCertificates, trustList.trustedCertificatesSize, ctx
    	);
    	if (retval != UA_STATUSCODE_GOOD) {
    		UA_LOG_INFO (UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
    					"Failed to decode trusted certificates");
    		goto error;
    	}
    }

    /* Decode issuer certificates */
    if (trustList.issuerCertificatesSize > 0) {
    	retval = UA_skIssuer_Cert2X509(
    		trustList.issuerCertificates, trustList.issuerCertificatesSize, ctx
    	);
    	if (retval != UA_STATUSCODE_GOOD) {
    		UA_LOG_INFO (UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                        "Failed to decode issuer certificates");
    		goto error;
    	}
    }

    /* Decode trusted revocation certificates */
     if (trustList.trustedCrlsSize >  0) {
     	retval = UA_skCrls_Cert2X509(
     		trustList.trustedCrls, trustList.trustedCrlsSize, ctx
     	);
     	if (retval != UA_STATUSCODE_GOOD) {
     		UA_LOG_INFO (UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
     					"Failed to decode trusted revocation certificates");
     		goto error;
     	}
     }

     /* Decode issuer revocation certificates */
     if (trustList.issuerCrlsSize >  0) {
      	retval = UA_skCrls_Cert2X509(
      		trustList.issuerCrls, trustList.issuerCrlsSize, ctx
      	);
      	if (retval != UA_STATUSCODE_GOOD) {
      		UA_LOG_INFO (UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
      					"Failed to decode issuer revocation certificates");
      		goto error;
      	}
     }

error:
	UA_clear(&trustList, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE]);
    return retval;
}

static UA_StatusCode
do_certificateVerification_verify(
	UA_CertificateManager *certificateManager,
    UA_PKIStore *pkiStore,
    const UA_ByteString *certificate
) {
    X509_STORE_CTX*       storeCtx;
    X509_STORE*           store;
    UA_StatusCode         ret;
    int                   opensslRet;
    X509 *                certificateX509 = NULL;

	/* Check parameter */
	if(certificateManager == NULL || pkiStore == NULL || certificate == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

	/* Create store context */
    store = X509_STORE_new();
    storeCtx = X509_STORE_CTX_new();
    if (store == NULL || storeCtx == NULL) {
        ret = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }

    /* Reload certificates */
    CertContext ctx;
    UA_CertContext_Init(&ctx);
    UA_StatusCode certFlag = reloadCertificates(&ctx, pkiStore);
    if(certFlag != UA_STATUSCODE_GOOD) {
        return certFlag;
    }

    certificateX509 = UA_OpenSSL_LoadCertificate(certificate);
    if (certificateX509 == NULL) {
        ret = UA_STATUSCODE_BADCERTIFICATEINVALID;
        goto cleanup;
    }

    X509_STORE_set_flags(store, 0);
    opensslRet = X509_STORE_CTX_init (storeCtx, store, certificateX509, ctx.skIssue);
    if (opensslRet != 1) {
        ret = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
#if defined(OPENSSL_API_COMPAT) && OPENSSL_API_COMPAT < 0x10100000L
	(void) X509_STORE_CTX_trusted_stack (storeCtx, ctx.skTrusted);
#else
	(void) X509_STORE_CTX_set0_trusted_stack (storeCtx, ctx.skTrusted);
#endif

    /* Set crls to ctx */
    if (sk_X509_CRL_num (ctx.skCrls) > 0) {
        X509_STORE_CTX_set0_crls (storeCtx, ctx.skCrls);
    }

    /* Set flag to check if the certificate has an invalid signature */
    X509_STORE_CTX_set_flags (storeCtx, X509_V_FLAG_CHECK_SS_SIGNATURE);

    if (X509_STORE_CTX_get_check_issued(storeCtx) (storeCtx,certificateX509, certificateX509) != 1) {
        X509_STORE_CTX_set_flags (storeCtx, X509_V_FLAG_CRL_CHECK);
    }

    /* This condition will check whether the certificate is a User certificate or a CA certificate.
     * If the KU_KEY_CERT_SIGN and KU_CRL_SIGN of key_usage are set, then the certificate shall be
     * condidered as CA Certificate and cannot be used to establish a connection. Refer the test case
     * CTT/Security/Security Certificate Validation/029.js for more details */
     /** \todo Can the ca-parameter of X509_check_purpose can be used? */
    if(X509_check_purpose(certificateX509, X509_PURPOSE_CRL_SIGN, 0) && X509_check_ca(certificateX509)) {
        return UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED;
    }

    opensslRet = X509_verify_cert (storeCtx);
    if (opensslRet == 1) {
        ret = UA_STATUSCODE_GOOD;

        /* Check if the not trusted certificate has a CRL file. If there is no CRL file available for the corresponding
         * parent certificate then return status code UA_STATUSCODE_BADCERTIFICATEISSUERREVOCATIONUNKNOWN. Refer the test
         * case CTT/Security/Security Certificate Validation/002.js */
        if (X509_STORE_CTX_get_check_issued (storeCtx) (storeCtx,certificateX509, certificateX509) != 1) {
            /* Free X509_STORE_CTX and reuse it for certification verification */
            if (storeCtx != NULL) {
               X509_STORE_CTX_free(storeCtx);
            }

            /* Initialised X509_STORE_CTX sructure*/
            storeCtx = X509_STORE_CTX_new();

            /* Sets up X509_STORE_CTX structure for a subsequent verification operation */
            X509_STORE_set_flags(store, 0);
            X509_STORE_CTX_init (storeCtx, store, certificateX509,ctx.skIssue);

            /* Set trust list to ctx */
            (void) X509_STORE_CTX_trusted_stack (storeCtx, ctx.skTrusted);

            /* Set crls to ctx */
            X509_STORE_CTX_set0_crls (storeCtx, ctx.skCrls);

            /* Set flags for CRL check */
            X509_STORE_CTX_set_flags (storeCtx, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

            opensslRet = X509_verify_cert (storeCtx);
            if (opensslRet != 1) {
                opensslRet = X509_STORE_CTX_get_error (storeCtx);
                if (opensslRet == X509_V_ERR_UNABLE_TO_GET_CRL) {
                    ret = UA_STATUSCODE_BADCERTIFICATEISSUERREVOCATIONUNKNOWN;
                }
            }
        }
    }
    else {
        opensslRet = X509_STORE_CTX_get_error (storeCtx);

        /* Check the issued certificate of a CA that is not trusted but available */
        if(opensslRet == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN){
            int                     trusted_cert_len = sk_X509_num(ctx.skTrusted);
            int                     cmpVal;
            X509                    *trusted_cert;
            const ASN1_OCTET_STRING *trusted_cert_keyid;
            const ASN1_OCTET_STRING *remote_cert_keyid;

            for (int i = 0; i < trusted_cert_len; i++) {
                trusted_cert = sk_X509_value(ctx.skTrusted, i);

                /* Fetch the Subject key identifier of the certificate in trust list */
                trusted_cert_keyid = X509_get0_subject_key_id(trusted_cert);

                /* Fetch the Subject key identifier of the remote certificate */
                remote_cert_keyid = X509_get0_subject_key_id(certificateX509);

                /* Check remote certificate is present in the trust list */
                cmpVal = ASN1_OCTET_STRING_cmp(trusted_cert_keyid, remote_cert_keyid);
                if (cmpVal == 0){
                    ret = UA_STATUSCODE_GOOD;
                    goto cleanup;
                }
            }
        }

        /* Return expected OPCUA error code */
        ret = UA_X509_Store_CTX_Error_To_UAError (opensslRet);
    }
cleanup:
    if (store != NULL) {
        X509_STORE_free (store);
    }
    if (storeCtx != NULL) {
        X509_STORE_CTX_free (storeCtx);
    }
    if (certificateX509 != NULL) {
        X509_free (certificateX509);
    }

    UA_CertContext_sk_free(&ctx);
    return ret;
}

static UA_StatusCode
certificateVerification_verify(
	UA_CertificateManager *certificateManager,
    UA_PKIStore *pkiStore,
    const UA_ByteString *certificate
) {
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
certificateVerification_verifyApplicationURI (
	UA_CertificateManager *certificateManager,
	UA_PKIStore *pkiStore,
    const UA_ByteString* certificate,
    const UA_String* applicationURI
) {
    const unsigned char * pData;
    X509 *                certificateX509;
    UA_String             subjectURI;
    GENERAL_NAMES *       pNames;
    int                   i;
    UA_StatusCode         ret;

    pData = certificate->data;
    if (pData == NULL) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Error Empty Certificate");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    certificateX509 = UA_OpenSSL_LoadCertificate(certificate);
    if (certificateX509 == NULL) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Error loading X509 Certificate");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    pNames = (GENERAL_NAMES *) X509_get_ext_d2i(certificateX509, NID_subject_alt_name,
                                                NULL, NULL);
    if (pNames == NULL) {
        X509_free (certificateX509);
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Error processing X509 Certificate");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }
    for (i = 0; i < sk_GENERAL_NAME_num (pNames); i++) {
         GENERAL_NAME * value = sk_GENERAL_NAME_value (pNames, i);
         if (value->type == GEN_URI) {
             subjectURI.length = (size_t) (value->d.ia5->length);
             subjectURI.data = (UA_Byte *) UA_malloc (subjectURI.length);
             if (subjectURI.data == NULL) {
                 UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Error Empty subjectURI");
                 X509_free (certificateX509);
                 sk_GENERAL_NAME_pop_free(pNames, GENERAL_NAME_free);
                 return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
             }
             (void) memcpy (subjectURI.data, value->d.ia5->data, subjectURI.length);
             break;
         }

    }

    ret = UA_STATUSCODE_GOOD;
    if (UA_Bstrstr (subjectURI.data, subjectURI.length,
                    applicationURI->data, applicationURI->length) == NULL) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Empty comparing subjectURI and applicationURI");
        ret = UA_STATUSCODE_BADCERTIFICATEURIINVALID;
    }

    X509_free (certificateX509);
    sk_GENERAL_NAME_pop_free(pNames, GENERAL_NAME_free);
    UA_String_clear (&subjectURI);
    return ret;
}

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
static UA_StatusCode
getCertificate_ExpirationDate(
	UA_DateTime *expiryDateTime,
    UA_ByteString *certificate
) {
    const unsigned char * pData;
    pData = certificate->data;
    X509 * x509 = d2i_X509 (NULL, &pData, (long) certificate->length);
    if (x509 == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Get the certificate Expiry date */
    ASN1_TIME *not_after = X509_get_notAfter(x509);

    struct tm dtTime;
    ASN1_TIME_to_tm(not_after, &dtTime);

    struct mytm dateTime;
    memset(&dateTime, 0, sizeof(struct mytm));
    dateTime.tm_year = dtTime.tm_year;
    dateTime.tm_mon = dtTime.tm_mon;
    dateTime.tm_mday = dtTime.tm_mday;
    dateTime.tm_hour = dtTime.tm_hour;
    dateTime.tm_min = dtTime.tm_min;
    dateTime.tm_sec = dtTime.tm_sec;

    long long sec_epoch = __tm_to_secs(&dateTime);

    *expiryDateTime = UA_DATETIME_UNIX_EPOCH;
    *expiryDateTime += sec_epoch * UA_DATETIME_SEC;

    return UA_STATUSCODE_GOOD;
}
#endif

static inline int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex) {
        return 0;
    }
    sk_X509_EXTENSION_push(sk, ex);
    return 1;
}

static inline int add_subject_attributes(const UA_String* subject, X509_NAME* name)
{
	/* copy subject to c string */
	char *subj = (char *)UA_malloc(subject->length + 1);
    if (subj == NULL) {
    	return 0;
    }
    strncpy(subj, (char *)subject->data, subject->length);
    strcat(subj, "\0");

    /* split string into tokens */
    char* token = strtok(subj, "/,");
    while (token != NULL) {

    	/* find delimiter in attribute */
    	size_t delim = 0;
    	for (size_t idx = 0; idx < strlen(token); idx++) {
    		if (token[idx] == '=') {
    			delim = idx;
    			break;
    		}
    	}
    	if (delim == 0 || delim == strlen(token)-1) {
    		UA_free(subj);
    		return 0;
    	}

    	token[delim] = '\0';
    	const unsigned char *para = (const unsigned char*)&token[delim+1];

    	/* add attribute to X509_NAME */
    	int result = X509_NAME_add_entry_by_txt(name, token, MBSTRING_UTF8, para, -1, -1, 0);
        if (!result) {
        	UA_free(subj);
        	return 0;
        }

    	/* get next token */
    	token = strtok(NULL, "/,");
    }

    UA_free(subj);
	return 1;
}

/* Create the CSR using openssl */
static UA_StatusCode certificateManager_createCSR(
	UA_CertificateManager* certificateManager,
	UA_PKIStore* pkiStore,
	const UA_NodeId certificateTypeId,
    const UA_ByteString* subject,
    const UA_ByteString* entropy,
    UA_String** csr
) {
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
	X509* x509Certificate = UA_OpenSSL_LoadCertificate(&certificateStr);
	if (x509Certificate == NULL) { /* FIXE: HUK Speicher freigeben */
		return UA_STATUSCODE_BADCERTIFICATEINVALID;
	}

	/* Get private Key */
	EVP_PKEY *privateKey = UA_OpenSSL_LoadPrivateKey(&privateKeyStr);
	if (privateKey == NULL) { /* FIXE: HUK Speicher freigeben */
		return UA_STATUSCODE_BADCERTIFICATEINVALID;
	}

	/* Create X509 certificate request */
	X509_REQ* request = X509_REQ_new();
	if (request == NULL) {
	    return UA_STATUSCODE_BADOUTOFMEMORY;
	}

	/* Set version in X509 certificate request */
	ret = X509_REQ_set_version(request, 0);
	if (ret != 1) {
		X509_REQ_free(request);
		return UA_STATUSCODE_BADOUTOFMEMORY;
	}

	/* For request extensions they are all packed in a single attribute.
	 * We save them in a STACK and add them all at once later...
	 */
	STACK_OF(X509_EXTENSION)*exts = sk_X509_EXTENSION_new_null();

	/* Set key usage in CSR context */
	X509_EXTENSION *key_usage_ext = NULL;
	key_usage_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment");
	if (key_usage_ext == NULL) {
		X509_REQ_free(request);
		sk_X509_EXTENSION_free(exts);
		return UA_STATUSCODE_BADINTERNALERROR;
	}
	sk_X509_EXTENSION_push(exts, key_usage_ext);

	/* Get subject alternate name field from certificate */
	X509_EXTENSION* subject_alt_name_ext = NULL;
	int pos = X509_get_ext_by_NID(x509Certificate, NID_subject_alt_name, -1);
	if (pos >= 0) {
		subject_alt_name_ext = X509_get_ext(x509Certificate, pos);
		if (subject_alt_name_ext != NULL) {
			/* Set subject alternate name in CSR context */
			sk_X509_EXTENSION_push(exts, subject_alt_name_ext);
		}
	}

	/* Now we've created the extensions we add them to the request */
	X509_REQ_add_extensions(request, exts);
	sk_X509_EXTENSION_free(exts);
	X509_EXTENSION_free(key_usage_ext);

	/* Get subject from argument or read it from certificate */
	X509_NAME* name = NULL;
	/* char *subj = NULL; */
	if (subject != NULL && subject->length > 0) {
	    name = X509_NAME_new();
	    if (name == NULL) {
	    	X509_REQ_free(request);
	    	return UA_STATUSCODE_BADINTERNALERROR;
	    }

	    /* add subject attributes to name */
	    if (!add_subject_attributes(subject, name)) {
	    	X509_REQ_free(request);
	    	X509_NAME_free(name);
	    	return UA_STATUSCODE_BADINTERNALERROR;
	    }
    }
	else {
	    /* Get subject name from certificate */
	    X509_NAME* tmpName = X509_get_subject_name(x509Certificate);
	    if (tmpName == NULL) {
	    	X509_REQ_free(request);
	    	return UA_STATUSCODE_BADINTERNALERROR;
	    }
	    name = X509_NAME_dup(tmpName);
	}

	/* Set the subject in CSR context */
	if (!X509_REQ_set_subject_name(request, name)) {
	    X509_REQ_free(request);
	    return UA_STATUSCODE_BADINTERNALERROR;
	}
	X509_NAME_free(name);

	/* Set public key in CSR context */
	EVP_PKEY* pubkey = X509_get_pubkey(x509Certificate);
	if (pubkey == NULL) {
	    X509_REQ_free(request);
	    return UA_STATUSCODE_BADINTERNALERROR;
	}
	if (!X509_REQ_set_pubkey(request, pubkey)) {
		EVP_PKEY_free(pubkey);
	    X509_REQ_free(request);
	    return UA_STATUSCODE_BADINTERNALERROR;
	}
	EVP_PKEY_free(pubkey);

	/* Sign the CSR */
	if (!X509_REQ_sign(request, privateKey, EVP_sha256())) {
	    X509_REQ_free(request);
	    return UA_STATUSCODE_BADINTERNALERROR;
	}

	/* Determine necessary length for CSR buffer */
	int csrBufferLength = i2d_X509_REQ(request, 0);
	if (csrBufferLength < 0) {
	    X509_REQ_free(request);
		return UA_STATUSCODE_BADINTERNALERROR;
	}

	/* create CSR buffer */
	UA_ByteString *csrByteString = UA_ByteString_new();
    UA_ByteString_init(csrByteString);
	UA_ByteString_allocBuffer(csrByteString, (size_t)csrBufferLength);

	/* Create CSR buffer (DER format) */
	char* ptr = (char*)csrByteString->data;
	i2d_X509_REQ(request, (unsigned char**)&ptr);

	*csr = csrByteString;

	return UA_STATUSCODE_GOOD;
}

static void
UA_CertificateManager_clear(UA_CertificateManager *certificateManager) {

	certificateManager->verifyCertificate = NULL;
	certificateManager->verifyApplicationURI = NULL;
	certificateManager->reloadTrustList = NULL;
	certificateManager->createCertificateSigningRequest = NULL;
	certificateManager->getExpirationDate = NULL;
	certificateManager->clear = NULL;
}


UA_StatusCode
UA_CertificateManager_create(UA_CertificateManager *certificateManager) {

	if (certificateManager == NULL) {
	    return UA_STATUSCODE_BADINVALIDARGUMENT;
	}

    certificateManager->verifyCertificate = certificateVerification_verify;
    certificateManager->verifyApplicationURI = certificateVerification_verifyApplicationURI;
	certificateManager->createCertificateSigningRequest =  certificateManager_createCSR;
#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
	certificateManager->getExpirationDate = getCertificate_ExpirationDate;
#endif
	certificateManager->clear = UA_CertificateManager_clear;

	return UA_STATUSCODE_GOOD;
}


/* main entry */

#if 0 /* FIXME: HUK */
UA_StatusCode
UA_CertificateVerification_Trustlist(UA_CertificateVerification * cv,
                                     const UA_ByteString *        certificateTrustList,
                                     size_t                       certificateTrustListSize,
                                     const UA_ByteString *        certificateIssuerList,
                                     size_t                       certificateIssuerListSize,
                                     const UA_ByteString *        certificateRevocationList,
                                     size_t                       certificateRevocationListSize) {
    UA_StatusCode ret;

    if (cv == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    CertContext * context = (CertContext *) UA_malloc (sizeof (CertContext));
    if (context == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    ret = UA_CertContext_Init (context);
    if (ret != UA_STATUSCODE_GOOD) {
        return ret;
    }

    cv->verifyApplicationURI = UA_CertificateVerification_VerifyApplicationURI;
    cv->clear = UA_CertificateVerification_clear;
    cv->context = context;
    cv->verifyCertificate = UA_CertificateVerification_Verify;
#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    cv->getExpirationDate     = xUA_GetCertificate_ExpirationDate;
#endif
    
    if (certificateTrustListSize > 0) {
        if (UA_skTrusted_Cert2X509 (certificateTrustList, certificateTrustListSize,
                                    context) != UA_STATUSCODE_GOOD) {
            ret = UA_STATUSCODE_BADINTERNALERROR;
            goto errout;
        }
    }

    if (certificateIssuerListSize > 0) {
        if (UA_skIssuer_Cert2X509 (certificateIssuerList, certificateIssuerListSize,
                                  context) != UA_STATUSCODE_GOOD) {
            ret = UA_STATUSCODE_BADINTERNALERROR;
            goto errout;
        }
    }

    if (certificateRevocationListSize > 0) {
        if (UA_skCrls_Cert2X509 (certificateRevocationList, certificateRevocationListSize,
                                  context) != UA_STATUSCODE_GOOD) {
            ret = UA_STATUSCODE_BADINTERNALERROR;
            goto errout;
        }
    }

    return UA_STATUSCODE_GOOD;

errout:
    UA_CertificateVerification_clear (cv);
    return ret;
}
#endif

#if 0
#ifdef __linux__ /* Linux only so far */
UA_StatusCode
UA_CertificateVerification_CertFolders(UA_CertificateManager*  certificateManager,
                                       const char *                 trustListFolder,
                                       const char *                 issuerListFolder,
                                       const char *                 revocationListFolder) {
    UA_StatusCode ret;
    if (certificateManager == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    CertContext * context = (CertContext *) UA_malloc (sizeof (CertContext));
    if (context == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    ret = UA_CertContext_Init (context);
    if (ret != UA_STATUSCODE_GOOD) {
        return ret;
    }

    certificateManager->verifyApplicationURI = UA_CertificateVerification_VerifyApplicationURI;
    certificateManager->clear = UA_CertificateVerification_clear;
    certificateManager->context = context;
    if(trustListFolder == NULL &&
       issuerListFolder == NULL &&
       revocationListFolder == NULL) {
    	certificateManager->verifyCertificate = UA_VerifyCertificateAllowAll;
    } else {
    	certificateManager->verifyCertificate = UA_CertificateVerification_Verify;
    }

    /* Only set the folder paths. They will be reloaded during runtime. */

    context->trustListFolder = UA_STRING_ALLOC(trustListFolder);
    context->issuerListFolder = UA_STRING_ALLOC(issuerListFolder);
    context->revocationListFolder = UA_STRING_ALLOC(revocationListFolder);

    return UA_STATUSCODE_GOOD;
}
#endif
#endif

#endif  /* end of defined(UA_ENABLE_ENCRYPTION_OPENSSL) || defined(UA_ENABLE_ENCRYPTION_LIBRESSL) */
