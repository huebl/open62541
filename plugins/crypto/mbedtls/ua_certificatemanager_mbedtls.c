#include <open62541/plugin/pki_default.h>

#ifdef UA_ENABLE_ENCRYPTION_MBEDTLS

#include "securitypolicy_mbedtls_common.h"
#include "san_mbedtls.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

typedef struct {
    mbedtls_pk_context privateKey;
    mbedtls_x509_crt certificate;
    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;
} CertificateManagerContext;

/* Create the CSR using mbedTLS */
static UA_StatusCode CertificateManager_createCSR(const UA_CertificateManager *cm,
                                                  const UA_String *subject,
                                                  const UA_ByteString *entropy,
                                                  UA_ByteString **csr) {
    if (cm == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    int ret = 0;
    *csr = NULL;

    mbedtls_x509write_csr  request;
    mbedtls_entropy_context entropy_ctx;

    mbedtls_x509write_csr_init(&request);
    mbedtls_entropy_init(&entropy_ctx);

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
        mbedtls_x509_name s = ((CertificateManagerContext *)cm->keyAndCertContext)->certificate.subject;
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
    san_list = san_mbedtls_get_san_list_from_cert(&((CertificateManagerContext *)cm->keyAndCertContext)->certificate);
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
    mbedtls_x509write_csr_set_key(&request, &((CertificateManagerContext *)(cm->keyAndCertContext))->privateKey);

    unsigned char requestBuf[4096];
    memset(requestBuf, 0, sizeof(requestBuf));
    if((ret = mbedtls_x509write_csr_der(&request, requestBuf, sizeof(requestBuf), mbedtls_ctr_drbg_random,
              &((CertificateManagerContext *)(cm->keyAndCertContext))->ctrDrbg)) <= 0 ) {
        mbedtls_x509write_csr_free(&request);
        mbedtls_entropy_free(&entropy_ctx);
        UA_free(subj);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

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

/* Clean up the Certificate Manager content */
static void UA_CertificateManager_clear(UA_CertificateManager *cm) {
    if (cm == NULL) {
        return;
    }

    CertificateManagerContext *context = (CertificateManagerContext *)cm->keyAndCertContext;
    if (context != NULL) {
        mbedtls_x509_crt_free(&context->certificate);
        mbedtls_pk_free(&context->privateKey);
        mbedtls_entropy_free(&context->entropy);
        mbedtls_ctr_drbg_free(&context->ctrDrbg);
        UA_free(context);
        cm->keyAndCertContext = NULL;
        cm->createCertificateSigningRequest = NULL;
    }
}

/* Initialize the Certificate Manager */
UA_StatusCode
UA_CertificateManager_create(UA_CertificateManager *cm,
                            const UA_ByteString *certificate,
                            const UA_ByteString *privateKey) {

	if ((cm == NULL) || (certificate == NULL) || (privateKey == NULL) ||
	    (certificate->length == 0) || (privateKey->length == 0)) {
	    return UA_STATUSCODE_BADINVALIDARGUMENT;
	}

	CertificateManagerContext *context;
	context = (CertificateManagerContext *)UA_malloc(sizeof(CertificateManagerContext));
	if (context != NULL) {
		/* Init entropy context */
		mbedtls_entropy_init(&context->entropy);

	    /* Set certificate */
        mbedtls_x509_crt_init(&context->certificate);
	    UA_ByteString tmpCert = UA_mbedTLS_CopyDataFormatAware(certificate);
	    if (mbedtls_x509_crt_parse(&context->certificate, tmpCert.data, tmpCert.length) != 0) {
	        return UA_STATUSCODE_BADINTERNALERROR;
	    }

	    /* Set private key */
	    mbedtls_pk_init(&context->privateKey);
	    if (UA_mbedTLS_LoadPrivateKey(privateKey, &context->privateKey, &context->entropy) != 0) {
	        return UA_STATUSCODE_BADINTERNALERROR;
	    }

	    /* Initialize the CTR-DRBG module */
	    mbedtls_ctr_drbg_init(&context->ctrDrbg);
        unsigned char pers[] = "saPfdfUdftljdh/sj4:59iw5St#984mf83+dkGJRE";
	    if (mbedtls_ctr_drbg_seed(&context->ctrDrbg,
	                              mbedtls_entropy_func, &context->entropy, pers, sizeof(pers)) != 0) {
	        return UA_STATUSCODE_BADINTERNALERROR;
	    }

	    /* Set the worker function for creating the CSR */
	    cm->createCertificateSigningRequest =  CertificateManager_createCSR;
	    /* Set the cleanup function */
	    cm->clear = UA_CertificateManager_clear;
	    /* Set the context pointer for further usage */
	    cm->keyAndCertContext = context;
	} else {
	    return UA_STATUSCODE_BADOUTOFMEMORY;
	}

	return UA_STATUSCODE_GOOD;
}

#endif
