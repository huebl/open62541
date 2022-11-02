#include <open62541/plugin/pki_default.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL

#include "securitypolicy_openssl_common.h"

typedef struct {
    EVP_PKEY* privateKey;
    X509* certificate;
} CertificateManagerContext;

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
static UA_StatusCode CertificateManager_createCSR(const UA_CertificateManager *cm,
                                                  const UA_String *subject,
                                                  const UA_ByteString *entropy,
                                                  UA_ByteString **csr) {
    if (cm == NULL) {
	   return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

	int ret = 0;
	*csr = NULL;

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
	int pos = X509_get_ext_by_NID(((CertificateManagerContext *)cm->keyAndCertContext)->certificate, NID_subject_alt_name, -1);
	if (pos >= 0) {
		subject_alt_name_ext = X509_get_ext(((CertificateManagerContext *)cm->keyAndCertContext)->certificate, pos);
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
	    X509_NAME* tmpName = X509_get_subject_name(((CertificateManagerContext *)cm->keyAndCertContext)->certificate);
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
	EVP_PKEY* pubkey = X509_get_pubkey(((CertificateManagerContext *)cm->keyAndCertContext)->certificate);
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
	if (!X509_REQ_sign(request, ((CertificateManagerContext *)cm->keyAndCertContext)->privateKey, EVP_sha256())) {
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

/* Clean up the Certificate Manager content */
static void UA_CertificateManager_clear(UA_CertificateManager *cm) {
    if (cm == NULL) {
        return;
    }
    CertificateManagerContext *context = (CertificateManagerContext *)cm->keyAndCertContext;
    if (context != NULL) {
    	if (context->certificate != NULL) {
    		X509_free(context->certificate);
    	}
    	if (context->privateKey != NULL) {
    		EVP_PKEY_free(context->privateKey);
    	}
        UA_free(context);
        cm->keyAndCertContext = NULL;
        cm->createCertificateSigningRequest = NULL;
    }
}

/* Initialize the Certificate Manager */
UA_StatusCode
UA_CertificateManager_create_old(UA_CertificateManager *cm,
                            const UA_ByteString *certificate,
                            const UA_ByteString *privateKey) {
	if ((cm == NULL) || (certificate == NULL) || (privateKey == NULL) ||
	    (certificate->length == 0) || (privateKey->length == 0)) {
	    return UA_STATUSCODE_BADINVALIDARGUMENT;
	}

	CertificateManagerContext *context;
	context = (CertificateManagerContext *)UA_malloc(sizeof(CertificateManagerContext));

	/* Init certificate manager context */
	context->privateKey = NULL;
	context->certificate = NULL;

	if (context != NULL) {
	    /* Set certificate */
	    const unsigned char* ptrCert = certificate->data;
	    context->certificate = NULL;
	    context->certificate= d2i_X509(0, &ptrCert, (long)certificate->length);
	    if (context->certificate == NULL) {
	    	return UA_STATUSCODE_BADINTERNALERROR;
	    }

	    /* Set private key */
	    const unsigned char* ptrPK = privateKey->data;
	    context->privateKey = NULL;
	    context->privateKey = d2i_AutoPrivateKey(0, &ptrPK, (long)privateKey->length);
	    if (context->privateKey == NULL) {
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
