/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2022 (c) Mark Giraud, Fraunhofer IOSB
 */

#include <open62541/plugin/certstore.h>
#include <open62541/plugin/certstore_default.h>
#include <dirent.h>
#include <open62541/types_generated_handling.h>
#include <sys/stat.h>
#include <libgen.h>

static UA_StatusCode
readFileToByteString(const char *const path, UA_ByteString *data) {
	if (path == NULL || data == NULL) {
		return UA_STATUSCODE_BADINTERNALERROR;
	}

    /* Open the file */
    FILE *fp = fopen(path, "rb");
    if(!fp) {
        return UA_STATUSCODE_BADNOTFOUND;
    }

    /* Get the file length, allocate the data and read */
    fseek(fp, 0, SEEK_END);
    UA_StatusCode retval = UA_ByteString_allocBuffer(data, (size_t)ftell(fp));
    if(retval == UA_STATUSCODE_GOOD) {
        fseek(fp, 0, SEEK_SET);
        size_t read = fread(data->data, sizeof(UA_Byte), data->length * sizeof(UA_Byte), fp);
        if(read != data->length) {
            UA_ByteString_clear(data);
        }
    } else {
        data->length = 0;
    }
    fclose(fp);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeByteStringToFile(const char *const path, const UA_ByteString *data) {
	UA_StatusCode retval = UA_STATUSCODE_GOOD;

	/* Open the file */
    FILE *fp = fopen(path, "wb");
    if(!fp) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Write byte string to file */
    size_t len = fwrite(data->data, sizeof(UA_Byte), data->length * sizeof(UA_Byte), fp);
    if(len != data->length) {
    	retval = UA_STATUSCODE_BADINTERNALERROR;
    }

    fclose(fp);
    return retval;
}

static UA_StatusCode
removeAllFilesFromDir(const char *const path) {
	UA_StatusCode retval = UA_STATUSCODE_GOOD;

	/* Check parameter */
	if (path == NULL) {
		return UA_STATUSCODE_BADINTERNALERROR;
	}

	/* remove all regular files from directory */
	DIR *dir = opendir(path);
	if(dir) {
        struct dirent *dirent;
	    while((dirent = readdir(dir)) != NULL) {
	        if(dirent->d_type == DT_REG) {
	        	char file_name[FILENAME_MAX];
	            snprintf(file_name, FILENAME_MAX, "%s/%s", path, (char*)dirent->d_name);
	            remove(file_name);
	        }
	    }
	    closedir(dir);
	}
	return retval;
}

static int
mkpath(char *dir, mode_t mode) {
    struct stat sb;
    if(!dir) {
        errno = EINVAL;
        return 1;
    }
    if(!stat(dir, &sb))
        return 0;
    mkpath(dirname(strdupa(dir)), mode);
    return mkdir(dir, mode);
}

static UA_StatusCode
setupPkiDir(char *directory, char *cwd, size_t cwdLen, char **out) {
    strncpy(&cwd[cwdLen], directory, PATH_MAX - cwdLen);
    *out = strndup(cwd, PATH_MAX - cwdLen);
    if(*out == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;
    mkpath(*out, 0777);
    return UA_STATUSCODE_GOOD;
}

typedef struct FilePKIStore {
    char *trustedCertDir;
    size_t trustedCertDirLen;
    char *trustedCrlDir;
    size_t trustedCrlDirLen;
    char *trustedIssuerCertDir;
    size_t trustedIssuerCertDirLen;
    char *trustedIssuerCrlDir;
    size_t trustedIssuerCrlDirLen;
    char *certificateDir;
    size_t certificateDirLen;
    char *rejectedCertDir;
    size_t rejectedCertDirLen;
    char *keyDir;
    size_t keyDirLen;
} FilePKIStore;

static UA_StatusCode
loadList(UA_ByteString **list, size_t *listSize, const char *listPath) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Determine number of certificates */
    size_t numCerts = 0;
    DIR *dir = opendir(listPath);
    if(dir) {
        struct dirent *dirent;
        while((dirent = readdir(dir)) != NULL) {
            if(dirent->d_type == DT_REG) {
            	numCerts++;
            }
        }
        closedir(dir);
    }

    retval = UA_Array_resize((void **)list, listSize, numCerts, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if (retval != UA_STATUSCODE_GOOD) {
    	return retval;
    }

    /* Read files from directory */
    size_t numActCerts = 0;
    dir = opendir(listPath);
    if(dir) {
        struct dirent *dirent;
        while((dirent = readdir(dir)) != NULL) {
            if(dirent->d_type == DT_REG) {

            	if (numActCerts < numCerts) {
            		/* Create filename to load */
            		char filename[FILENAME_MAX];
            		if(snprintf(filename, FILENAME_MAX, "%s/%s", listPath, dirent->d_name) < 0) {
            			closedir(dir);
            			return UA_STATUSCODE_BADINTERNALERROR;
            		}

            		/* Load data from file */
            		retval = readFileToByteString(filename, &((*list)[numActCerts]));
            		if (retval != UA_STATUSCODE_GOOD) {
            			closedir(dir);
            			return retval;
            		}
            	}

                numActCerts++;
            }
        }
        closedir(dir);
    }

    return retval;
}

static UA_StatusCode
storeList(const UA_ByteString *list, size_t listSize, const char *listPath) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Check parameter */
    if (listPath == NULL) {
    	return UA_STATUSCODE_BADINTERNALERROR;
    }
    if (listSize > 0 && list == NULL) {
    	return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* remove existing files in directory */
    retval = removeAllFilesFromDir(listPath);
    if (retval != UA_STATUSCODE_GOOD) {
    	return retval;
    }

    /* Store new byte strings */
    size_t idx = 0;
    for (idx = 0; idx < listSize; idx++) {
    	/* FIXME: TODO create thumbprint */

       	/* Create filename to load */
        char filename[FILENAME_MAX];
        if(snprintf(filename, FILENAME_MAX, "%s/%s%ld", listPath, "file", idx) < 0) {
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        /* Store data in file */
        retval = writeByteStringToFile(filename, &list[idx]);
        if (retval != UA_STATUSCODE_GOOD) {
        	return retval;
        }
    }

    return retval;
}

static UA_StatusCode
loadTrustList_file(UA_PKIStore *certStore, UA_TrustListDataType *trustList) {
    /* Check parameter */
	if (certStore == NULL || trustList == NULL) {
		return UA_STATUSCODE_BADINTERNALERROR;
	}

	FilePKIStore *context = (FilePKIStore *)certStore->context;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES) {
        retval = loadList(&trustList->trustedCertificates, &trustList->trustedCertificatesSize,
                          context->trustedCertDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCRLS) {
        retval = loadList(&trustList->trustedCrls, &trustList->trustedCrlsSize,
                          context->trustedCrlDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_ISSUERCERTIFICATES) {
        retval = loadList(&trustList->issuerCertificates, &trustList->issuerCertificatesSize,
                          context->trustedIssuerCertDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_ISSUERCRLS) {
        retval = loadList(&trustList->issuerCrls, &trustList->issuerCrlsSize,
                          context->trustedIssuerCrlDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    return retval;
}


static UA_StatusCode
storeTrustList_file(UA_PKIStore *certStore, const UA_TrustListDataType *trustList) {
	/* Check parameter */
	if (certStore == NULL || trustList == NULL) {
		return UA_STATUSCODE_BADINTERNALERROR;
	}

    FilePKIStore *context = (FilePKIStore *)certStore->context;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES) {
        retval = storeList(trustList->trustedCertificates, trustList->trustedCertificatesSize,
                          context->trustedCertDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCRLS) {
        retval = storeList(trustList->trustedCrls, trustList->trustedCrlsSize,
                          context->trustedCrlDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_ISSUERCERTIFICATES) {
        retval = storeList(trustList->issuerCertificates, trustList->issuerCertificatesSize,
                          context->trustedIssuerCertDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    if(trustList->specifiedLists & UA_TRUSTLISTMASKS_ISSUERCRLS) {
        retval = storeList(trustList->issuerCrls, trustList->issuerCrlsSize,
                          context->trustedIssuerCrlDir);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }
    return retval;
}

static UA_StatusCode
loadRejectedList(UA_PKIStore *certStore, UA_ByteString **rejectedList, size_t *rejectedListSize)
{
    /* Check parameter */
	if (certStore == NULL || rejectedList == NULL || rejectedListSize == NULL) {
		return UA_STATUSCODE_BADINTERNALERROR;
	}

    FilePKIStore *context = (FilePKIStore *)certStore->context;

    return loadList(rejectedList, rejectedListSize, context->rejectedCertDir);
}

static UA_StatusCode
storeRejectedList(UA_PKIStore *certStore, const UA_ByteString *rejectedList, size_t rejectedListSize)
{
    /* Check parameter */
	if (certStore == NULL) {
		return UA_STATUSCODE_BADINTERNALERROR;
	}

	FilePKIStore *context = (FilePKIStore *)certStore->context;

	return storeList(rejectedList, rejectedListSize, context->rejectedCertDir);
}

static UA_StatusCode
appendRejectedList(UA_PKIStore *certStore, const UA_ByteString *certificate)
{
    /* Check parameter */
	if (certStore == NULL || certificate == NULL) {
		return UA_STATUSCODE_BADINTERNALERROR;
	}

	FilePKIStore *context = (FilePKIStore *)certStore->context;

  	/* Create filename to load */
    char filename[FILENAME_MAX];
    if(snprintf(filename, FILENAME_MAX, "%s/%s", context->rejectedCertDir, "file") < 0) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Store data in file */
    return writeByteStringToFile(filename, certificate);
}

static UA_StatusCode
loadCertificate_file(UA_PKIStore *pkiStore, const UA_NodeId certType, UA_ByteString *cert) {
    if(pkiStore == NULL || cert == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_ByteString_clear(cert);
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    UA_String nodeIdStr;
    UA_String_init(&nodeIdStr);
    UA_NodeId_print(&certType, &nodeIdStr);

    FilePKIStore *context = (FilePKIStore *)pkiStore->context;
    char filename[FILENAME_MAX];
    if(snprintf(filename, FILENAME_MAX, "%s/%s", context->certificateDir, nodeIdStr.data) < 0) {
        retval = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    retval = readFileToByteString(filename, cert);

cleanup:

    UA_String_clear(&nodeIdStr);
    return retval;
}

static UA_StatusCode
storeCertificate_file(UA_PKIStore *pkiStore, const UA_NodeId certType, const UA_ByteString *cert)
{
    if(pkiStore == NULL || cert == NULL || cert->length == 0) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    UA_String nodeIdStr;
    UA_String_init(&nodeIdStr);
    UA_NodeId_print(&certType, &nodeIdStr);

    FilePKIStore *context = (FilePKIStore *)pkiStore->context;
    char filename[FILENAME_MAX];
    if(snprintf(filename, FILENAME_MAX, "%s/%s", context->certificateDir, nodeIdStr.data) < 0) {
        retval = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    retval = writeByteStringToFile(filename, cert);

cleanup:

    UA_String_clear(&nodeIdStr);
    return retval;
}

static UA_StatusCode
loadPrivateKey_file(UA_PKIStore *pkiStore, const UA_NodeId certType, UA_ByteString *privateKey)
{
    if(pkiStore == NULL || privateKey == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_ByteString_clear(privateKey);
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    UA_String nodeIdStr;
    UA_String_init(&nodeIdStr);
    UA_NodeId_print(&certType, &nodeIdStr);

    FilePKIStore *context = (FilePKIStore *)pkiStore->context;
    char filename[FILENAME_MAX];
    if(snprintf(filename, FILENAME_MAX, "%s/%s", context->keyDir, nodeIdStr.data) < 0) {
        retval = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    retval = readFileToByteString(filename, privateKey);

cleanup:

    UA_String_clear(&nodeIdStr);
    return retval;
}


static UA_StatusCode
storePrivateKey_file(UA_PKIStore *pkiStore, const UA_NodeId certType, const UA_ByteString *privateKey)
{
	   if(pkiStore == NULL || privateKey == NULL || privateKey->length == 0) {
	        return UA_STATUSCODE_BADINTERNALERROR;
	    }
	    UA_StatusCode retval = UA_STATUSCODE_GOOD;

	    UA_String nodeIdStr;
	    UA_String_init(&nodeIdStr);
	    UA_NodeId_print(&certType, &nodeIdStr);

	    FilePKIStore *context = (FilePKIStore *)pkiStore->context;
	    char filename[FILENAME_MAX];
	    if(snprintf(filename, FILENAME_MAX, "%s/%s", context->keyDir, nodeIdStr.data) < 0) {
	        retval = UA_STATUSCODE_BADINTERNALERROR;
	        goto cleanup;
	    }

	    retval = writeByteStringToFile(filename, privateKey);

	cleanup:

	    UA_String_clear(&nodeIdStr);
	    return retval;
}

static UA_StatusCode
clear_file(UA_PKIStore *certStore) {
	/* check parameter */
	if (certStore == NULL) {
		return UA_STATUSCODE_BADINTERNALERROR;
	}

    FilePKIStore *context = (FilePKIStore *)certStore->context;
    if(context) {
        if(context->trustedCertDir)
            UA_free(context->trustedCertDir);
        if(context->trustedCrlDir)
            UA_free(context->trustedCrlDir);
        if(context->trustedIssuerCertDir)
            UA_free(context->trustedIssuerCertDir);
        if(context->trustedIssuerCrlDir)
            UA_free(context->trustedIssuerCrlDir);
        if(context->certificateDir)
            UA_free(context->certificateDir);
        if(context->rejectedCertDir)
            UA_free(context->rejectedCertDir);
        if(context->keyDir)
            UA_free(context->keyDir);
        UA_free(context);
    }

    UA_NodeId_clear(&certStore->certificateGroupId);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_PKIStore_File(UA_PKIStore *pkiStore, UA_NodeId *certificateGroupId) {

	/* Check parameter */
    if(pkiStore == NULL || certificateGroupId == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    memset(pkiStore, 0, sizeof(UA_PKIStore));
    char cwd[PATH_MAX];
    if(getcwd(cwd, PATH_MAX) == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    size_t cwdLen = strnlen(cwd, PATH_MAX);

    FilePKIStore *context = (FilePKIStore *)UA_malloc(sizeof(FilePKIStore));
    pkiStore->loadTrustList = loadTrustList_file;
    pkiStore->storeTrustList = storeTrustList_file;
    pkiStore->loadRejectedList = loadRejectedList;
    pkiStore->storeRejectedList = storeRejectedList;
    pkiStore->appendRejectedList = appendRejectedList;
    pkiStore->loadCertificate = loadCertificate_file;
    pkiStore->storeCertificate = storeCertificate_file;
    pkiStore->loadPrivateKey = loadPrivateKey_file;
    pkiStore->storePrivateKey = storePrivateKey_file;
    pkiStore->clear = clear_file;
    pkiStore->context = context;

    strncpy(&cwd[cwdLen], "/pki/", PATH_MAX - cwdLen);
    cwdLen = strnlen(cwd, PATH_MAX);

    UA_String nodeIdStr;
    UA_String_init(&nodeIdStr);
    UA_NodeId_print(certificateGroupId, &nodeIdStr);
    strncpy(&cwd[cwdLen], (char *)nodeIdStr.data, PATH_MAX - cwdLen);
    cwdLen = strnlen(cwd, PATH_MAX);
    UA_String_clear(&nodeIdStr);

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= setupPkiDir("/trusted/certs", cwd, cwdLen, &context->trustedCertDir);
    retval |= setupPkiDir("/trusted/crls", cwd, cwdLen, &context->trustedCrlDir);
    retval |= setupPkiDir("/issuer/certs", cwd, cwdLen, &context->trustedIssuerCertDir);
    retval |= setupPkiDir("/issuer/crls", cwd, cwdLen, &context->trustedIssuerCrlDir);
    retval |= setupPkiDir("/rejected/certs", cwd, cwdLen, &context->rejectedCertDir);
    retval |= setupPkiDir("/own/certs", cwd, cwdLen, &context->certificateDir);
    retval |= setupPkiDir("/own/keys", cwd, cwdLen, &context->keyDir);
    if(retval != UA_STATUSCODE_GOOD) {
        goto error;
    }

    UA_NodeId_copy(certificateGroupId, &pkiStore->certificateGroupId);

    return UA_STATUSCODE_GOOD;

error:
    pkiStore->clear(pkiStore);
    return UA_STATUSCODE_BADINTERNALERROR;
}
