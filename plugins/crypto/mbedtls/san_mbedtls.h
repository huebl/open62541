#ifndef san_mbedtls_H_
#define san_mbedtls_H_

#include <open62541/config.h>

#ifdef UA_ENABLE_ENCRYPTION_MBEDTLS

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

typedef struct san_mbedtls_san_list_entry_s
{
	mbedtls_x509_subject_alternative_name san;
	struct san_mbedtls_san_list_entry_s* next;
} san_mbedtls_san_list_entry_t;

void san_mbedtls_san_list_entry_free(san_mbedtls_san_list_entry_t* san_list_entry);

san_mbedtls_san_list_entry_t* san_mbedtls_get_san_list_from_cert(const mbedtls_x509_crt* cert);

int san_mbedtls_set_san_list_to_csr(mbedtls_x509write_csr* req, const san_mbedtls_san_list_entry_t* san_list);

#endif

#endif /* UA_SECURITYPOLICY_MBEDTLS_COMMON_H_ */
