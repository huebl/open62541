#include "san_mbedtls.h"

#ifdef UA_ENABLE_ENCRYPTION_MBEDTLS


#include <mbedtls/platform.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>

#define MBEDTLS_SAN_MAX_LEN    64

#define SAN_CHK_ASN1_ADD(s, b, f) 						\
    do                                                  \
    {                                                   \
        if((ret = (f)) < 0) {                       	\
			mbedtls_free(b);                            \
            return ret;                                 \
        } else {                                        \
            (s) += (size_t)ret;                         \
        }												\
} while( 0 )


static san_mbedtls_san_list_entry_t* san_mbedtls_san_list_entry_new(void)
{
	san_mbedtls_san_list_entry_t* san_list_entry = NULL;

	san_list_entry = (san_mbedtls_san_list_entry_t*)mbedtls_calloc(1, sizeof(san_mbedtls_san_list_entry_t));
	memset(san_list_entry, 0x00, sizeof(san_mbedtls_san_list_entry_t));

	return san_list_entry;
}

void san_mbedtls_san_list_entry_free(san_mbedtls_san_list_entry_t* san_list_entry)
{
	/* Check parameter */
	if (san_list_entry == NULL) return;

	/* Delete all entries in chain */
	san_mbedtls_san_list_entry_t* cur = san_list_entry;
	while (cur != NULL) {
		san_list_entry = cur;
		cur = cur->next;
		mbedtls_free(san_list_entry);
	}
}

static size_t san_mbedtls_san_list_size(const san_mbedtls_san_list_entry_t* san_list)
{
	/* check parameter */
	if (san_list == NULL) return 0;

	/* Count entries in san list */
	size_t count = 0;
	const san_mbedtls_san_list_entry_t* cur = san_list;
	while (cur != NULL) {
		count++;
		cur = cur->next;
	}

	return count;
}

san_mbedtls_san_list_entry_t* san_mbedtls_get_san_list_from_cert(const mbedtls_x509_crt* cert)
{
	/* Check parameter */
	if (cert == NULL) {
		return NULL;
	}

	/* Read subject alternate names from certificate */
	san_mbedtls_san_list_entry_t* san_list = NULL;
	const mbedtls_x509_sequence* cur = &cert->subject_alt_names;

    while (cur != NULL) {
    	san_mbedtls_san_list_entry_t* san_list_entry = NULL;

    	int type = 0;
    	switch (cur->buf.tag & (MBEDTLS_ASN1_TAG_CLASS_MASK | MBEDTLS_ASN1_TAG_VALUE_MASK))
    	{
    		case (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_DNS_NAME):
			{
    			type = MBEDTLS_X509_SAN_DNS_NAME;
    	        break;
			}
    		case (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER):
			{
    			type = MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER;
    			break;
			}
    		case (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_IP_ADDRESS):
			{
    			type = MBEDTLS_X509_SAN_IP_ADDRESS;
    			break;
			}
     		default:
    		{
    			/* Ignore other subject alternate names */
    			cur = cur->next;
    			continue;
    		}
    	}

		san_list_entry = san_mbedtls_san_list_entry_new();
		if (san_list_entry == NULL) {
			san_mbedtls_san_list_entry_free(san_list);
			return NULL;
		}

		san_list_entry->san.type = type;
        memcpy(&san_list_entry->san.san.unstructured_name, &cur->buf, sizeof(cur->buf));
        if (san_list != NULL) san_list_entry->next = san_list;
        san_list = san_list_entry;

    	cur = cur->next;
    }

	return san_list;
}

int san_mbedtls_set_san_list_to_csr(mbedtls_x509write_csr* req,
		                             const san_mbedtls_san_list_entry_t* san_list)
{
	int ret = 0;

	/* check parameter */
	if (req == NULL || san_list == NULL) return 0;

	/* Calculate size of extension buffer */
	size_t san_list_size = san_mbedtls_san_list_size(san_list);
	if (san_list_size == 0) return 1;
	size_t ext_buf_size = (san_list_size * (MBEDTLS_SAN_MAX_LEN +2)) + 2;

	/* Create extension buffer */
	unsigned char* ext_buf = (unsigned char*)mbedtls_calloc(1, ext_buf_size);
	if (ext_buf == NULL) return 0;
	memset(ext_buf, 0x00, ext_buf_size);

	/* Write san entries to extension buffer */
	const san_mbedtls_san_list_entry_t* cur = san_list;
	unsigned char* pc = ext_buf + ext_buf_size;
	size_t len = 0;
	while (cur != NULL) {
		switch (cur->san.type)
		{
			case MBEDTLS_X509_SAN_DNS_NAME:
			case MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
			case MBEDTLS_X509_SAN_IP_ADDRESS:
			{
				/* Write variable to extension buffer */
				SAN_CHK_ASN1_ADD(len, ext_buf, mbedtls_asn1_write_raw_buffer(
					&pc, ext_buf, cur->san.san.unstructured_name.p, cur->san.san.unstructured_name.len));

				SAN_CHK_ASN1_ADD(len, ext_buf, mbedtls_asn1_write_len(
					&pc, ext_buf, cur->san.san.unstructured_name.len));

				SAN_CHK_ASN1_ADD(len, ext_buf, mbedtls_asn1_write_tag(
					&pc, ext_buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | (unsigned char)cur->san.type));

				break;
			}
	   		default:
	    	{
	    		/* Ignore other subject alternate names */
	    	}
		}
		cur = cur->next;
	}
	if (len == 0) {
		mbedtls_free(ext_buf);
		return 1;
	}

	/* Write sequence info to extension buffer */
	SAN_CHK_ASN1_ADD(len, ext_buf, mbedtls_asn1_write_len(&pc, ext_buf, len));
	SAN_CHK_ASN1_ADD(len, ext_buf, mbedtls_asn1_write_tag(&pc, ext_buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	/* Write extension buffer to CSR */
	ret = mbedtls_x509write_csr_set_extension(
			req, MBEDTLS_OID_SUBJECT_ALT_NAME, MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
            ext_buf + ext_buf_size - len, len);
	if (ret != 0) {
		mbedtls_free(ext_buf);
		return 0;
	}

	mbedtls_free(ext_buf);
	return 1;
}

bool san_mbedtls_get_uniform_resource_identifier(
	san_mbedtls_san_list_entry_t* san_list,
	UA_String* uniform_resource_identifier
)
{
	/* Check parameter */
	if (san_list == NULL || uniform_resource_identifier == NULL) {
		return false;
	}

	UA_String_init(uniform_resource_identifier);

	const san_mbedtls_san_list_entry_t* cur = san_list;
	while (cur != NULL) {
		if (cur->san.type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) {
			uniform_resource_identifier->length = cur->san.san.unstructured_name.len;
			uniform_resource_identifier->data =  cur->san.san.unstructured_name.p;
			return true;
		}
	}
	return false;
}

#endif
