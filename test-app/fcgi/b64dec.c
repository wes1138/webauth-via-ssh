#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

/* decode base64 using openssl.  Adapted from:
 * http://doctrina.org/Base64-With-OpenSSL-C-API.html */
size_t Base64Decode(char* b64message, char** buffer)
{
	BIO *bio, *b64;
	int decodeLen = (strlen(b64message) * 3) / 4, len = 0;
	*buffer = (char*)malloc(decodeLen+1);
	FILE* stream = fmemopen(b64message, strlen(b64message), "r");
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stream, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	len = BIO_read(bio, *buffer, strlen(b64message));
	(*buffer)[len] = 0;

	BIO_free_all(bio);
	fclose(stream);

	return len;
}

