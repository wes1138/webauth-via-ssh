/* Generate authentication tokens.
 *
 * By virtue of being able to run this code on this machine,
 * the user (named in the arguments) has been authenticated.
 * The command listed in ssh authorized_keys is used to ensure
 * that this script is called with the appropriate username.
 * (This program will generate a token for any user passed to it.)
 * */

#include <stdio.h>
#include <getopt.h>
#include <time.h>
#include <string.h>

/* NOTE: we use openssl for hmac since (until recently) openssh depended
 * on it, and there wouldn't be any new dependencies needed.  */
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "common.h"

#define FNAME_LEN   256
#define UNAME_LEN   64
#define TIME_LEN    16 /* on current machines, should never exceed 8 */
#define HMAC_LEN    20
#define MAX_KEY_LEN 256

static const int inputLen = UNAME_LEN + TIME_LEN;
static const int tokenLen = UNAME_LEN + TIME_LEN + HMAC_LEN;

int main(int argc, char *argv[]) {
	static struct option long_opts[] = {
		{"user",    required_argument, 0, 'u'},
		{"key",     required_argument, 0, 'k'},
		{"text",    no_argument,       0, 't'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	char keyfile[FNAME_LEN];
	char username[UNAME_LEN];
	memset(username,0,UNAME_LEN);
	memset(keyfile,0,FNAME_LEN);
	strncpy(keyfile,"/tmp/.webtoken-key",FNAME_LEN-1);
	char c;
	int textmode = 0;
	int opt_index = 0;
	while ((c = getopt_long(argc, argv, "u:k:th", long_opts,
					&opt_index)) != -1) {
		switch (c) {
			case 'u':
				strncpy(username,optarg,UNAME_LEN-1);
				username[UNAME_LEN-1] = 0;
				break;
			case 'k':
				strncpy(keyfile,optarg,FNAME_LEN-1);
				keyfile[FNAME_LEN-1] = 0;
				break;
			case 't':
				textmode = 1;
				break;
			case 'h':
			case '?':
				printf("Usage: %s [OPTIONS]...\n"
					"Generate authentication tokens.\n\n"
					"   -u,--user  USER    generate token for user USER.\n"
					"   -k,--key   FILE    read key from FILE.\n"
					"   -t,--text          output in a human-readable format.\n"
					"   --help             show this message and exit.\n",
						argv[0]);
				return (c == 'h') ? 0 : misc_badness;
		}
	}

	if (username[0] == 0) {
		fprintf(stderr, "username is a required argument.\n");
		return unknown_key;
		/* the authorized_keys_command can send us an empty string if no
		 * match is found. */
	}

	/* construct username|expirationdate|HMAC(first two fields).
	 * You should pad the username, and maybe the other too. */
	unsigned char key[MAX_KEY_LEN];
	FILE* f = fopen(keyfile,"rb");
	if (!f) {
		fprintf(stderr, "key file (%s) not found.\n",keyfile);
		return server_error;
	}
	fseek(f,0L,SEEK_END);
	long ksize = ftell(f);
	rewind(f);
	if (ksize > MAX_KEY_LEN) {
		fprintf(stderr, "MAX_KEY_LEN (%i) exceeded: key had %lu bytes\n",
				MAX_KEY_LEN,ksize);
		return server_error;
	}

	size_t bread = fread(key,1,ksize,f);
	if (bread != ksize) {
		fprintf(stderr, "Failed reading key from %s\n", keyfile);
		return server_error;
	}
	fclose(f);

	/* construct token as:
	 * input := username|expiration
	 * token := input|hmac(input,key) */
	time_t exptime = time(0) + 1800; /* half an hour from now */
	unsigned char token[tokenLen];
	memset(token,0,inputLen);
	memcpy(token,username,UNAME_LEN);
	memcpy(token+UNAME_LEN,&exptime,sizeof(time_t));
	unsigned int macsize;
	HMAC(EVP_sha1(),key,ksize,token,inputLen,token+inputLen,&macsize);
	if (macsize != HMAC_LEN) {
		fprintf(stderr, "warning: HMAC wrote %i != %i bytes\n",
				macsize,HMAC_LEN);
	}
	size_t i, written;
	if (textmode) {
		printf("%s|%lu|",username,exptime);
		for (i = 0; i < HMAC_LEN; i++) {
			printf("%02x",token[inputLen + i]);
		}
		printf("\n");
	} else {
		written = 0;
		while(written < tokenLen) {
			written += fwrite(token+written,1,tokenLen - written,stdout);
		}
	}

	return success;
}
