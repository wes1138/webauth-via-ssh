#include "fcgi_stdio.h" /* fcgi library; put it first*/

#include <stdlib.h>

int count;

void initialize(void)
{
	count=0;
}

int main(void)
{
	/* Initialization. */  
	initialize();

	/* Response loop. */
	/* NOTE: Before the double \r\n, it seems that you can write
	 * whatever headers you want.  There seems to be some filtering
	 * done by libfcgi (or nginx?), but not too much (e.g., "Content-type"
	 * was replaced with "Content-Type").  Other headers were also added
	 * (probably by libfcgi?), like the usual HTTP/1.1 200 OK.  I would guess
	 * that if you write different response codes, they'll be more or less
	 * preserved, and will overwrite the defaults.
	 * https://en.wikipedia.org/wiki/HTTP_cookie#Setting_a_cookie  */
	const char* vars[] = {"QUERY_STRING","REQUEST_METHOD","CONTENT_TYPE",
		"CONTENT_LENGTH","SCRIPT_NAME","REQUEST_URI","DOCUMENT_URI",
		"DOCUMENT_ROOT","SERVER_PROTOCOL","REMOTE_ADDR","REMOTE_PORT",
		"SERVER_ADDR","SERVER_PORT","SERVER_NAME","HTTP_COOKIE","REQUEST_BODY"
	};
	while (FCGI_Accept() >= 0)   {
		printf("Content-type: text/html\r\n"
				"Set-Cookie: lolcook=this is a fine cookie.\r\n"
				"\r\n"
				"<title>FastCGI Hello! (C, fcgi_stdio library)</title>"
				"<h1>FastCGI Hello! (C, fcgi_stdio library)</h1>"
				"Request number %d running on host <i>%s</i>\n",
				++count, getenv("SERVER_NAME"));
		printf("%s","<br /><br />");
		int i;
		for (i = 0; i < sizeof(vars)/sizeof(char*); i++) {
			printf("%s: %s<br />\n",vars[i],getenv(vars[i]));
		}
	}
	return 0;
}

