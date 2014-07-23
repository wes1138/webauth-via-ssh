#include "fcgi_stdio.h" /* fcgi library; put it first*/

#include <stdlib.h>

#include <string>
#include <map>
using std::string;
using std::map;
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define AUTH_COOKIE_NAME "auth-token="

map<string,string> data;

int count;

char *loginHtml, *editHtml;
/* NOTE: these last the life of the program, so no need
 * to free them later. */

int fileToString(const char* fname, char** content)
{
	FILE* f = fopen(fname,"rb");
	if (!f) return -1;
	fseek(f,0L,SEEK_END);
	size_t fsize = ftell(f);
	rewind(f);
	*content = new char[fsize+1];
	(*content)[fsize] = 0; /* make sure it is a c-string. */
	fread(*content,1,fsize,f);
	fclose(f);
	return 0;
}

void initialize(void)
{
	fileToString(HTMLPATH"login.html",&loginHtml);
	count=0;
}

/* this relies on stdio.h, so we have to place it in its
 * own module to avoid conflicts with fcgi_stdio. */
extern "C"
size_t Base64Decode(char* b64message, char** buffer);

/* XXX: there is unnecessary coupling of this program with the
 * token stuff.  Should be separated into a token checking/verifying
 * daemon that this code talks to.  */
#define FNAME_LEN   256
#define UNAME_LEN   64
#define TIME_LEN    16 /* on current machines, should never exceed 8 */
#define HMAC_LEN    20
#define MAX_KEY_LEN 256
/* you'll need these for tokend: */
// const int inputLen = UNAME_LEN + TIME_LEN + sizeof(keyIndex);
// const int tokenLen = UNAME_LEN + TIME_LEN + sizeof(keyIndex) + HMAC_LEN;
const int inputLen = UNAME_LEN + TIME_LEN;
const int tokenLen = UNAME_LEN + TIME_LEN + HMAC_LEN;
const char* keyfile = "/tmp/.webtoken-key";

int checkToken(const string& b64token, string& username /* [output] */)
{
	/* These return codes can be used for tokend later:
	 * 0 -- success
	 * 1 -- expired
	 * 2 -- invalid (good format, but the key says "no")
	 * 3 -- malformed token (i.e., it had the wrong length, or
	 *      the username wasn't null-{padded,terminated}).
	 * 4 -- internal error
	 * */
	int rcode = 4; /* default to an error so we know if the code
	                  wasn't set. */
	unsigned char key[MAX_KEY_LEN];
	FILE* f = fopen(keyfile,"rb");
	if (!f) return 4;
	fseek(f,0L,SEEK_END);
	size_t ksize = ftell(f);
	rewind(f);
	if (ksize > MAX_KEY_LEN) return 4;

	size_t bread = fread(key,1,ksize,f);
	if (bread != ksize) return 4;
	fclose(f);

	unsigned char mac[HMAC_LEN];
	unsigned int macsize,i;
	char* tcopy = new char[b64token.length()+1];
	strncpy(tcopy,b64token.c_str(),b64token.length()+1);
	char* token;
	size_t tlen = Base64Decode(tcopy,&token);
	/* from this point on, don't return, but goto done */
	if (tlen != tokenLen || token[UNAME_LEN - 1] != 0) {
		/* NOTE: it should technically violate the format if
		 * there are non-consecutive null chars in the first 64. */
		rcode = 3;
		goto done;
	} else {
		/* extract username */
		username = token;
		/* check for expiration */
		time_t exptime;
		memcpy(&exptime,token+UNAME_LEN,sizeof(time_t));
		if (exptime < time(0)) {
			rcode = 1;
			goto done;
		}
		unsigned char* tmac = (unsigned char*)token + inputLen;
		HMAC(EVP_sha1(),key,ksize,(unsigned char*)token,inputLen,mac,&macsize);
		/* now check against the token's mac */
		for (i=0; i<HMAC_LEN; i++) {
			if (mac[i] != tmac[i]) break;
		}
		rcode = (i == HMAC_LEN) ? 0 : 2;
		goto done;
	}

done:
	free(token);
	return rcode;
}

int main(void)
{
	initialize();

	#if 0
	/* for reference, here are some of the headers we can get
	 * via the environment: */
	const char* vars[] = {"QUERY_STRING","REQUEST_METHOD","CONTENT_TYPE",
		"CONTENT_LENGTH","SCRIPT_NAME","REQUEST_URI","DOCUMENT_URI",
		"DOCUMENT_ROOT","SERVER_PROTOCOL","REMOTE_ADDR","REMOTE_PORT",
		"SERVER_ADDR","SERVER_PORT","SERVER_NAME","HTTP_COOKIE","REQUEST_BODY"
	};
	#endif

	string authResult;

	while (FCGI_Accept() >= 0)   {
		/* first, need to parse cookie string, looking for the "auth-token"
		 * cookie.  Remember, in the Set-Cookie response header, there is
		 * only one cookie, with attributes separated by ";" while the
		 * Cookie: in the request header has all the cookies separated
		 * by ";" with attributes separated by ",". */
		string username;
		string cookie = getenv("HTTP_COOKIE");
		string cname = AUTH_COOKIE_NAME;
		string ccontent; /* value of the cookie */
		size_t cstart = cookie.find(cname);
		/* No token at all: go to signup / registration.
		 * Token is there, but old: load the js that talks to authd, and on
		 * success, automatically redirect to their personal page.  */
		if (cstart == string::npos) {
			/* fresh start; deliver sign in / register page. */
			/* NOTE: if you give back a page that references some js script
			 * (not inline), this will prompt further http requests, right?
			 * Is that a good enough reason to do it inline?  Try it for now. */
			/* first print the http header: */
			printf("Content-type: text/html\r\n\r\n");
			printf("%s\n",loginHtml);
			continue;
		}

		/* parse the rest of that cookie */
		size_t cend = cookie.find(";",cstart);
		if (cend != string::npos) /* convert from position to length */
			cend = cend - cstart - cname.length();
		ccontent = cookie.substr(cstart + cname.length(), cend);
		int rcode = checkToken(ccontent,username);
		switch (rcode) {
			case 0: /* success */
				/* for now, just print a status message */
				authResult = "authentication succeeded";
				break;
			case 1:
				authResult = "token expired";
				break;
			case 2:
				authResult = "invalid token";
				break;
			case 3:
				authResult = "malformed token";
				break;
			default: /* rcode==4, or something we didn't expect. */
				authResult = "internal error x_x";
				break;
		}

		if (rcode) {
			string setcook;
			if (rcode < 4) {
				/* remove cookie */
				setcook = "Set-Cookie: "AUTH_COOKIE_NAME
					"; expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n";
			}
			printf("Content-type: text/html\r\n"
					"%s" /* set-cookie, or empty string. */
					"\r\n"
					"<!DOCTYPE html>\n"
					"<html xmlns=\"http://www.w3.org/1999/xhtml\">"
					"<head>\n"
					"<title>SSH for the web: test page</title>\n"
					"</head><body>\n"
					"Authentication failure for user %s:<br />%s\n"
					"</body></html>",
					setcook.c_str(),username.c_str(),authResult.c_str());
			/* XXX in a "real" application, you'd have to make something
			 * more sophisticated, as this would discard any edits for
			 * which the POST happened after the token expired.
			 * */
			continue;
		}

		/************** AT THIS POINT, THE USER IS AUTHENTICATED ***********/

		/* now check for POST data.  if \exists, update user's stuff;
		 * otherwise, just serve the page where the user can edit
		 * his/her text.  NOTE: simultaneous access to this thing will
		 * not work very well. */
		string rqMethod = getenv("REQUEST_METHOD");
		if (rqMethod == "POST") {
			string newText = getenv("REQUEST_BODY");
			data[username] = newText;
			printf("Content-type: text/html\r\n"
					"\r\n"
					"<!DOCTYPE html>\n"
					"<html xmlns=\"http://www.w3.org/1999/xhtml\">"
					"<body>Record updated successfully.</body></html>\n");
			continue;
		}

		/* show page to let user edit data.  NOTE: the script provides a
		 * function called postText() to send data back to the server,
		 * and another called clearMessage() to reset the status. */
		printf("Content-type: text/html\r\n"
				"\r\n"
				"<!DOCTYPE html>\n"
				"<html xmlns=\"http://www.w3.org/1999/xhtml\">"
				"<head>\n"
				"<title>SSH for the web: test page</title>\n"
				"<link rel=\"stylesheet\" type=\"text/css\" href=\"/html/default.css\" />\n"
				"<script type=\"text/javascript\" src=\"/js/post-text.js\"></script>"
				"</head><body>\n"
				"<h1>SSH Test</h1>\n"
				"<h3>Welcome, <em>%s</em></h3>\n"
				"<textarea rows=\"5\" cols=\"76\" id=\"usertext\"\n"
				"onchange=\"clearMessage()\">\n"
				"%s" /* user data goes here. */
				"</textarea><br />\n"
				"<input type=\"button\" onclick=\"postText()\"\n"
				"value=\"save\" /> <span id=\"savestatus\"></span><br />\n"
				"</body></html>",username.c_str(),data[username].c_str());

		#if 0
		/* dump the environment to see what's in there: */
		printf("Content-type: text/html\r\n"
				"Set-Cookie: lolcook=this is a fine cookie.\r\n"
				"\r\n"
				"<title>FastCGI Hello! (C, fcgi_stdio library)</title>"
				"<h1>FastCGI Hello! (C, fcgi_stdio library)</h1>"
				"Request number %d running on host <i>%s</i>\n",
				++count, getenv("SERVER_NAME"));
		printf("%s","<br /><br />");
		for (size_t i = 0; i < sizeof(vars)/sizeof(char*); i++) {
			printf("%s: %s<br />\n",vars[i],getenv(vars[i]));
		}
		#endif
		#if 0
		if (ccontent != "") {
			printf("<br /><br /> %s had value '%s'\n", cname.c_str(),ccontent.c_str());
		}
		#endif
	}
	return 0;
}

