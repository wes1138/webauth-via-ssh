/* Generate and validate authentication tokens.
 *
 * By virtue of being able to speak to this program (via local socket),
 * the user has been authenticated.  (This program will generate a token for
 * any user passed to it.)  The ssh authorized_keys script is responsible
 * for ensuring the legitimacy of tokens.
 * */

#include <stdio.h>
#include <getopt.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>

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
#define KEY_LEN     32

#define err(msg) \
	do { perror(msg); exit(1); } while(0)

static int stale = 0;

static unsigned int keyIndex = 0;
static const int inputLen = UNAME_LEN + TIME_LEN + sizeof(keyIndex);
static const int tokenLen = UNAME_LEN + TIME_LEN + sizeof(keyIndex) + HMAC_LEN;

static void setStale(int signo, siginfo_t *info, void *context)
{
	stale = 1;
}

static int setupTimer(timer_t* timerid,
		void (*action)(int,siginfo_t*,void*), int seconds)
{
	struct sigevent sev;
	struct sigaction sa;
	sa.sa_flags = 0;
	sa.sa_sigaction = action;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGRTMIN, &sa, NULL) == -1)
		return -1;
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN;
	sev.sigev_value.sival_ptr = timerid;
	if (timer_create(CLOCK_MONOTONIC, &sev, timerid) == -1)
		return -1;
	struct itimerspec its;
	its.it_value.tv_sec = seconds;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = seconds;
	its.it_interval.tv_nsec = 0;
	if (timer_settime(*timerid,0,&its,0) == -1)
		return -1;
	return 0;
}

int xread(int fd, void *buf, size_t nBytes)
{
	do {
		ssize_t n = read(fd, buf, nBytes);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && errno == EWOULDBLOCK) continue;
		if (n < 0) return -1;
		buf = (char *)buf + n;
		nBytes -= n;
	} while (nBytes);
	return 0;
}
int xwrite(int fd, const void *buf, size_t nBytes)
{
	do {
		ssize_t n = write(fd, buf, nBytes);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && errno == EWOULDBLOCK) continue;
		if (n < 0) return -1;
		buf = (const char *)buf + n;
		nBytes -= n;
	} while (nBytes);
	return 0;
}

void closesock(int sockfd)
{
	shutdown(sockfd,SHUT_RDWR);
	close(sockfd);
}

int sendMessage(int fd, unsigned char rcode, uint32_t len, void* buf)
{
	if (xwrite(fd,&rcode,1)) goto X_X;
	if (xwrite(fd,&len,4)) goto X_X;
	if (xwrite(fd,buf,len)) goto X_X;
	return 0;
X_X:
	closesock(fd);
	return -1;
}
int recvMessage(int fd, unsigned char* action, uint32_t* len, void* buf, size_t maxLen)
{
	if (xread(fd,action,1) < 0 || xread(fd,len,4) < 0) goto X_X;
	if (*len > maxLen || xread(fd,buf,*len) < 0) goto X_X;
	return 0;
X_X:
	closesock(fd);
	return -1;
}

/* TODO: I think the simplest thing will turn out to be threads after all.
 * The main thread will be responsible for key rotation, and will load
 * the worker thread with its own static copy of the key and the fd for the
 * newly opened client connection.  Then you can be more relaxed / friendly
 * with the network communication (if a client takes a little time, you don't
 * have to cut them off).  This approach retains the property that we don't
 * need synchronization or locks. */

int main(int argc, char *argv[]) {
	static struct option long_opts[] = {
		{"socket",   required_argument, 0, 's'},
		{"keyfile",  required_argument, 0, 'k'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	char keyfile[FNAME_LEN];
	char sockfile[FNAME_LEN];
	char username[UNAME_LEN];
	memset(keyfile,0,FNAME_LEN);
	memset(sockfile,0,FNAME_LEN);
	strncpy(keyfile,"/dev/urandom",FNAME_LEN-1);
	strncpy(sockfile,"/tmp/.tokend-sock",FNAME_LEN-1);
	/* XXX use $XDG_RUNTIME_DIR if it is available? */
	/* XXX handle signals for cleaning up (e.g. unlink sockfile). */
	char c;
	int opt_index = 0;
	while ((c = getopt_long(argc, argv, "s:k:h", long_opts,
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
			case 'h':
			case '?':
				printf("Usage: %s [OPTIONS]...\n"
					"Generate authentication tokens.\n\n"
					"   -u,--socket  SOCK    Location of socket.\n"
					"   -k,--key     FILE    Use FILE for key (rather than /dev/random).\n"
					"   --help               show this message and exit.\n",
						argv[0]);
				return (c == 'h') ? 0 : misc_badness;
		}
	}

	/* set up timer for rotating the key */
	timer_t timerid;
	if (setupTimer(&timerid,setStale,5))
		err("timer setup");
	#if 0
	int count = 0;
	while (count < 5) {
		if (!stale)
			fprintf(stderr, "main loop...\n");
		else {
			stale = 0;
			fprintf(stderr, "refreshing key.\n");
			++count;
		}
		sleep(1);
	}
	return 0;
	#endif

	/* NOTE: the usual daemon pattern calls for forking or threading,
	 * but since the processing here is so light (compute hmac, write
	 * a little data to a socket), my guess is that the overhead
	 * isn't warranted.  */
	/* NOTE: to avoid locking issues, we can always update keys in
	 * the main thread, and use the other thread just as a timer
	 * which sets a "stale" flag.  If the flag is set, you change
	 * the key before servicing the next request (or after, I guess).
	 * Before might be more secure, but makes that user wait a little
	 * longer.  To keep track of which key was used for a token, the
	 * timestamp seems promising, but I think we should instead just
	 * append an id on the end of each token and to each key.  The
	 * issue is that the situation of a token issued at the same time
	 * as the creation of the key could be ambiguous, esp. as time is
	 * measured in seconds, the way we've done it.
	 * */

	/* setup socket */
	struct sockaddr_un addr;
	struct sockaddr_un caddr;
	int listenfd, rwfd; /* listening file, read/write file */
	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listenfd == -1)
		err("socket creation");
	memset(&addr,0,sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path,sockfile,sizeof(addr.sun_path) - 1);
	if (bind(listenfd, (struct sockaddr*) &addr,
				sizeof(struct sockaddr_un)) == -1)
		err("binding socket");
	if (listen(listenfd,50) == -1)
		err("listening");
	socklen_t caddr_size = sizeof(struct sockaddr_un);

	/* set up the first key */
	unsigned char key[KEY_LEN];
	FILE* f = fopen(keyfile,"rb");
	if (!f) {
		fprintf(stderr, "key file (%s) not found.\n",keyfile);
		return server_error;
	}
	size_t bread = fread(key,1,KEY_LEN,f);
	if (bread != KEY_LEN) {
		fprintf(stderr, "Could not read sufficient bytes from %s\n", keyfile);
		return server_error;
	}
	fclose(f);

	while (1) {
		/* listen for requests, respond inline. */
		/* NOTE: in general, you need to handle errors more gracefully
		 * here, without exiting.  The only thing that should be able to
		 * kill the daemon once running is a SIGKILL.
		 * NOTE: you also have to make sure that your read doesn't hang;
		 * if it does, you should report failure and move on.  However,
		 * it should be only trusted programs that are even allowed to
		 * communicate with this module.  Still, if one of them goes nuts,
		 * you don't want other things to break.  Forget about this for now;
		 * if it ever becomes an issue, just use fork() in here.  No races
		 * to worry about that way.
		 * */
		rwfd = accept(listenfd, (struct sockaddr*) &caddr, &caddr_size);
		if (rwfd == -1) {
			fprintf(stderr, "Error during accept; trying again.\n");
			continue;
		}
		/* read client's request: */
		unsigned char req,result;
		uint32_t req_len;
		unsigned char req_buf[tokenLen]; /* token len also upper bounds username len */
		unsigned int macsize,i;
		memset(req_buf,0,tokenLen);
		if (recvMessage(rwfd,&req,&req_len,req_buf,tokenLen) < 0)
			continue;
		if (req == create_token) {
			if (req_len > UNAME_LEN) {
				closesock(rwfd);
				continue;
			}
			/* construct token as:
			 * input := username|expiration|keyindex
			 * token := input|hmac(input,key[keyindex]) */
			time_t exptime = time(0) + 1800; /* half an hour from now */
			// unsigned char token[tokenLen];
			unsigned char* token = req_buf;
			memcpy(token+UNAME_LEN,&exptime,sizeof(time_t));
			memcpy(token+UNAME_LEN+TIME_LEN,&keyIndex,sizeof(keyIndex));
			HMAC(EVP_sha1(),key,KEY_LEN,token,inputLen,token+inputLen,&macsize);
			/* XXX do the key rotation thing. */
			if (macsize != HMAC_LEN) {
				fprintf(stderr, "warning: HMAC wrote %i != %i bytes\n",
						macsize,HMAC_LEN);
			}
			sendMessage(rwfd,success,tokenLen,token);
		} else if (req == check_token) {
			/* mac prefix and compare with suffix. */
			/* XXX: check the expiration date */
			unsigned char mac[HMAC_LEN];
			unsigned char* tmac = req_buf + inputLen;
			HMAC(EVP_sha1(),key,KEY_LEN,req_buf,inputLen,mac,&macsize);
			/* XXX do the key rotation thing. */
			for (i=0; i<HMAC_LEN; i++) {
				if (mac[i] != tmac[i]) break;
			}
			result = (i == HMAC_LEN); /* 1 iff success */
			sendMessage(rwfd,success,1,&result);
		} else {
			result = 0;
			sendMessage(rwfd,misc_badness,1,&result);
			/* NOTE: result has no meaning here.  It is just
			 * sent to keep the communication pattern uniform. */
		}
		closesock(rwfd);
	}

	return success;
}
