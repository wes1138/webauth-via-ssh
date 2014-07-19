#pragma once

/* authd.c is agnostic of the token format, but for convenience,
 * we set an upper bound on the length: */
#define MAX_TOKEN_LEN 1024

/* The following return codes make sense to authd.c, but in general
 * returning 0 iff success is enough to make things work. */
/* XXX give these better names (avoid naming conflicts)
 * Also, some are used by tokend, and others would be used by some wrapper...
 * tokend would never return unknown_key or ssh_error for example.  You need
 * to make another set for tokend?  Neither set contains the other.  E.g.,
 * tokend might need to tell you the token you gave it has expired, but
 * this is never something authd would say (it was trying to get you a
 * fresh token). */
enum ret_codes {
	success = 0,
	unknown_key,
	misc_badness,
	server_error,
	/* and if we supply a username, too: */
	// wrong_key,
	ssh_error = 255 /* keep this last. */
};

/* tokend interface: input messages are formatted as:
 * action  -- 1 byte  (see enum below for values)
 * len     -- 4 bytes (size of payload)
 * payload -- len bytes, which either contain a token, or a username
 *            for which a token is to be created.
 * */
enum tokend_actions {
	create_token = 0,
	check_token
};
/* tokend output messages are formatted as:
 * result  -- 1 byte  (see ret_codes above for values)
 * len     -- 4 bytes (size of payload)
 * payload -- len bytes, which either contain a token, or a 0/1 byte
 *            indicating validity of a token (1 iff token is valid).
 * */

