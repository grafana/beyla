#ifndef HTTP_DEFS_H
#define HTTP_DEFS_H

#define MAX_CONCURRENT_REQUESTS 10000

// Taken from linux/socket.h
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			    */

#define IP_V6_ADDR_LEN 16

// Most Linux distros use 32768 to 61000 for the ephemeral ports, so we look up from 32768
// IANA suggests that the range should be 49152-65535, which is what Windows uses
#define EPHEMERAL_PORT_MIN 32768

// Taken from errno.h
#define	EINPROGRESS	115	/* Operation now in progress */

#endif