/* dns-stuff.c - DNS related code including CERT RR (rfc-4398)
 * Copyright (C) 2006 Free Software Foundation, Inc.
 * Copyright (C) 2006, 2015 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef GNUPG_DIRMNGR_DNS_STUFF_H
#define GNUPG_DIRMNGR_DNS_STUFF_H

#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#else
# include <sys/types.h>
# include <sys/socket.h>
#endif

/*
 * Flags used with resolve_dns_addr.
 */
#define DNS_NUMERICHOST        1  /* Force numeric output format.  */
#define DNS_WITHBRACKET        2  /* Put brackets around numeric v6
                                     addresses.  */

/*
 * Constants for use with get_dns_cert.
 */
#define DNS_CERTTYPE_ANY       0 /* Internal catch all type. */
/* Certificate types according to RFC-4398:  */
#define DNS_CERTTYPE_PKIX      1 /* X.509 as per PKIX. */
#define DNS_CERTTYPE_SPKI      2 /* SPKI certificate.  */
#define DNS_CERTTYPE_PGP       3 /* OpenPGP packet.  */
#define DNS_CERTTYPE_IPKIX     4 /* The URL of an X.509 data object. */
#define DNS_CERTTYPE_ISPKI     5 /* The URL of an SPKI certificate.  */
#define DNS_CERTTYPE_IPGP      6 /* The fingerprint
                                    and URL of an OpenPGP packet.  */
#define DNS_CERTTYPE_ACPKIX    7 /* Attribute Certificate.  */
#define DNS_CERTTYPE_IACPKIX   8 /* The URL of an Attribute Certificate.  */
#define DNS_CERTTYPE_URI     253 /* URI private.  */
#define DNS_CERTTYPE_OID     254 /* OID private.  */
/* Hacks for our implementation.  */
#define DNS_CERTTYPE_RRBASE 1024 /* Base of special constants.  */
#define DNS_CERTTYPE_RR61   (DNS_CERTTYPE_RRBASE + 61)



struct dns_addrinfo_s;
typedef struct dns_addrinfo_s *dns_addrinfo_t;
struct dns_addrinfo_s
{
  dns_addrinfo_t next;
  int family;
  int socktype;
  int protocol;
  int addrlen;
  struct sockaddr addr[1];
};


struct srventry
{
  unsigned short priority;
  unsigned short weight;
  unsigned short port;
  int run_count;
  char target[1025];
};


/* Calling this function switches the DNS code into Tor mode if
   possibe.  Return 0 on success.  */
gpg_error_t enable_dns_tormode (int new_circuit);

/* Change the default IP address of the nameserver to IPADDR.  The
   address needs to be a numerical IP address and will be used for the
   next DNS query.  Note that this is only used in Tor mode.  */
void set_dns_nameserver (const char *ipaddr);


void free_dns_addrinfo (dns_addrinfo_t ai);

/* Function similar to getaddrinfo.  */
gpg_error_t resolve_dns_name (const char *name, unsigned short port,
                              int want_family, int want_socktype,
                              dns_addrinfo_t *r_dai, char **r_canonname);

/* Function similar to getnameinfo.  */
gpg_error_t resolve_dns_addr (const struct sockaddr *addr, int addrlen,
                              unsigned int flags, char **r_name);

/* Return true if NAME is a numerical IP address.  */
int is_ip_address (const char *name);

/* Return true if NAME is an onion address.  */
int is_onion_address (const char *name);

/* Get the canonical name for NAME.  */
gpg_error_t get_dns_cname (const char *name, char **r_cname);

/* Return a CERT record or an arbitray RR.  */
gpg_error_t get_dns_cert (const char *name, int want_certtype,
                          void **r_key, size_t *r_keylen,
                          unsigned char **r_fpr, size_t *r_fprlen,
                          char **r_url);


int getsrv (const char *name,struct srventry **list);


#endif /*GNUPG_DIRMNGR_DNS_STUFF_H*/
