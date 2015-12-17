/* dns-stuff.c - DNS related code including CERT RR (rfc-4398)
 * Copyright (C) 2003, 2005, 2006, 2009 Free Software Foundation, Inc.
 * Copyright (C) 2005, 2006, 2009, 2015 Werner Koch
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

#include <config.h>
#include <sys/types.h>
#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#else
# include <netinet/in.h>
# include <arpa/nameser.h>
# include <resolv.h>
# include <netdb.h>
#endif
#include <string.h>
#include <unistd.h>
#ifdef USE_ADNS
# include <adns.h>
#endif

#if !defined(HAVE_GETADDRINFO) && !defined(USE_ADNS)
# error Either getaddrinfo or the ADNS library is required.
#endif

#ifdef WITHOUT_NPTH /* Give the Makefile a chance to build without Pth.  */
# undef USE_NPTH
#endif
#ifdef USE_NPTH
# include <npth.h>
#endif

#include "util.h"
#include "host2net.h"
#include "dns-stuff.h"

#ifdef USE_NPTH
# define my_unprotect()        npth_unprotect ()
# define my_protect()          npth_protect ()
#else
# define my_unprotect()        do { } while(0)
# define my_protect()          do { } while(0)
#endif

/* We allow the use of 0 instead of AF_UNSPEC - check this assumption.  */
#if AF_UNSPEC != 0
# error AF_UNSPEC does not have the value 0
#endif

/* Windows does not support the AI_ADDRCONFIG flag - use zero instead.  */
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

/* Provide a replacement function for older ADNS versions.  */
#ifndef HAVE_ADNS_FREE
# define adns_free(a) free ((a))
#endif

/* Not every installation has gotten around to supporting SRVs or
   CERTs yet... */
#ifndef T_SRV
#define T_SRV 33
#endif
#ifndef T_CERT
# define T_CERT 37
#endif

/* ADNS has no support for CERT yet. */
#define my_adns_r_cert 37


/* The default nameserver used with ADNS in Tor mode.  */
#define DEFAULT_NAMESERVER "8.8.8.8"


/* If set Tor mode shall be used.  */
static int tor_mode;

/* A string with the nameserver IP address used with Tor.
  (40 should be sufficient for v6 but we add some extra for a scope.) */
static char tor_nameserver[40+20];

/* A string to hold the credentials presented to Tor.  */
#ifdef USE_ADNS
static char tor_credentials[50];
#endif

/* Sets the module in Tor mode.  Returns 0 is this is possible or an
   error code.  */
gpg_error_t
enable_dns_tormode (int new_circuit)
{
  (void) new_circuit;

#if defined(USE_DNS_CERT) && defined(USE_ADNS)
# if HAVE_ADNS_IF_TORMODE
   if (!*tor_credentials || new_circuit)
     {
       static unsigned int counter;

       gpgrt_snprintf (tor_credentials, sizeof tor_credentials,
                       "dirmngr-%lu:p%u",
                       (unsigned long)getpid (), counter);
       counter++;
     }
   tor_mode = 1;
   return 0;
# endif
#endif

  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


/* Change the default IP address of the nameserver to IPADDR.  The
   address needs to be a numerical IP address and will be used for the
   next DNS query.  Note that this is only used in Tor mode.  */
void
set_dns_nameserver (const char *ipaddr)
{
  strncpy (tor_nameserver, ipaddr? ipaddr : DEFAULT_NAMESERVER,
           sizeof tor_nameserver -1);
  tor_nameserver[sizeof tor_nameserver -1] = 0;
}


/* Free an addressinfo linked list as returned by resolve_dns_name.  */
void
free_dns_addrinfo (dns_addrinfo_t ai)
{
  while (ai)
    {
      dns_addrinfo_t next = ai->next;
      xfree (ai);
      ai = next;
    }
}


static gpg_error_t
map_eai_to_gpg_error (int ec)
{
  gpg_error_t err;

  switch (ec)
    {
    case EAI_AGAIN:     err = gpg_error (GPG_ERR_EAGAIN); break;
    case EAI_BADFLAGS:  err = gpg_error (GPG_ERR_INV_FLAG); break;
    case EAI_FAIL:      err = gpg_error (GPG_ERR_SERVER_FAILED); break;
    case EAI_MEMORY:    err = gpg_error (GPG_ERR_ENOMEM); break;
    case EAI_NODATA:    err = gpg_error (GPG_ERR_NO_DATA); break;
    case EAI_NONAME:    err = gpg_error (GPG_ERR_NO_NAME); break;
    case EAI_SERVICE:   err = gpg_error (GPG_ERR_NOT_SUPPORTED); break;
    case EAI_FAMILY:    err = gpg_error (GPG_ERR_EAFNOSUPPORT); break;
    case EAI_SOCKTYPE:  err = gpg_error (GPG_ERR_ESOCKTNOSUPPORT); break;
#ifndef HAVE_W32_SYSTEM
    case EAI_ADDRFAMILY:err = gpg_error (GPG_ERR_EADDRNOTAVAIL); break;
    case EAI_SYSTEM:    err = gpg_error_from_syserror (); break;
#endif
    default:            err = gpg_error (GPG_ERR_UNKNOWN_ERRNO); break;
    }
  return err;
}


#ifdef USE_ADNS
/* Init ADNS and store the new state at R_STATE.  Returns 0 on
   success; prints an error message and returns an error code on
   failure.  */
static gpg_error_t
my_adns_init (adns_state *r_state)
{
  gpg_error_t err = 0;
  int ret;

  if (tor_mode)
    {
      char *cfgstr;

      if (!*tor_nameserver)
        set_dns_nameserver (NULL);

      cfgstr = xtryasprintf ("nameserver %s\n"
                             "options adns_tormode adns_sockscred:%s",
                             tor_nameserver, tor_credentials);
      if (!cfgstr)
        err = gpg_error_from_syserror ();
      else
        {
          ret = adns_init_strcfg (r_state, adns_if_debug /*adns_if_noerrprint*/, NULL, cfgstr);
          if (ret)
            err = gpg_error_from_errno (ret);
          xfree (cfgstr);
        }
    }
  else
    {
      ret = adns_init (r_state, adns_if_noerrprint, NULL);
      if (ret)
        err = gpg_error_from_errno (ret);
    }

  if (err)
    {
      log_error ("error initializing adns: %s\n", gpg_strerror (err));
      return err;
    }
  return 0;
}
#endif /*USE_ADNS*/


#ifdef USE_ADNS
/* Resolve a name using the ADNS library.  See resolve_dns_name for
   the description.  */
static gpg_error_t
resolve_name_adns (const char *name, unsigned short port,
                   int want_family, int want_socktype,
                   dns_addrinfo_t *r_dai, char **r_canonname)
{
  gpg_error_t err = 0;
  int ret;
  dns_addrinfo_t daihead = NULL;
  dns_addrinfo_t dai;
  adns_state state;
  adns_answer *answer = NULL;
  int count;

  (void)want_family;

  *r_dai = NULL;
  if (r_canonname)
    *r_canonname = NULL;

  if (want_socktype != SOCK_STREAM && want_socktype != SOCK_DGRAM)
    return gpg_error (GPG_ERR_ESOCKTNOSUPPORT);

  err = my_adns_init (&state);
  if (err)
    return err;

  my_unprotect ();
  ret = adns_synchronous (state, name, adns_r_addr,
                          adns_qf_quoteok_query, &answer);
  my_protect ();
  if (ret)
    {
      err = gpg_error_from_syserror ();
      log_error ("DNS query failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  err = gpg_error (GPG_ERR_NOT_FOUND);
  if (answer->status != adns_s_ok || answer->type != adns_r_addr)
    {
      log_error ("DNS query returned an error: %s (%s)\n",
                 adns_strerror (answer->status),
                 adns_errabbrev (answer->status));
      goto leave;
    }

  if (r_canonname && answer->cname)
    {
      *r_canonname = xtrystrdup (answer->cname);
      if (!*r_canonname)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  for (count = 0; count < answer->nrrs; count++)
    {
      int len;
      adns_rr_addr *addr;

      len  = answer->rrs.addr[count].len;
      addr = &answer->rrs.addr[count];
      if (addr->addr.sa.sa_family != AF_INET6
          && addr->addr.sa.sa_family != AF_INET)
        continue;

      dai = xtrymalloc (sizeof *dai + len - 1);
      if (!dai)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      dai->family = addr->addr.sa.sa_family;
      dai->socktype = want_socktype == SOCK_STREAM? SOCK_STREAM : SOCK_DGRAM;
      dai->protocol = want_socktype == SOCK_STREAM? IPPROTO_TCP : IPPROTO_UDP;
      dai->addrlen = len;
      memcpy (dai->addr, &addr->addr.sa, len);
      ((struct sockaddr_in *) dai->addr)->sin_port = htons (port);
      dai->next = daihead;
      daihead = dai;
      err = 0;
    }

 leave:
  adns_free (answer);
  adns_finish (state);
  if (err)
    {
      if (r_canonname)
        {
          xfree (*r_canonname);
          *r_canonname = NULL;
        }
      free_dns_addrinfo (daihead);
    }
  else
    *r_dai = daihead;
  return err;
}
#endif /*USE_ADNS*/


#ifndef USE_ADNS
/* Resolve a name using the standard system function.  */
static gpg_error_t
resolve_name_standard (const char *name, unsigned short port,
                       int want_family, int want_socktype,
                       dns_addrinfo_t *r_dai, char **r_canonname)
{
  gpg_error_t err = 0;
  dns_addrinfo_t daihead = NULL;
  dns_addrinfo_t dai;
  struct addrinfo *aibuf = NULL;
  struct addrinfo hints, *ai;
  char portstr[21];
  int ret;

  *r_dai = NULL;
  if (r_canonname)
    *r_canonname = NULL;

  memset (&hints, 0, sizeof hints);
  hints.ai_family = want_family;
  hints.ai_socktype = want_socktype;
  hints.ai_flags = AI_ADDRCONFIG;
  if (r_canonname)
    hints.ai_flags |= AI_CANONNAME;

  if (port)
    snprintf (portstr, sizeof portstr, "%hu", port);
  else
    *portstr = 0;

  /* We can't use the the AI_IDN flag because that does the conversion
     using the current locale.  However, GnuPG always used UTF-8.  To
     support IDN we would need to make use of the libidn API.  */
  ret = getaddrinfo (name, *portstr? portstr : NULL, &hints, &aibuf);
  if (ret)
    {
      aibuf = NULL;
      err = map_eai_to_gpg_error (ret);
      if (gpg_err_code (err) == GPG_ERR_NO_NAME)
        {
          /* There seems to be a bug in the glibc getaddrinfo function
             if the CNAME points to a long list of A and AAAA records
             in which case the function return NO_NAME.  Let's do the
             CNAME redirection again.  */
          char *cname;

          if (get_dns_cname (name, &cname))
            goto leave; /* Still no success.  */

          ret = getaddrinfo (cname, *portstr? portstr : NULL, &hints, &aibuf);
          xfree (cname);
          if (ret)
            {
              aibuf = NULL;
              err = map_eai_to_gpg_error (ret);
              goto leave;
            }
          err = 0; /* Yep, now it worked.  */
        }
      else
        goto leave;
    }

  if (r_canonname && aibuf && aibuf->ai_canonname)
    {
      *r_canonname = xtrystrdup (aibuf->ai_canonname);
      if (!*r_canonname)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  for (ai = aibuf; ai; ai = ai->ai_next)
    {
      if (ai->ai_family != AF_INET6 && ai->ai_family != AF_INET)
        continue;

      dai = xtrymalloc (sizeof *dai + ai->ai_addrlen - 1);
      dai->family = ai->ai_family;
      dai->socktype = ai->ai_socktype;
      dai->protocol = ai->ai_protocol;
      dai->addrlen = ai->ai_addrlen;
      memcpy (dai->addr, ai->ai_addr, ai->ai_addrlen);
      dai->next = daihead;
      daihead = dai;
    }

 leave:
  if (aibuf)
    freeaddrinfo (aibuf);
  if (err)
    {
      if (r_canonname)
        {
          xfree (*r_canonname);
          *r_canonname = NULL;
        }
      free_dns_addrinfo (daihead);
    }
  else
    *r_dai = daihead;
  return err;
}
#endif /*!USE_ADNS*/


/* Resolve an address using the standard system function.  */
static gpg_error_t
resolve_addr_standard (const struct sockaddr *addr, int addrlen,
                       unsigned int flags, char **r_name)
{
  gpg_error_t err;
  int ec;
  char *buffer, *p;
  int buflen;

  *r_name = NULL;

  buflen = NI_MAXHOST;
  buffer = xtrymalloc (buflen + 2 + 1);
  if (!buffer)
    return gpg_error_from_syserror ();

  if ((flags & DNS_NUMERICHOST) || tor_mode)
    ec = EAI_NONAME;
  else
    ec = getnameinfo (addr, addrlen, buffer, buflen, NULL, 0, NI_NAMEREQD);

  if (!ec && *buffer == '[')
    ec = EAI_FAIL;  /* A name may never start with a bracket.  */
  else if (ec == EAI_NONAME)
    {
      p = buffer;
      if (addr->sa_family == AF_INET6 && (flags & DNS_WITHBRACKET))
        {
          *p++ = '[';
          buflen -= 2;
        }
      ec = getnameinfo (addr, addrlen, p, buflen, NULL, 0, NI_NUMERICHOST);
      if (!ec && addr->sa_family == AF_INET6 && (flags & DNS_WITHBRACKET))
        strcat (buffer, "]");
    }

  if (ec)
    err = map_eai_to_gpg_error (ec);
  else
    {
      p = xtryrealloc (buffer, strlen (buffer)+1);
      if (!p)
        err = gpg_error_from_syserror ();
      else
        {
          buffer = p;
          err = 0;
        }
    }

  if (err)
    xfree (buffer);
  else
    *r_name = buffer;

  return err;
}


/* This a wrapper around getaddrinfo with slightly different semantics.
   NAME is the name to resolve.
   PORT is the requested port or 0.
   WANT_FAMILY is either 0 (AF_UNSPEC), AF_INET6, or AF_INET4.
   WANT_SOCKETTYPE is either SOCK_STREAM or SOCK_DGRAM.

   On success the result is stored in a linked list with the head
   stored at the address R_AI; the caller must call gpg_addrinfo_free
   on this.  If R_CANONNAME is not NULL the official name of the host
   is stored there as a malloced string; if that name is not available
   NULL is stored.  */
gpg_error_t
resolve_dns_name (const char *name, unsigned short port,
                  int want_family, int want_socktype,
                  dns_addrinfo_t *r_ai, char **r_canonname)
{
#ifdef USE_ADNS
  return resolve_name_adns (name, port, want_family, want_socktype,
                            r_ai, r_canonname);
#else
  return resolve_name_standard (name, port, want_family, want_socktype,
                                r_ai, r_canonname);
#endif
}


gpg_error_t
resolve_dns_addr (const struct sockaddr *addr, int addrlen,
                  unsigned int flags, char **r_name)
{
#ifdef USE_ADNS_disabled_for_now
  return resolve_addr_adns (addr, addrlen, flags, r_name);
#else
  return resolve_addr_standard (addr, addrlen, flags, r_name);
#endif
}


/* Check whether NAME is an IP address.  Returns true if it is either
   an IPv6 or IPv4 numerical address.  */
int
is_ip_address (const char *name)
{
  const char *s;
  int ndots, dblcol, n;

  if (*name == '[')
    return 1; /* yes: A legal DNS name may not contain this character;
                 this mut be bracketed v6 address.  */
  if (*name == '.')
    return 0; /* No.  A leading dot is not a valid IP address.  */

  /* Check whether this is a v6 address.  */
  ndots = n = dblcol = 0;
  for (s=name; *s; s++)
    {
      if (*s == ':')
        {
          ndots++;
          if (s[1] == ':')
            {
              ndots++;
              if (dblcol)
                return 0; /* No: Only one "::" allowed.  */
              dblcol++;
              if (s[1])
                s++;
            }
          n = 0;
        }
      else if (*s == '.')
        goto legacy;
      else if (!strchr ("0123456789abcdefABCDEF", *s))
        return 0; /* No: Not a hex digit.  */
      else if (++n > 4)
        return 0; /* To many digits in a group.  */
    }
  if (ndots > 7)
    return 0; /* No: Too many colons.  */
  else if (ndots > 1)
    return 1; /* Yes: At least 2 colons indicate an v6 address.  */

 legacy:
  /* Check whether it is legacy IP address.  */
  ndots = n = 0;
  for (s=name; *s; s++)
    {
      if (*s == '.')
        {
          if (s[1] == '.')
            return 0; /* No:  Douple dot. */
          if (atoi (s+1) > 255)
            return 0; /* No:  Ipv4 byte value too large.  */
          ndots++;
          n = 0;
        }
      else if (!strchr ("0123456789", *s))
        return 0; /* No: Not a digit.  */
      else if (++n > 3)
        return 0; /* No: More than 3 digits.  */
    }
  return !!(ndots == 3);
}


/* Return true if NAME is an onion address.  */
int
is_onion_address (const char *name)
{
  size_t len;

  len = name? strlen (name) : 0;
  if (len < 8 || strcmp (name + len - 6, ".onion"))
    return 0;
  /* Note that we require at least 2 characters before the suffix.  */
  return 1;  /* Yes.  */
}


/* Returns 0 on success or an error code.  If a PGP CERT record was
   found, the malloced data is returned at (R_KEY, R_KEYLEN) and
   the other return parameters are set to NULL/0.  If an IPGP CERT
   record was found the fingerprint is stored as an allocated block at
   R_FPR and its length at R_FPRLEN; an URL is is allocated as a
   string and returned at R_URL.  If WANT_CERTTYPE is 0 this function
   returns the first CERT found with a supported type; it is expected
   that only one CERT record is used.  If WANT_CERTTYPE is one of the
   supported certtypes only records with this certtype are considered
   and the first found is returned.  (R_KEY,R_KEYLEN) are optional. */
gpg_error_t
get_dns_cert (const char *name, int want_certtype,
              void **r_key, size_t *r_keylen,
              unsigned char **r_fpr, size_t *r_fprlen, char **r_url)
{
#ifdef USE_DNS_CERT
#ifdef USE_ADNS
  gpg_error_t err;
  int ret;
  adns_state state;
  adns_answer *answer = NULL;
  unsigned int ctype;
  int count;

  if (r_key)
    *r_key = NULL;
  if (r_keylen)
    *r_keylen = 0;
  *r_fpr = NULL;
  *r_fprlen = 0;
  *r_url = NULL;

  err = my_adns_init (&state);
  if (err)
    return err;

  my_unprotect ();
  ret = adns_synchronous (state, name,
                          (adns_r_unknown
                           | (want_certtype < DNS_CERTTYPE_RRBASE
                              ? my_adns_r_cert
                              : (want_certtype - DNS_CERTTYPE_RRBASE))),
                          adns_qf_quoteok_query, &answer);
  my_protect ();
  if (ret)
    {
      err = gpg_error_from_syserror ();
      /* log_error ("DNS query failed: %s\n", strerror (errno)); */
      adns_finish (state);
      return err;
    }
  if (answer->status != adns_s_ok)
    {
      /* log_error ("DNS query returned an error: %s (%s)\n", */
      /*            adns_strerror (answer->status), */
      /*            adns_errabbrev (answer->status)); */
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  err = gpg_error (GPG_ERR_NOT_FOUND);
  for (count = 0; count < answer->nrrs; count++)
    {
      int datalen = answer->rrs.byteblock[count].len;
      const unsigned char *data = answer->rrs.byteblock[count].data;

      /* First check for our generic RR hack.  */
      if (datalen
          && want_certtype >= DNS_CERTTYPE_RRBASE
          && ((want_certtype - DNS_CERTTYPE_RRBASE)
              == (answer->type & ~adns_r_unknown)))
        {
          /* Found the requested record - return it.  */
          *r_key = xtrymalloc (datalen);
          if (!*r_key)
            err = gpg_error_from_syserror ();
          else
            {
              memcpy (*r_key, data, datalen);
              *r_keylen = datalen;
              err = 0;
            }
          goto leave;
        }

      if (datalen < 5)
        continue;  /* Truncated CERT record - skip.  */

      ctype = buf16_to_uint (data);
      /* (key tag and algorithm fields are not required.) */
      data += 5;
      datalen -= 5;

      if (want_certtype && want_certtype != ctype)
        ; /* Not of the requested certtype.  */
      else if (ctype == DNS_CERTTYPE_PGP && datalen >= 11 && r_key && r_keylen)
        {
          /* CERT type is PGP.  Gpg checks for a minimum length of 11,
             thus we do the same.  */
          *r_key = xtrymalloc (datalen);
          if (!*r_key)
            err = gpg_error_from_syserror ();
          else
            {
              memcpy (*r_key, data, datalen);
              *r_keylen = datalen;
              err = 0;
            }
          goto leave;
        }
      else if (ctype == DNS_CERTTYPE_IPGP && datalen && datalen < 1023
               && datalen >= data[0] + 1 && r_fpr && r_fprlen && r_url)
        {
          /* CERT type is IPGP.  We made sure that the data is
             plausible and that the caller requested this
             information.  */
          *r_fprlen = data[0];
          if (*r_fprlen)
            {
              *r_fpr = xtrymalloc (*r_fprlen);
              if (!*r_fpr)
                {
                  err = gpg_error_from_syserror ();
                  goto leave;
                }
              memcpy (*r_fpr, data + 1, *r_fprlen);
            }
          else
            *r_fpr = NULL;

          if (datalen > *r_fprlen + 1)
            {
              *r_url = xtrymalloc (datalen - (*r_fprlen + 1) + 1);
              if (!*r_url)
                {
                  err = gpg_error_from_syserror ();
                  xfree (*r_fpr);
                  *r_fpr = NULL;
                  goto leave;
                }
              memcpy (*r_url,
                      data + (*r_fprlen + 1), datalen - (*r_fprlen + 1));
              (*r_url)[datalen - (*r_fprlen + 1)] = '\0';
            }
          else
            *r_url = NULL;

          err = 0;
          goto leave;
        }
    }

 leave:
  adns_free (answer);
  adns_finish (state);
  return err;

#else /*!USE_ADNS*/

  gpg_error_t err;
  unsigned char *answer;
  int r;
  u16 count;

  if (r_key)
    *r_key = NULL;
  if (r_keylen)
    *r_keylen = 0;
  *r_fpr = NULL;
  *r_fprlen = 0;
  *r_url = NULL;

  /* Allocate a 64k buffer which is the limit for an DNS response.  */
  answer = xtrymalloc (65536);
  if (!answer)
    return gpg_error_from_syserror ();

  err = gpg_error (GPG_ERR_NOT_FOUND);
  r = res_query (name, C_IN,
                 (want_certtype < DNS_CERTTYPE_RRBASE
                  ? T_CERT
                  : (want_certtype - DNS_CERTTYPE_RRBASE)),
                 answer, 65536);
  /* Not too big, not too small, no errors and at least 1 answer. */
  if (r >= sizeof (HEADER) && r <= 65536
      && (((HEADER *) answer)->rcode) == NOERROR
      && (count = ntohs (((HEADER *) answer)->ancount)))
    {
      int rc;
      unsigned char *pt, *emsg;

      emsg = &answer[r];

      pt = &answer[sizeof (HEADER)];

      /* Skip over the query */

      rc = dn_skipname (pt, emsg);
      if (rc == -1)
        {
          err = gpg_error (GPG_ERR_INV_OBJ);
          goto leave;
        }
      pt += rc + QFIXEDSZ;

      /* There are several possible response types for a CERT request.
         We're interested in the PGP (a key) and IPGP (a URI) types.
         Skip all others.  TODO: A key is better than a URI since
         we've gone through all this bother to fetch it, so favor that
         if we have both PGP and IPGP? */

      while (count-- > 0 && pt < emsg)
        {
          u16 type, class, dlen, ctype;

          rc = dn_skipname (pt, emsg);  /* the name we just queried for */
          if (rc == -1)
            {
              err = gpg_error (GPG_ERR_INV_OBJ);
              goto leave;
            }

          pt += rc;

          /* Truncated message? 15 bytes takes us to the point where
             we start looking at the ctype. */
          if ((emsg - pt) < 15)
            break;

          type = buf16_to_u16 (pt);
          pt += 2;

          class = buf16_to_u16 (pt);
          pt += 2;

          if (class != C_IN)
            break;

          /* ttl */
          pt += 4;

          /* data length */
          dlen = buf16_to_u16 (pt);
          pt += 2;

          /* Check the type and parse.  */
          if (want_certtype >= DNS_CERTTYPE_RRBASE
              && type == (want_certtype - DNS_CERTTYPE_RRBASE)
              && r_key)
            {
              *r_key = xtrymalloc (dlen);
              if (!*r_key)
                err = gpg_error_from_syserror ();
              else
                {
                  memcpy (*r_key, pt, dlen);
                  *r_keylen = dlen;
                  err = 0;
                }
              goto leave;
            }
          else if (want_certtype >= DNS_CERTTYPE_RRBASE)
            {
              /* We did not found the requested RR.  */
              pt += dlen;
            }
          else if (type == T_CERT)
            {
              /* We got a CERT type.   */
              ctype = buf16_to_u16 (pt);
              pt += 2;

              /* Skip the CERT key tag and algo which we don't need. */
              pt += 3;

              dlen -= 5;

              /* 15 bytes takes us to here */
              if (want_certtype && want_certtype != ctype)
                ; /* Not of the requested certtype.  */
              else if (ctype == DNS_CERTTYPE_PGP && dlen && r_key && r_keylen)
                {
                  /* PGP type */
                  *r_key = xtrymalloc (dlen);
                  if (!*r_key)
                    err = gpg_error_from_syserror ();
                  else
                    {
                      memcpy (*r_key, pt, dlen);
                      *r_keylen = dlen;
                      err = 0;
                    }
                  goto leave;
                }
              else if (ctype == DNS_CERTTYPE_IPGP
                       && dlen && dlen < 1023 && dlen >= pt[0] + 1)
                {
                  /* IPGP type */
                  *r_fprlen = pt[0];
                  if (*r_fprlen)
                    {
                      *r_fpr = xtrymalloc (*r_fprlen);
                      if (!*r_fpr)
                        {
                          err = gpg_error_from_syserror ();
                          goto leave;
                        }
                      memcpy (*r_fpr, &pt[1], *r_fprlen);
                    }
                  else
                    *r_fpr = NULL;

                  if (dlen > *r_fprlen + 1)
                    {
                      *r_url = xtrymalloc (dlen - (*r_fprlen + 1) + 1);
                      if (!*r_fpr)
                        {
                          err = gpg_error_from_syserror ();
                          xfree (*r_fpr);
                          *r_fpr = NULL;
                          goto leave;
                        }
                      memcpy (*r_url, &pt[*r_fprlen + 1],
                              dlen - (*r_fprlen + 1));
                      (*r_url)[dlen - (*r_fprlen + 1)] = '\0';
                    }
                  else
                    *r_url = NULL;

                  err = 0;
                  goto leave;
                }

              /* No subtype matches, so continue with the next answer. */
              pt += dlen;
            }
          else
            {
              /* Not a requested type - might be a CNAME. Try next item.  */
              pt += dlen;
            }
        }
    }

 leave:
  xfree (answer);
  return err;

#endif /*!USE_ADNS */
#else /* !USE_DNS_CERT */
  (void)name;
  if (r_key)
    *r_key = NULL;
  if (r_keylen)
    *r_keylen = NULL;
  *r_fpr = NULL;
  *r_fprlen = 0;
  *r_url = NULL;

  return gpg_error (GPG_ERR_NOT_SUPPORTED);
#endif
}

#ifdef USE_DNS_SRV
static int
priosort(const void *a,const void *b)
{
  const struct srventry *sa=a,*sb=b;
  if(sa->priority>sb->priority)
    return 1;
  else if(sa->priority<sb->priority)
    return -1;
  else
    return 0;
}


int
getsrv (const char *name,struct srventry **list)
{
  int srvcount=0;
  u16 count;
  int i, rc;

  *list = NULL;

#ifdef USE_ADNS
  {
    adns_state state;
    adns_answer *answer = NULL;

    if (my_adns_init (&state))
      return -1;

    my_unprotect ();
    rc = adns_synchronous (state, name, adns_r_srv, adns_qf_quoteok_query,
                           &answer);
    my_protect ();
    if (rc)
      {
        log_error ("DNS query failed: %s\n", strerror (errno));
        adns_finish (state);
        return -1;
      }
    if (answer->status != adns_s_ok
        || answer->type != adns_r_srv || !answer->nrrs)
      {
        log_error ("DNS query returned an error or no records: %s (%s)\n",
                   adns_strerror (answer->status),
                   adns_errabbrev (answer->status));
        adns_free (answer);
        adns_finish (state);
        return 0;
      }

    for (count = 0; count < answer->nrrs; count++)
      {
        struct srventry *srv = NULL;
        struct srventry *newlist;

        if (strlen (answer->rrs.srvha[count].ha.host) >= sizeof srv->target)
          {
            log_info ("hostname in SRV record too long - skipped\n");
            continue;
          }

        newlist = xtryrealloc (*list, (srvcount+1)*sizeof(struct srventry));
        if (!newlist)
          goto fail;
        *list = newlist;
        memset (&(*list)[srvcount], 0, sizeof(struct srventry));
        srv = &(*list)[srvcount];
        srvcount++;

        srv->priority = answer->rrs.srvha[count].priority;
        srv->weight   = answer->rrs.srvha[count].weight;
        srv->port     = answer->rrs.srvha[count].port;
        strcpy (srv->target, answer->rrs.srvha[count].ha.host);
      }

    adns_free (answer);
    adns_finish (state);
  }
#else /*!USE_ADNS*/
  {
    unsigned char answer[2048];
    HEADER *header = (HEADER *)answer;
    unsigned char *pt, *emsg;
    int r;
    u16 dlen;

    /* Do not allow a query using the standard resolver in Tor mode.  */
    if (tor_mode)
      return -1;

    r = res_query (name, C_IN, T_SRV, answer, sizeof answer);
    if (r < sizeof (HEADER) || r > sizeof answer
        || header->rcode != NOERROR || !(count=ntohs (header->ancount)))
      return 0; /* Error or no record found.  */

    emsg = &answer[r];
    pt = &answer[sizeof(HEADER)];

    /* Skip over the query */
    rc = dn_skipname (pt, emsg);
    if (rc == -1)
      goto fail;

    pt += rc + QFIXEDSZ;

    while (count-- > 0 && pt < emsg)
      {
        struct srventry *srv=NULL;
        u16 type,class;
        struct srventry *newlist;

        newlist = xtryrealloc (*list, (srvcount+1)*sizeof(struct srventry));
        if (!newlist)
          goto fail;
        *list = newlist;
        memset(&(*list)[srvcount],0,sizeof(struct srventry));
        srv=&(*list)[srvcount];
        srvcount++;

        rc = dn_skipname(pt,emsg); /* the name we just queried for */
        if (rc == -1)
          goto fail;
        pt+=rc;

        /* Truncated message? */
        if((emsg-pt)<16)
          goto fail;

        type = buf16_to_u16 (pt);
        pt += 2;
        /* We asked for SRV and got something else !? */
        if(type!=T_SRV)
          goto fail;

        class = buf16_to_u16 (pt);
        pt += 2;
        /* We asked for IN and got something else !? */
        if(class!=C_IN)
          goto fail;

        pt += 4; /* ttl */
        dlen = buf16_to_u16 (pt);
        pt += 2;

        srv->priority = buf16_to_ushort (pt);
        pt += 2;
        srv->weight = buf16_to_ushort (pt);
        pt += 2;
        srv->port = buf16_to_ushort (pt);
        pt += 2;

        /* Get the name.  2782 doesn't allow name compression, but
           dn_expand still works to pull the name out of the
           packet. */
        rc = dn_expand(answer,emsg,pt,srv->target, sizeof srv->target);
        if (rc == 1 && srv->target[0] == 0) /* "." */
          {
            xfree(*list);
            *list = NULL;
            return 0;
          }
        if (rc == -1)
          goto fail;
        pt += rc;
        /* Corrupt packet? */
        if (dlen != rc+6)
          goto fail;
      }
  }
#endif /*!USE_ADNS*/

  /* Now we have an array of all the srv records. */

  /* Order by priority */
  qsort(*list,srvcount,sizeof(struct srventry),priosort);

  /* For each priority, move the zero-weighted items first. */
  for (i=0; i < srvcount; i++)
    {
      int j;

      for (j=i;j < srvcount && (*list)[i].priority == (*list)[j].priority; j++)
        {
          if((*list)[j].weight==0)
            {
              /* Swap j with i */
              if(j!=i)
                {
                  struct srventry temp;

                  memcpy (&temp,&(*list)[j],sizeof(struct srventry));
                  memcpy (&(*list)[j],&(*list)[i],sizeof(struct srventry));
                  memcpy (&(*list)[i],&temp,sizeof(struct srventry));
                }

              break;
            }
        }
    }

  /* Run the RFC-2782 weighting algorithm.  We don't need very high
     quality randomness for this, so regular libc srand/rand is
     sufficient.  */

  {
    static int done;
    if (!done)
      {
        done = 1;
        srand (time (NULL)*getpid());
      }
  }

  for (i=0; i < srvcount; i++)
    {
      int j;
      float prio_count=0,chose;

      for (j=i; j < srvcount && (*list)[i].priority == (*list)[j].priority; j++)
        {
          prio_count+=(*list)[j].weight;
          (*list)[j].run_count=prio_count;
        }

      chose=prio_count*rand()/RAND_MAX;

      for (j=i;j<srvcount && (*list)[i].priority==(*list)[j].priority;j++)
        {
          if (chose<=(*list)[j].run_count)
            {
              /* Swap j with i */
              if(j!=i)
                {
                  struct srventry temp;

                  memcpy(&temp,&(*list)[j],sizeof(struct srventry));
                  memcpy(&(*list)[j],&(*list)[i],sizeof(struct srventry));
                  memcpy(&(*list)[i],&temp,sizeof(struct srventry));
                }
              break;
            }
        }
    }

  return srvcount;

 fail:
  xfree(*list);
  *list=NULL;
  return -1;
}
#endif /*USE_DNS_SRV*/


gpg_error_t
get_dns_cname (const char *name, char **r_cname)
{
  gpg_error_t err;
  int rc;

  *r_cname = NULL;

#ifdef USE_ADNS
  {
    adns_state state;
    adns_answer *answer = NULL;

    if (my_adns_init (&state))
      return gpg_error (GPG_ERR_GENERAL);

    my_unprotect ();
    rc = adns_synchronous (state, name, adns_r_cname, adns_qf_quoteok_query,
                           &answer);
    my_protect ();
    if (rc)
      {
        err = gpg_error_from_syserror ();
        log_error ("DNS query failed: %s\n", gpg_strerror (err));
        adns_finish (state);
        return err;
      }
    if (answer->status != adns_s_ok
        || answer->type != adns_r_cname || answer->nrrs != 1)
      {
        err = gpg_error (GPG_ERR_GENERAL);
        log_error ("DNS query returned an error or no records: %s (%s)\n",
                   adns_strerror (answer->status),
                   adns_errabbrev (answer->status));
        adns_free (answer);
        adns_finish (state);
        return err;
      }
    *r_cname = xtrystrdup (answer->rrs.str[0]);
    if (!*r_cname)
      err = gpg_error_from_syserror ();
    else
      err = 0;

    adns_free (answer);
    adns_finish (state);
    return err;
  }
#else /*!USE_ADNS*/
  {
    unsigned char answer[2048];
    HEADER *header = (HEADER *)answer;
    unsigned char *pt, *emsg;
    int r;
    char *cname;
    int cnamesize = 1025;
    u16 count;

    /* Do not allow a query using the standard resolver in Tor mode.  */
    if (tor_mode)
      return -1;

    r = res_query (name, C_IN, T_CERT, answer, sizeof answer);
    if (r < sizeof (HEADER) || r > sizeof answer)
      return gpg_error (GPG_ERR_SERVER_FAILED);
    if (header->rcode != NOERROR || !(count=ntohs (header->ancount)))
      return gpg_error (GPG_ERR_NO_NAME); /* Error or no record found.  */
    if (count != 1)
      return gpg_error (GPG_ERR_SERVER_FAILED);

    emsg = &answer[r];
    pt = &answer[sizeof(HEADER)];
    rc = dn_skipname (pt, emsg);
    if (rc == -1)
      return gpg_error (GPG_ERR_SERVER_FAILED);

    pt += rc + QFIXEDSZ;
    if (pt >= emsg)
      return gpg_error (GPG_ERR_SERVER_FAILED);

    rc = dn_skipname (pt, emsg);
    if (rc == -1)
      return gpg_error (GPG_ERR_SERVER_FAILED);
    pt += rc + 2 + 2 + 4;
    if (pt+2 >= emsg)
      return gpg_error (GPG_ERR_SERVER_FAILED);
    pt += 2;  /* Skip rdlen */

    cname = xtrymalloc (cnamesize);
    if (!cname)
      return gpg_error_from_syserror ();

    rc = dn_expand (answer, emsg, pt, cname, cnamesize -1);
    if (rc == -1)
      {
        xfree (cname);
        return gpg_error (GPG_ERR_SERVER_FAILED);
      }
    *r_cname = xtryrealloc (cname, strlen (cname)+1);
    if (!*r_cname)
      {
        err = gpg_error_from_syserror ();
        xfree (cname);
        return err;
      }
    return 0;
  }
#endif /*!USE_ADNS*/
}
