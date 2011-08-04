/* pka.c - DNS Public Key Association RR access
 * Copyright (C) 2005, 2009 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_DNS_PKA
#include <sys/types.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif
#endif /* USE_DNS_PKA */
#ifdef USE_ADNS
# include <adns.h>
# ifndef HAVE_ADNS_FREE
#  define adns_free free
# endif
#endif

#include "util.h"
#include "pka.h"

#ifdef USE_DNS_PKA
/* Parse the TXT resource record. Format is:

   v=pka1;fpr=a4d94e92b0986ab5ee9dcd755de249965b0358a2;uri=string

   For simplicity white spaces are not allowed.  Because we expect to
   use a new RRTYPE for this in the future we define the TXT really
   strict for simplicity: No white spaces, case sensitivity of the
   names, order must be as given above.  Only URI is optional.

   This function modifies BUFFER.  On success 0 is returned, the 20
   byte fingerprint stored at FPR and BUFFER contains the URI or an
   empty string.
*/
static int
parse_txt_record (char *buffer, unsigned char *fpr)
{
  char *p, *pend;
  int i;

  p = buffer;
  pend = strchr (p, ';');
  if (!pend)
    return -1;
  *pend++ = 0;
  if (strcmp (p, "v=pka1"))
    return -1; /* Wrong or missing version. */

  p = pend;
  pend = strchr (p, ';');
  if (pend)
    *pend++ = 0;
  if (strncmp (p, "fpr=", 4))
    return -1; /* Missing fingerprint part. */
  p += 4;
  for (i=0; i < 20 && hexdigitp (p) && hexdigitp (p+1); i++, p += 2)
    fpr[i] = xtoi_2 (p);
  if (i != 20)
    return -1; /* Fingerprint consists not of exactly 40 hexbytes. */

  p = pend;
  if (!p || !*p)
    {
      *buffer = 0;
      return 0; /* Success (no URI given). */
    }
  if (strncmp (p, "uri=", 4))
    return -1; /* Unknown part. */
  p += 4;
  /* There is an URI, copy it to the start of the buffer. */
  while (*p)
    *buffer++ = *p++;
  *buffer = 0;
  return 0;
}


/* For the given email ADDRESS lookup the PKA information in the DNS.

   On success the 20 byte SHA-1 fingerprint is stored at FPR and the
   URI will be returned in an allocated buffer.  Note that the URI
   might be an zero length string as this information is optional.
   Caller must xfree the returned string.

   On error NULL is returned and the 20 bytes at FPR are not
   defined. */
char *
get_pka_info (const char *address, unsigned char *fpr)
{
#ifdef USE_ADNS
  int rc;
  adns_state state;
  const char *domain;
  char *name;
  adns_answer *answer = NULL;
  char *buffer = NULL;

  domain = strrchr (address, '@');
  if (!domain || domain == address || !domain[1])
    return NULL; /* Invalid mail address given.  */
  name = xtrymalloc (strlen (address) + 5 + 1);
  if (!name)
    return NULL;
  memcpy (name, address, domain - address);
  strcpy (stpcpy (name + (domain-address), "._pka."), domain+1);

  rc = adns_init (&state, adns_if_noerrprint, NULL);
  if (rc)
    {
      log_error ("error initializing adns: %s\n", strerror (errno));
      xfree (name);
      return NULL;
    }

  rc = adns_synchronous (state, name, adns_r_txt, adns_qf_quoteok_query,
                         &answer);
  xfree (name);
  if (rc)
    {
      log_error ("DNS query failed: %s\n", strerror (errno));
      adns_finish (state);
      return NULL;
    }
  if (answer->status != adns_s_ok
      || answer->type != adns_r_txt || !answer->nrrs)
    {
      /* log_error ("DNS query returned an error: %s (%s)\n", */
      /*            adns_strerror (answer->status), */
      /*            adns_errabbrev (answer->status)); */
      adns_free (answer);
      adns_finish (state);
      return NULL;
    }

  /* We use a PKA records iff there is exactly one record.  */
  if (answer->nrrs == 1 && answer->rrs.manyistr[0]->i != -1)
    {
      buffer = xtrystrdup (answer->rrs.manyistr[0]->str);
      if (parse_txt_record (buffer, fpr))
        {
          xfree (buffer);
          buffer = NULL;   /* Not a valid gpg trustdns RR. */
        }
    }

  adns_free (answer);
  adns_finish (state);
  return buffer;

#else /*!USE_ADNS*/
  union
    {
      signed char p[PACKETSZ];
      HEADER h;
    } answer;
  int anslen;
  int qdcount, ancount;
  int rc;
  unsigned char *p, *pend;
  const char *domain;
  char *name;


  domain = strrchr (address, '@');
  if (!domain || domain == address || !domain[1])
    return NULL; /* invalid mail address given. */

  name = xtrymalloc (strlen (address) + 5 + 1);
  if (!name)
    return NULL;
  memcpy (name, address, domain - address);
  strcpy (stpcpy (name + (domain-address), "._pka."), domain+1);

  anslen = res_query (name, C_IN, T_TXT, answer.p, PACKETSZ);
  xfree (name);
  if (anslen < sizeof(HEADER))
    return NULL; /* DNS resolver returned a too short answer. */
  if ( (rc=answer.h.rcode) != NOERROR )
    return NULL; /* DNS resolver returned an error. */

  /* We assume that PACKETSZ is large enough and don't do dynmically
     expansion of the buffer. */
  if (anslen > PACKETSZ)
    return NULL; /* DNS resolver returned a too long answer */

  qdcount = ntohs (answer.h.qdcount);
  ancount = ntohs (answer.h.ancount);

  if (!ancount)
    return NULL; /* Got no answer. */

  p = answer.p + sizeof (HEADER);
  pend = answer.p + anslen; /* Actually points directly behind the buffer. */

  while (qdcount-- && p < pend)
    {
      rc = dn_skipname (p, pend);
      if (rc == -1)
        return NULL;
      p += rc + QFIXEDSZ;
    }

  if (ancount > 1)
    return NULL; /* more than one possible gpg trustdns record - none used. */

  while (ancount-- && p <= pend)
    {
      unsigned int type, class, txtlen, n;
      char *buffer, *bufp;

      rc = dn_skipname (p, pend);
      if (rc == -1)
        return NULL;
      p += rc;
      if (p >= pend - 10)
        return NULL; /* RR too short. */

      type = *p++ << 8;
      type |= *p++;
      class = *p++ << 8;
      class |= *p++;
      p += 4;
      txtlen = *p++ << 8;
      txtlen |= *p++;
      if (type != T_TXT || class != C_IN)
        return NULL; /* Answer does not match the query. */

      buffer = bufp = xmalloc (txtlen + 1);
      while (txtlen && p < pend)
        {
          for (n = *p++, txtlen--; txtlen && n && p < pend; txtlen--, n--)
            *bufp++ = *p++;
        }
      *bufp = 0;
      if (parse_txt_record (buffer, fpr))
        {
          xfree (buffer);
          return NULL; /* Not a valid gpg trustdns RR. */
        }
      return buffer;
    }

  return NULL;
#endif /*!USE_ADNS*/
}

#else /* !USE_DNS_PKA */

/* Dummy version of the function if we can't use the resolver
   functions. */
char *
get_pka_info (const char *address, unsigned char *fpr)
{
  return NULL;
}
#endif /* !USE_DNS_PKA */


#ifdef TEST
int
main(int argc,char *argv[])
{
  unsigned char fpr[20];
  char *uri;
  int i;

  if (argc < 2)
    {
      fprintf (stderr, "usage: pka mail-addresses\n");
      return 1;
    }
  argc--;
  argv++;

  for (; argc; argc--, argv++)
    {
      uri = get_pka_info ( *argv, fpr );
      printf ("%s", *argv);
      if (uri)
        {
          putchar (' ');
          for (i=0; i < 20; i++)
            printf ("%02X", fpr[i]);
          if (*uri)
            printf (" %s", uri);
          xfree (uri);
        }
      putchar ('\n');
    }
  return 0;
}
#endif /* TEST */

/*
Local Variables:
compile-command: "cc -DUSE_DNS_PKA -DTEST -I.. -I../include -Wall -g -o pka pka.c -lresolv ../tools/no-libgcrypt.o ../jnlib/libjnlib.a"
End:
*/
