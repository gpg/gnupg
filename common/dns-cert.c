/* dns-cert.c - DNS CERT code (rfc-4398)
 * Copyright (C) 2005, 2006, 2009 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <sys/types.h>
#ifdef USE_DNS_CERT
# ifdef HAVE_W32_SYSTEM
#  include <windows.h>
# else
#  include <netinet/in.h>
#  include <arpa/nameser.h>
#  include <resolv.h>
# endif
# include <string.h>
#endif
#ifdef USE_ADNS
# include <adns.h>
# ifndef HAVE_ADNS_FREE
#  define adns_free free
# endif
#endif

#include "util.h"
#include "iobuf.h"
#include "dns-cert.h"

/* Not every installation has gotten around to supporting CERTs
   yet... */
#ifndef T_CERT
#define T_CERT 37
#endif

/* ADNS has no support for CERT yet. */
#define my_adns_r_cert 37


/* Certificate types according to RFC-4398.  */
#define CERTTYPE_PKIX      1 /* X.509 as per PKIX. */
#define CERTTYPE_SPKI      2 /* SPKI certificate.  */
#define CERTTYPE_PGP       3 /* OpenPGP packet.  */
#define CERTTYPE_IPKIX     4 /* The URL of an X.509 data object. */
#define CERTTYPE_ISPKI     5 /* The URL of an SPKI certificate.  */
#define CERTTYPE_IPGP      6 /* The fingerprint and URL of an OpenPGP packet.*/
#define CERTTYPE_ACPKIX    7 /* Attribute Certificate.  */
#define CERTTYPE_IACPKIX   8 /* The URL of an Attribute Certificate.  */
#define CERTTYPE_URI     253 /* URI private.  */
#define CERTTYPE_OID     254 /* OID private.  */


/* Returns -1 on error, 0 for no answer, 1 for PGP provided and 2 for
   IPGP provided.  Note that this function returns the first CERT
   found with a supported type; it is expected that only one CERT
   record is used. */
int
get_dns_cert (const char *name, size_t max_size, IOBUF * iobuf,
              unsigned char **fpr, size_t * fpr_len, char **url)
{
#ifdef USE_DNS_CERT
#ifdef USE_ADNS
  adns_state state;
  adns_answer *answer = NULL;
  int rc;
  unsigned int ctype;
  int count;

  rc = adns_init (&state, adns_if_noerrprint, NULL);
  if (rc)
    {
      log_error ("error initializing adns: %s\n", strerror (errno));
      return -1;
    }

  rc = adns_synchronous (state, name, (adns_r_unknown | my_adns_r_cert),
                         adns_qf_quoteok_query, &answer);
  if (rc)
    {
      /* log_error ("DNS query failed: %s\n", strerror (errno)); */
      adns_finish (state);
      return -1;
    }
  if (answer->status != adns_s_ok)
    {
      /* log_error ("DNS query returned an error: %s (%s)\n", */
      /*            adns_strerror (answer->status), */
      /*            adns_errabbrev (answer->status)); */
      adns_free (answer);
      adns_finish (state);
      return 0;
    }

  for (rc = 0, count = 0; !rc && count < answer->nrrs; count++)
    {
      int datalen = answer->rrs.byteblock[count].len;
      const unsigned char *data = answer->rrs.byteblock[count].data;

      if (datalen < 5)
        continue;  /* Truncated CERT record - skip.  */

      ctype = ((data[0] << 8) | data[1]);
      /* (key tag and algorithm fields are not required.) */
      data += 5;
      datalen -= 5;

      if (ctype == CERTTYPE_PGP && datalen >= 11)
        {
          /* CERT type is PGP.  Gpg checks for a minimum length of 11,
             thus we do the same.  */
          *iobuf = iobuf_temp_with_content ((char *)data, datalen);
          rc = 1;
        }
      else if (ctype == CERTTYPE_IPGP && datalen && datalen < 1023
               && datalen >= data[0] + 1 && fpr && fpr_len && url)
        {
          /* CERT type is IPGP.  We made sure that the data is
             plausible and that the caller requested this
             information.  */
          *fpr_len = data[0];
          if (*fpr_len)
            {
              *fpr = xmalloc (*fpr_len);
              memcpy (*fpr, data + 1, *fpr_len);
            }
          else
            *fpr = NULL;

          if (datalen > *fpr_len + 1)
            {
              *url = xmalloc (datalen - (*fpr_len + 1) + 1);
              memcpy (*url, data + (*fpr_len + 1), datalen - (*fpr_len + 1));
              (*url)[datalen - (*fpr_len + 1)] = '\0';
            }
          else
            *url = NULL;

          rc = 2;
        }
    }

  adns_free (answer);
  adns_finish (state);
  return rc;

#else /*!USE_ADNS*/

  unsigned char *answer;
  int ret = -1;
  int r;
  u16 count;

  if (fpr)
    *fpr = NULL;

  if (url)
    *url = NULL;

  answer = xmalloc (max_size);

  r = res_query (name, C_IN, T_CERT, answer, max_size);
  /* Not too big, not too small, no errors and at least 1 answer. */
  if (r >= sizeof (HEADER) && r <= max_size
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
        goto fail;

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
            break;

          pt += rc;

          /* Truncated message? 15 bytes takes us to the point where
             we start looking at the ctype. */
          if ((emsg - pt) < 15)
            break;

          type = *pt++ << 8;
          type |= *pt++;

          class = *pt++ << 8;
          class |= *pt++;
          /* We asked for IN and got something else !? */
          if (class != C_IN)
            break;

          /* ttl */
          pt += 4;

          /* data length */
          dlen = *pt++ << 8;
          dlen |= *pt++;

          /* We asked for CERT and got something else - might be a
             CNAME, so loop around again. */
          if (type != T_CERT)
            {
              pt += dlen;
              continue;
            }

          /* The CERT type */
          ctype = *pt++ << 8;
          ctype |= *pt++;

          /* Skip the CERT key tag and algo which we don't need. */
          pt += 3;

          dlen -= 5;

          /* 15 bytes takes us to here */

          if (ctype == CERTTYPE_PGP && iobuf && dlen)
            {
              /* PGP type */
              *iobuf = iobuf_temp_with_content ((char *) pt, dlen);
              ret = 1;
              break;
            }
          else if (ctype == CERTTYPE_IPGP
                   && dlen && dlen < 1023 && dlen >= pt[0] + 1
                   && fpr && fpr_len && url)
            {
              /* IPGP type */
              *fpr_len = pt[0];

              if (*fpr_len)
                {
                  *fpr = xmalloc (*fpr_len);
                  memcpy (*fpr, &pt[1], *fpr_len);
                }
              else
                *fpr = NULL;

              if (dlen > *fpr_len + 1)
                {
                  *url = xmalloc (dlen - (*fpr_len + 1) + 1);
                  memcpy (*url, &pt[*fpr_len + 1], dlen - (*fpr_len + 1));
                  (*url)[dlen - (*fpr_len + 1)] = '\0';
                }
              else
                *url = NULL;

              ret = 2;
              break;
            }

          /* Neither type matches, so go around to the next answer. */
          pt += dlen;
        }
    }

 fail:
  xfree (answer);
  return ret;
#endif /*!USE_ADNS */
#else /* !USE_DNS_CERT */
  (void)name;
  (void)max_size;
  (void)iobuf;
  (void)fpr;
  (void)fpr_len;
  (void)url;

  return -1;
#endif
}
