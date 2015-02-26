/* pka.c - DNS Public Key Association RR access
 * Copyright (C) 2005, 2009 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "mbox-util.h"
#include "dns-cert.h"
#include "pka.h"


/* For the given email ADDRESS lookup the PKA information in the DNS.

   On success the fingerprint is stored at FPRBUF and the URI will be
   returned in an allocated buffer.  Note that the URI might be a zero
   length string as this information is optional.  Caller must xfree
   the returned string.  FPRBUFLEN gives the size of the expected
   fingerprint (usually 20).

   On error NULL is returned and the FPRBUF is not defined. */
char *
get_pka_info (const char *address, void *fprbuf, size_t fprbuflen)
{
  char *result = NULL;
  char *mbox;
  char *domain;  /* Points to mbox.  */
  char hashbuf[20];
  char *hash = NULL;
  char *name = NULL;
  unsigned char *fpr = NULL;
  size_t fpr_len;
  char *url = NULL;

  mbox = mailbox_from_userid (address);
  if (!mbox)
    goto leave;
  domain = strchr (mbox, '@');
  if (!domain)
    goto leave;
  *domain++ = 0;

  gcry_md_hash_buffer (GCRY_MD_SHA1, hashbuf, mbox, strlen (mbox));
  hash = zb32_encode (hashbuf, 8*20);
  if (!hash)
    goto leave;
  name = strconcat (hash, "._pka.", domain, NULL);
  if (!name)
    goto leave;

  if (get_dns_cert (name, DNS_CERTTYPE_IPGP, NULL, &fpr, &fpr_len, &url))
    goto leave;
  if (!fpr)
    goto leave;

  /* Return the fingerprint.  */
  if (fpr_len != fprbuflen)
    {
      /* fprintf (stderr, "get_dns_cert failed: fprlen (%zu/%zu)\n", */
      /*          fpr_len, fprbuflen); */
      goto leave;
    }
  memcpy (fprbuf, fpr, fpr_len);

  /* We return the URL or an empty string.  */
  if (!url)
    url = xtrycalloc (1, 1);
  result = url;
  url = NULL;

 leave:
  xfree (fpr);
  xfree (url);
  xfree (name);
  xfree (hash);
  xfree (mbox);
  return result;
}
