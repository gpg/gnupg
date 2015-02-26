/* pka.c - DNS Public Key Association CERT record access
 * Copyright (C) 1998-2015 Free Software Foundation, Inc.
 * Copyright (C) 1998-2015 Werner Koch
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
#include <errno.h>

#include "memory.h"
#include "types.h"
#include "cipher.h"
#include "util.h"

static int
string_has_ctrl_or_space (const char *string)
{
  for (; *string; string++ )
    if (!(*string & 0x80) && *string <= 0x20)
      return 1;
  return 0;
}


/* Return true if STRING has two consecutive '.' after an '@'
   sign.  */
static int
has_dotdot_after_at (const char *string)
{
  string = strchr (string, '@');
  if (!string)
    return 0; /* No at-sign.  */
  string++;
  return !!strstr (string, "..");
}


/* Return the mailbox (local-part@domain) form a standard user id.
   Caller must free the result.  Returns NULL if no valid mailbox was
   found (or we are out of memory). */
static char *
mailbox_from_userid (const char *userid)
{
  const char *s, *s_end;
  size_t len;
  char *result = NULL;

  s = strchr (userid, '<');
  if (s)
    {
      /* Seems to be a standard user id.  */
      s++;
      s_end = strchr (s, '>');
      if (s_end && s_end > s)
        {
          len = s_end - s;
          result = xmalloc (len + 1);
          strncpy (result, s, len);
          result[len] = 0;
          /* Apply some basic checks on the address.  We do not use
             is_valid_mailbox because those checks are too strict.  */
          if (string_count_chr (result, '@') != 1  /* Need exactly one '@.  */
              || *result == '@'           /* local-part missing.  */
              || result[len-1] == '@'     /* domain missing.  */
              || result[len-1] == '.'     /* ends with a dot.  */
              || string_has_ctrl_or_space (result)
              || has_dotdot_after_at (result))
            {
              xfree (result);
              result = NULL;
              errno = EINVAL;
            }
        }
      else
        errno = EINVAL;
    }
  else if (is_valid_mailbox (userid))
    {
      /* The entire user id is a mailbox.  Return that one.  Note that
         this fallback method has some restrictions on the valid
         syntax of the mailbox.  However, those who want weird
         addresses should know about it and use the regular <...>
         syntax.  */
      result = xtrystrdup (userid);
    }
  else
    errno = EINVAL;

  return result? ascii_strlwr (result) : NULL;
}


/* Zooko's base32 variant. See RFC-6189 and
   http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
   Caller must xfree the returned string.  Returns NULL and sets ERRNO
   on error.  To avoid integer overflow DATALEN is limited to 2^16
   bytes.  Note, that DATABITS is measured in bits!.  */
static char *
zb32_encode (const void *data, unsigned int databits)
{
  static char const zb32asc[32] = {'y','b','n','d','r','f','g','8',
                                   'e','j','k','m','c','p','q','x',
                                   'o','t','1','u','w','i','s','z',
                                   'a','3','4','5','h','7','6','9' };
  const unsigned char *s;
  char *output, *d;
  size_t datalen;

  datalen = (databits + 7) / 8;
  if (datalen > (1 << 16))
    {
      errno = EINVAL;
      return NULL;
    }

  d = output = xtrymalloc (8 * (datalen / 5)
                           + 2 * (datalen % 5)
                           - ((datalen%5)>2)
                           + 1);
  if (!output)
    return NULL;

  /* I use straightforward code.  The compiler should be able to do a
     better job on optimization than me and it is easier to read.  */
  for (s = data; datalen >= 5; s += 5, datalen -= 5)
    {
      *d++ = zb32asc[((s[0]      ) >> 3)               ];
      *d++ = zb32asc[((s[0] &   7) << 2) | (s[1] >> 6) ];
      *d++ = zb32asc[((s[1] &  63) >> 1)               ];
      *d++ = zb32asc[((s[1] &   1) << 4) | (s[2] >> 4) ];
      *d++ = zb32asc[((s[2] &  15) << 1) | (s[3] >> 7) ];
      *d++ = zb32asc[((s[3] & 127) >> 2)               ];
      *d++ = zb32asc[((s[3] &   3) << 3) | (s[4] >> 5) ];
      *d++ = zb32asc[((s[4] &  31)     )               ];
    }

  switch (datalen)
    {
    case 4:
      *d++ = zb32asc[((s[0]      ) >> 3)               ];
      *d++ = zb32asc[((s[0] &   7) << 2) | (s[1] >> 6) ];
      *d++ = zb32asc[((s[1] &  63) >> 1)               ];
      *d++ = zb32asc[((s[1] &   1) << 4) | (s[2] >> 4) ];
      *d++ = zb32asc[((s[2] &  15) << 1) | (s[3] >> 7) ];
      *d++ = zb32asc[((s[3] & 127) >> 2)               ];
      *d++ = zb32asc[((s[3] &   3) << 3)               ];
      break;
    case 3:
      *d++ = zb32asc[((s[0]      ) >> 3)               ];
      *d++ = zb32asc[((s[0] &   7) << 2) | (s[1] >> 6) ];
      *d++ = zb32asc[((s[1] &  63) >> 1)               ];
      *d++ = zb32asc[((s[1] &   1) << 4) | (s[2] >> 4) ];
      *d++ = zb32asc[((s[2] &  15) << 1)               ];
      break;
    case 2:
      *d++ = zb32asc[((s[0]      ) >> 3)               ];
      *d++ = zb32asc[((s[0] &   7) << 2) | (s[1] >> 6) ];
      *d++ = zb32asc[((s[1] &  63) >> 1)               ];
      *d++ = zb32asc[((s[1] &   1) << 4)               ];
      break;
    case 1:
      *d++ = zb32asc[((s[0]      ) >> 3)               ];
      *d++ = zb32asc[((s[0] &   7) << 2)               ];
      break;
    default:
      break;
    }
  *d = 0;

  /* Need to strip some bytes if not a multiple of 40.  */
  output[(databits + 5 - 1) / 5] = 0;
  return output;
}



/* For the given email ADDRESS lookup the PKA information in the DNS.

   On success the fingerprint is stored at FPRBUF and the URI will be
   returned in an allocated buffer.  Note that the URI might be a zero
   length string as this information is optional.  Caller must xfree
   the returned string.  FPRBUFLEN gives the size of the expected
   fingerprint (usually 20).

   On error NULL is returned and the 20 bytes at FPR are not
   defined. */
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

  sha1_hash_buffer (hashbuf, mbox, strlen (mbox));
  hash = zb32_encode (hashbuf, 8*20);
  if (!hash)
    goto leave;
  name = strconcat (hash, "._pka.", domain, NULL);
  if (!name)
    goto leave;
  if (get_cert (name, 1, 16384, NULL, &fpr, &fpr_len, &url))
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
    url = xcalloc (1, 1);
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
