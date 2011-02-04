/* userids.c - Utility functions for user ids.
 * Copyright (C) 2001, 2003, 2004, 2006,
 *               2009 Free Software Foundation, Inc.
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

/* This file implements a few utility functions useful when working
   with canonical encrypted S-expresions (i.e. not the S-exprssion
   objects from libgcrypt).  */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "userids.h"


/* Parse the user-id NAME and build a search description for it.
 * Returns 0 on succdess or an error code.  DESC may be NULL to merely
 * check the validity of a user-id.
 *
 * Some used rules:
 * - If the username starts with 8,9,16 or 17 hex-digits (the first one
 *   must be in the range 0..9), this is considered a keyid; depending
 *   on the length a short or complete one.
 * - If the username starts with 32,33,40 or 41 hex-digits (the first one
 *   must be in the range 0..9), this is considered a fingerprint.
 * - If the username starts with a left angle, we assume it is a complete
 *   email address and look only at this part.
 * - If the username starts with a colon we assume it is a unified
 *   key specfification.
 * - If the username starts with a '.', we assume it is the ending
 *   part of an email address
 * - If the username starts with an '@', we assume it is a part of an
 *   email address
 * - If the userid start with an '=' an exact compare is done.
 * - If the userid starts with a '*' a case insensitive substring search is
 *   done (This is the default).
 * - If the userid starts with a '+' we will compare individual words
 *   and a match requires that all the words are in the userid.
 *   Words are delimited by white space or "()<>[]{}.@-+_,;/&!"
 *   (note that you can't search for these characters). Compare
 *   is not case sensitive.
 * - If the userid starts with a '&' a 40 hex digits keygrip is expected.
 */

gpg_error_t
classify_user_id (const char *name, KEYDB_SEARCH_DESC *desc)
{
  const char *s;
  int hexprefix = 0;
  int hexlength;
  int mode = 0;
  KEYDB_SEARCH_DESC dummy_desc;

  if (!desc)
    desc = &dummy_desc;

  /* Clear the structure so that the mode field is set to zero unless
     we set it to the correct value right at the end of this
     function. */
  memset (desc, 0, sizeof *desc);

  /* Skip leading spaces.  */
  for(s = name; *s && spacep (s); s++ )
    ;

  switch (*s)
    {
    case 0:  /* Empty string is an error.  */
      return gpg_error (GPG_ERR_INV_USER_ID);

    case '.': /* An email address, compare from end.  Note that this
                 has not yet been implemented in the search code.  */
      mode = KEYDB_SEARCH_MODE_MAILEND;
      s++;
      desc->u.name = s;
      break;

    case '<': /* An email address.  */
      mode = KEYDB_SEARCH_MODE_MAIL;
      s++;
      desc->u.name = s;
      break;

    case '@':  /* Part of an email address.  */
      mode = KEYDB_SEARCH_MODE_MAILSUB;
      s++;
      desc->u.name = s;
      break;

    case '=':  /* Exact compare.  */
      mode = KEYDB_SEARCH_MODE_EXACT;
      s++;
      desc->u.name = s;
      break;

    case '*':  /* Case insensitive substring search.  */
      mode = KEYDB_SEARCH_MODE_SUBSTR;
      s++;
      desc->u.name = s;
      break;

    case '+':  /* Compare individual words.  Note that this has not
                  yet been implemented in the search code.  */
      mode = KEYDB_SEARCH_MODE_WORDS;
      s++;
      desc->u.name = s;
      break;

    case '/': /* Subject's DN.  */
      s++;
      if (!*s || spacep (s)) /* No DN or prefixed with a space.  */
        return gpg_error (GPG_ERR_INV_USER_ID);
      desc->u.name = s;
      mode = KEYDB_SEARCH_MODE_SUBJECT;
      break;

    case '#': /* S/N with optional issuer id or just issuer id.  */
      {
        const char *si;

        s++;
        if ( *s == '/')
          { /* "#/" indicates an issuer's DN.  */
            s++;
            if (!*s || spacep (s)) /* No DN or prefixed with a space.  */
              return gpg_error (GPG_ERR_INV_USER_ID);
            desc->u.name = s;
            mode = KEYDB_SEARCH_MODE_ISSUER;
          }
        else
          { /* Serialnumber + optional issuer ID.  */
            for (si=s; *si && *si != '/'; si++)
              {
                 /* Check for an invalid digit in the serial number. */
                if (!strchr("01234567890abcdefABCDEF", *si))
                  return gpg_error (GPG_ERR_INV_USER_ID);
              }
            desc->sn = (const unsigned char*)s;
            desc->snlen = -1;
            if (!*si)
              mode = KEYDB_SEARCH_MODE_SN;
            else
              {
                s = si+1;
                if (!*s || spacep (s))  /* No DN or prefixed with a space.  */
                  return gpg_error (GPG_ERR_INV_USER_ID);
                desc->u.name = s;
                mode = KEYDB_SEARCH_MODE_ISSUER_SN;
              }
          }
      }
      break;

    case ':': /* Unified fingerprint. */
      {
        const char *se, *si;
        int i;

        se = strchr (++s,':');
        if (!se)
          return gpg_error (GPG_ERR_INV_USER_ID);
        for (i=0,si=s; si < se; si++, i++ )
          {
            if (!strchr("01234567890abcdefABCDEF", *si))
              return gpg_error (GPG_ERR_INV_USER_ID); /* Invalid digit.  */
          }
        if (i != 32 && i != 40)
          return gpg_error (GPG_ERR_INV_USER_ID); /* Invalid length of fpr.  */
        for (i=0,si=s; si < se; i++, si +=2)
          desc->u.fpr[i] = hextobyte(si);
        for (; i < 20; i++)
          desc->u.fpr[i]= 0;
        s = se + 1;
        mode = KEYDB_SEARCH_MODE_FPR;
      }
      break;

    case '&': /* Keygrip*/
      {
        if (hex2bin (s+1, desc->u.grip, 20) < 0)
          return gpg_error (GPG_ERR_INV_USER_ID); /* Invalid. */
        mode = KEYDB_SEARCH_MODE_KEYGRIP;
      }
      break;

    default:
      if (s[0] == '0' && s[1] == 'x')
        {
          hexprefix = 1;
          s += 2;
        }

      hexlength = strspn(s, "0123456789abcdefABCDEF");
      if (hexlength >= 8 && s[hexlength] =='!')
        {
          desc->exact = 1;
          hexlength++; /* Just for the following check.  */
        }

      /* Check if a hexadecimal number is terminated by EOS or blank.  */
      if (hexlength && s[hexlength] && !spacep (s+hexlength))
        {
          if (hexprefix) /* A "0x" prefix without a correct
                            termination is an error.  */
            return gpg_error (GPG_ERR_INV_USER_ID);
          /* The first characters looked like a hex number, but the
             entire string is not.  */
          hexlength = 0;
        }

      if (desc->exact)
        hexlength--; /* Remove the bang.  */

      if (hexlength == 8
          || (!hexprefix && hexlength == 9 && *s == '0'))
        {
          /* Short keyid.  */
          if (hexlength == 9)
            s++;
          desc->u.kid[1] = strtoul( s, NULL, 16 );
          mode = KEYDB_SEARCH_MODE_SHORT_KID;
        }
      else if (hexlength == 16
               || (!hexprefix && hexlength == 17 && *s == '0'))
        {
          /* Long keyid.  */
          char buf[9];
          if (hexlength == 17)
            s++;
          mem2str (buf, s, 9);
          desc->u.kid[0] = strtoul (buf, NULL, 16);
          desc->u.kid[1] = strtoul (s+8, NULL, 16);
          mode = KEYDB_SEARCH_MODE_LONG_KID;
        }
      else if (hexlength == 32
               || (!hexprefix && hexlength == 33 && *s == '0'))
        {
          /* MD5 fingerprint.  */
          int i;
          if (hexlength == 33)
            s++;
          memset (desc->u.fpr+16, 0, 4);
          for (i=0; i < 16; i++, s+=2)
            {
              int c = hextobyte(s);
              if (c == -1)
                return gpg_error (GPG_ERR_INV_USER_ID);
              desc->u.fpr[i] = c;
            }
          mode = KEYDB_SEARCH_MODE_FPR16;
        }
      else if (hexlength == 40
               || (!hexprefix && hexlength == 41 && *s == '0'))
        {
          /* SHA1/RMD160 fingerprint.  */
          int i;
          if (hexlength == 41)
            s++;
          for (i=0; i < 20; i++, s+=2)
            {
              int c = hextobyte(s);
              if (c == -1)
                return gpg_error (GPG_ERR_INV_USER_ID);
              desc->u.fpr[i] = c;
            }
          mode = KEYDB_SEARCH_MODE_FPR20;
        }
      else if (!hexprefix)
        {
          /* The fingerprint in an X.509 listing is often delimited by
             colons, so we try to single this case out. */
          mode = 0;
          hexlength = strspn (s, ":0123456789abcdefABCDEF");
          if (hexlength == 59 && (!s[hexlength] || spacep (s+hexlength)))
            {
              int i;

              for (i=0; i < 20; i++, s += 3)
                {
                  int c = hextobyte(s);
                  if (c == -1 || (i < 19 && s[2] != ':'))
                    break;
                  desc->u.fpr[i] = c;
                }
              if (i == 20)
                mode = KEYDB_SEARCH_MODE_FPR20;
            }
          if (!mode) /* Default to substring search.  */
            {
              desc->exact = 0;
              desc->u.name = s;
              mode = KEYDB_SEARCH_MODE_SUBSTR;
            }
        }
      else
	{
          /* Hex number with a prefix but with a wrong length.  */
          return gpg_error (GPG_ERR_INV_USER_ID);
        }
    }

  desc->mode = mode;
  return 0;
}
