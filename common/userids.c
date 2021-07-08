/* userids.c - Utility functions for user ids.
 * Copyright (C) 2001, 2003, 2004, 2006,
 *               2009 Free Software Foundation, Inc.
 * Copyright (C) 2015  g10 Code GmbH
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "userids.h"


/* Parse the user-id NAME and build a search description for it.
 * Returns 0 on success or an error code.  DESC may be NULL to merely
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
 * - If the userid starts with a '^' followed by 40 hex digits it describes
 *   a Unique-Blob-ID (UBID) which is the hash of keyblob or certificate as
 *   stored in the database.  This is used in the IPC of the keyboxd.
 */

gpg_error_t
classify_user_id (const char *name, KEYDB_SEARCH_DESC *desc, int openpgp_hack)
{
  const char *s;
  char *s2 = NULL;
  int rc = 0;
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

  /* Skip leading and trailing spaces.  */
  for(s = name; *s && spacep (s); s++ )
    ;
  if (*s && spacep (s + strlen(s) - 1))
    {
      s2 = xtrystrdup (s);
      if (!s2)
        {
          rc = gpg_error_from_syserror ();
          goto out;
        }
      trim_trailing_spaces (s2);
      s = s2;
    }

  switch (*s)
    {
    case 0:  /* Empty string is an error.  */
      rc = gpg_error (GPG_ERR_INV_USER_ID);
      goto out;

    case '.': /* An email address, compare from end.  Note that this
                 has not yet been implemented in the search code.  */
      mode = KEYDB_SEARCH_MODE_MAILEND;
      s++;
      desc->u.name = s;
      desc->name_used = 1;
      break;

    case '<': /* An email address.  */
      mode = KEYDB_SEARCH_MODE_MAIL;
      /* FIXME: The keyring code in g10 assumes that the mail name is
         prefixed with an '<'.  However the keybox code used for sm/
         assumes it has been removed.  For now we use this simple hack
         to overcome the problem.  */
      if (!openpgp_hack)
        s++;
      desc->u.name = s;
      desc->name_used = 1;
      break;

    case '@':  /* Part of an email address.  */
      mode = KEYDB_SEARCH_MODE_MAILSUB;
      s++;
      desc->u.name = s;
      desc->name_used = 1;
      break;

    case '=':  /* Exact compare.  */
      mode = KEYDB_SEARCH_MODE_EXACT;
      s++;
      desc->u.name = s;
      desc->name_used = 1;
      break;

    case '*':  /* Case insensitive substring search.  */
      mode = KEYDB_SEARCH_MODE_SUBSTR;
      s++;
      desc->u.name = s;
      desc->name_used = 1;
      break;

    case '+':  /* Compare individual words.  Note that this has not
                  yet been implemented in the search code.  */
      mode = KEYDB_SEARCH_MODE_WORDS;
      s++;
      desc->u.name = s;
      desc->name_used = 1;
      break;

    case '/': /* Subject's DN.  */
      s++;
      if (!*s || spacep (s)) /* No DN or prefixed with a space.  */
        {
          rc = gpg_error (GPG_ERR_INV_USER_ID);
          goto out;
        }
      desc->u.name = s;
      desc->name_used = 1;
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
              {
                rc = gpg_error (GPG_ERR_INV_USER_ID);
                goto out;
              }
            desc->u.name = s;
            desc->name_used = 1;
            mode = KEYDB_SEARCH_MODE_ISSUER;
          }
        else
          { /* Serialnumber + optional issuer ID.  */
            for (si=s; *si && *si != '/'; si++)
              {
                 /* Check for an invalid digit in the serial number. */
                if (!strchr("01234567890abcdefABCDEF", *si))
                  {
                    rc = gpg_error (GPG_ERR_INV_USER_ID);
                    goto out;
                  }
              }
            desc->sn = (const unsigned char*)s;
            desc->snlen = si - s;
            desc->snhex = 1;
            if (!*si)
              mode = KEYDB_SEARCH_MODE_SN;
            else
              {
                s = si+1;
                if (!*s || spacep (s))  /* No DN or prefixed with a space.  */
                  {
                    rc = gpg_error (GPG_ERR_INV_USER_ID);
                    goto out;
                  }
                desc->u.name = s;
                desc->name_used = 1;
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
          {
            rc = gpg_error (GPG_ERR_INV_USER_ID);
            goto out;
          }
        for (i=0,si=s; si < se; si++, i++ )
          {
            if (!strchr("01234567890abcdefABCDEF", *si))
              {
                rc = gpg_error (GPG_ERR_INV_USER_ID); /* Invalid digit.  */
                goto out;
              }
          }
        if (i != 32 && i != 40 && i != 64)
          {
            rc = gpg_error (GPG_ERR_INV_USER_ID); /* Invalid length of fpr.  */
            goto out;
          }
        for (i=0,si=s; si < se; i++, si +=2)
          desc->u.fpr[i] = hextobyte(si);
        desc->fprlen = i;
        for (; i < 32; i++)
          desc->u.fpr[i]= 0;
        mode = KEYDB_SEARCH_MODE_FPR;
      }
      break;

    case '&': /* Keygrip*/
      {
        if (hex2bin (s+1, desc->u.grip, 20) < 0)
          {
            rc = gpg_error (GPG_ERR_INV_USER_ID); /* Invalid. */
            goto out;
          }
        mode = KEYDB_SEARCH_MODE_KEYGRIP;
      }
      break;

    case '^': /* UBID */
      {
        if (hex2bin (s+1, desc->u.ubid, UBID_LEN) < 0)
          {
            rc = gpg_error (GPG_ERR_INV_USER_ID); /* Invalid. */
            goto out;
          }
        mode = KEYDB_SEARCH_MODE_UBID;
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
            {
              rc = gpg_error (GPG_ERR_INV_USER_ID);
              goto out;
            }
          /* The first characters looked like a hex number, but the
             entire string is not.  */
          hexlength = 0;
        }

      if (desc->exact)
        hexlength--; /* Remove the bang.  */

      if ((hexlength == 8
           && (s[hexlength] == 0
               || (s[hexlength] == '!' && s[hexlength + 1] == 0)))
          || (!hexprefix && hexlength == 9 && *s == '0'))
        {
          /* Short keyid.  */
          if (hexlength == 9)
            s++;
          desc->u.kid[1] = strtoul( s, NULL, 16 );
          mode = KEYDB_SEARCH_MODE_SHORT_KID;
        }
      else if ((hexlength == 16
                && (s[hexlength] == 0
                    || (s[hexlength] == '!' && s[hexlength + 1] == 0)))
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
      else if ((hexlength == 32
                && (s[hexlength] == 0
                    || (s[hexlength] == '!' && s[hexlength + 1] == 0)))
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
                {
                  rc = gpg_error (GPG_ERR_INV_USER_ID);
                  goto out;
                }
              desc->u.fpr[i] = c;
            }
          desc->fprlen = 16;
          for (; i < 32; i++)
            desc->u.fpr[i]= 0;
          mode = KEYDB_SEARCH_MODE_FPR;
        }
      else if ((hexlength == 40
                && (s[hexlength] == 0
                    || (s[hexlength] == '!' && s[hexlength + 1] == 0)))
               || (!hexprefix && hexlength == 41 && *s == '0'))
        {
          /* SHA1 fingerprint.  */
          int i;
          if (hexlength == 41)
            s++;
          for (i=0; i < 20; i++, s+=2)
            {
              int c = hextobyte(s);
              if (c == -1)
                {
                  rc = gpg_error (GPG_ERR_INV_USER_ID);
                  goto out;
                }
              desc->u.fpr[i] = c;
            }
          desc->fprlen = 20;
          for (; i < 32; i++)
            desc->u.fpr[i]= 0;
          mode = KEYDB_SEARCH_MODE_FPR;
        }
      else if ((hexlength == 64
                && (s[hexlength] == 0
                    || (s[hexlength] == '!' && s[hexlength + 1] == 0)))
               || (!hexprefix && hexlength == 65 && *s == '0'))
        {
          /* SHA256 fingerprint.  */
          int i;
          if (hexlength == 65)
            s++;
          for (i=0; i < 32; i++, s+=2)
            {
              int c = hextobyte(s);
              if (c == -1)
                {
                  rc = gpg_error (GPG_ERR_INV_USER_ID);
                  goto out;
                }
              desc->u.fpr[i] = c;
            }
          desc->fprlen = 32;
          mode = KEYDB_SEARCH_MODE_FPR;
        }
      else if (!hexprefix)
        {
          /* The fingerprint of an X.509 listing is often delimited by
           * colons, so we try to single this case out.  Note that the
           * OpenPGP bang suffix is not supported here.  */
          desc->exact = 0;
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
                {
                  desc->fprlen = 20;
                  mode = KEYDB_SEARCH_MODE_FPR;
                }
              for (; i < 32; i++)
                desc->u.fpr[i]= 0;
            }
          if (!mode)
            {
              /* Still not found.  Now check for a space separated
               * OpenPGP v4 fingerprint like:
               *   8061 5870 F5BA D690 3336  86D0 F2AD 85AC 1E42 B367
               * or
               *   8061 5870 F5BA D690 3336 86D0 F2AD 85AC 1E42 B367
               * FIXME: Support OpenPGP v5 fingerprint
               */
              hexlength = strspn (s, " 0123456789abcdefABCDEF");
              if (s[hexlength] && s[hexlength] != ' ')
                hexlength = 0; /* Followed by non-space.  */
              while (hexlength && s[hexlength-1] == ' ')
                hexlength--;   /* Trim trailing spaces.  */
              if ((hexlength == 49 || hexlength == 50)
                  && (!s[hexlength] || s[hexlength] == ' '))
                {
                  int i, c;

                  for (i=0; i < 20; i++)
                    {
                      if (i && !(i % 2))
                        {
                          if (*s != ' ')
                            break;
                          s++;
                          /* Skip the double space in the middle but
                             don't require it to help copying
                             fingerprints from sources which fold
                             multiple space to one.  */
                          if (i == 10 && *s == ' ')
                            s++;
                        }

                      c = hextobyte(s);
                      if (c == -1)
                        break;
                      desc->u.fpr[i] = c;
                      s += 2;
                    }
                  if (i == 20)
                    {
                      desc->fprlen = 20;
                      mode = KEYDB_SEARCH_MODE_FPR;
                    }
                  for (; i < 32; i++)
                    desc->u.fpr[i]= 0;
                }
            }
          if (!mode) /* Default to substring search.  */
            {
              desc->u.name = s;
              desc->name_used = 1;
              mode = KEYDB_SEARCH_MODE_SUBSTR;
            }
        }
      else
	{
          /* Hex number with a prefix but with a wrong length.  */
          rc = gpg_error (GPG_ERR_INV_USER_ID);
          goto out;
        }
    }

  desc->mode = mode;
 out:
  xfree (s2);
  return rc;
}
