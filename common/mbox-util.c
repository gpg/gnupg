/* mbox-util.c - Mail address helper functions
 * Copyright (C) 1998-2010 Free Software Foundation, Inc.
 * Copyright (C) 1998-2015 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* NB: GPGME uses the same code to reflect our idea on how to extract
 * a mail address from a user id.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "mbox-util.h"


static int
string_count_chr (const char *string, int c)
{
  int count;

  for (count=0; *string; string++ )
    if ( *string == c )
      count++;
  return count;
}

static int
mem_count_chr (const void *buffer, int c, size_t length)
{
  const char *s = buffer;
  int count;

  for (count=0; length; length--, s++)
    if (*s == c)
      count++;
  return count;
}


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


/* Check whether BUFFER has characters not valid in an RFC-822
   address.  LENGTH gives the length of BUFFER.

   To cope with OpenPGP we ignore non-ascii characters so that for
   example umlauts are legal in an email address.  An OpenPGP user ID
   must be utf-8 encoded but there is no strict requirement for
   RFC-822.  Thus to avoid IDNA encoding we put the address verbatim
   as utf-8 into the user ID under the assumption that mail programs
   handle IDNA at a lower level and take OpenPGP user IDs as utf-8.
   Note that we can't do an utf-8 encoding checking here because in
   keygen.c this function is called with the native encoding and
   native to utf-8 encoding is only done later.  */
int
has_invalid_email_chars (const void *buffer, size_t length)
{
  const unsigned char *s = buffer;
  int at_seen=0;
  const char *valid_chars=
    "01234567890_-.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

  for ( ; length && *s; length--, s++ )
    {
      if ((*s & 0x80))
        continue; /* We only care about ASCII.  */
      if (*s == '@')
        at_seen=1;
      else if (!at_seen && !(strchr (valid_chars, *s)
                             || strchr ("!#$%&'*+/=?^`{|}~", *s)))
        return 1;
      else if (at_seen && !strchr (valid_chars, *s))
        return 1;
    }
  return 0;
}


/* Same as is_valid_mailbox (see below) but operates on non-nul
   terminated buffer.  */
int
is_valid_mailbox_mem (const void *name_arg, size_t namelen)
{
  const char *name = name_arg;

  return !( !name
            || !namelen
            || has_invalid_email_chars (name, namelen)
            || mem_count_chr (name, '@', namelen) != 1
            || *name == '@'
            || name[namelen-1] == '@'
            || name[namelen-1] == '.'
            || gnupg_memstr (name, namelen, ".."));
}


/* Check whether NAME represents a valid mailbox according to
   RFC822. Returns true if so. */
int
is_valid_mailbox (const char *name)
{
  return name? is_valid_mailbox_mem (name, strlen (name)) : 0;
}


/* Return the mailbox (local-part@domain) form a standard user id.
 * All plain ASCII characters in the result are converted to
 * lowercase.  If SUBADDRESS is 1, '+' denoted sub-addresses are not
 * included in the result.  Caller must free the result.  Returns NULL
 * if no valid mailbox was found (or we are out of memory). */
char *
mailbox_from_userid (const char *userid, int subaddress)
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
          result = xtrymalloc (len + 1);
          if (!result)
            return NULL; /* Ooops - out of core.  */
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

  if (result && subaddress == 1)
    {
      char *atsign, *plus;

      if ((atsign = strchr (result, '@')))
        {
          /* We consider a subaddress only if there is a single '+'
           * in the local part and the '+' is not the first or last
           * character.  */
          *atsign = 0;
          if ((plus = strchr (result, '+'))
              && !strchr (plus+1, '+')
              && result != plus
              && plus[1] )
            {
              *atsign = '@';
              memmove (plus, atsign, strlen (atsign)+1);
            }
          else
            *atsign = '@';
        }
    }

  return result? ascii_strlwr (result): NULL;
}


/* Check whether UID is a valid standard user id of the form
     "Heinrich Heine <heinrichh@duesseldorf.de>"
   and return true if this is the case. */
int
is_valid_user_id (const char *uid)
{
  if (!uid || !*uid)
    return 0;

  return 1;
}


/* Returns true if STRING is a valid domain name according to the LDH
 * rule. */
int
is_valid_domain_name (const char *string)
{
  static char const ldh_chars[] =
    "01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-";
  const char *s;

  /* Note that we do not check the length limit of a label or the
   * entire name */

  for (s=string; *s; s++)
    if (*s == '.')
      {
        if (string == s)
          return 0; /* Dot at the start of the string.  */
                    /* (may also be at the end like in ".") */
        if (s[1] == '.')
          return 0; /* No - double dot.  */
      }
    else if (!strchr (ldh_chars, *s))
      return 0;
    else if (*s == '-')
      {
        if (string == s)
          return 0;  /* Leading hyphen.  */
        if (s[-1] == '.')
          return 0;  /* Hyphen at begin of a label.  */
        if (s[1] == '.')
          return 0;  /* Hyphen at start of a label.  */
        if (!s[1])
          return 0;  /* Trailing hyphen.  */
      }

  return !!*string;
}
