/* divert-scd.c - divert operations to the scdaemon 
 *	Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"
#include "sexp-parse.h"



static int
ask_for_card (const unsigned char *shadow_info, char **r_kid)
{
  int rc, i;
  const unsigned char *s;
  size_t n;
  char *serialno;
  int no_card = 0;
  char *desc;
  char *want_sn, *want_kid;

  *r_kid = NULL;
  s = shadow_info;
  if (*s != '(')
    return GNUPG_Invalid_Sexp;
  s++;
  n = snext (&s);
  if (!n)
    return GNUPG_Invalid_Sexp;
  want_sn = xtrymalloc (n+1);
  if (!want_sn)
    return GNUPG_Out_Of_Core;
  memcpy (want_sn, s, n);
  want_sn[n] = 0;
  s += n;

  n = snext (&s);
  if (!n)
    return GNUPG_Invalid_Sexp;
  want_kid = xtrymalloc (n+1);
  if (!want_kid)
    {
      xfree (want_sn);
      return GNUPG_Out_Of_Core;
    }
  memcpy (want_kid, s, n);
  want_kid[n] = 0;

  for (;;)
    {
      rc = agent_card_serialno (&serialno);
      if (!rc)
        {
          log_debug ("detected card with S/N %s\n", serialno);
          i = strcmp (serialno, want_sn);
          xfree (serialno);
          serialno = NULL;
          if (!i)
            {
              xfree (want_sn);
              *r_kid = want_kid;
              return 0; /* yes, we have the correct card */
            }
        }
      else if (rc == GNUPG_Card_Not_Present)
        {
          log_debug ("no card present\n");
          rc = 0;
          no_card = 1;
        }
      else
        {
          log_error ("error accesing card: %s\n", gnupg_strerror (rc));
        }

      if (!rc)
        {
          if (asprintf (&desc,
                    "%s:%%0A%%0A"
                    "  \"%s\"",
                    no_card? "Please insert the card with serial number" 
                    : "Please remove the current card and "
                    "insert the one with serial number",
                    want_sn) < 0)
            {
              rc = GNUPG_Out_Of_Core;
            }
          else
            {
              rc = agent_get_confirmation (desc, NULL);
              free (desc);
            }
        }
      if (rc)
        {
          xfree (want_sn);
          xfree (want_kid);
          return rc;
        }
    }
}



int
divert_pksign (GCRY_SEXP *s_sig, GCRY_SEXP s_hash, const char *shadow_info)
{
  int rc;
  char *kid;

  rc = ask_for_card (shadow_info, &kid);
  if (rc)
    return rc;

 
  xfree (kid);
  return GNUPG_Not_Implemented;
}


int 
divert_pkdecrypt (GCRY_SEXP *s_plain, GCRY_SEXP s_cipher,
                  const char *shadow_info)
{
  int rc;
  char *kid;

  rc = ask_for_card (shadow_info, &kid);
  if (rc)
    return rc;

 
  xfree (kid);
  return GNUPG_Not_Implemented;
}



