/* learncard.c - Handle the LEARN command
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
#include "../assuan/assuan.h"

struct keypair_info_s {
  struct keypair_info_s *next;
  int no_cert;
  char *id;  /* points into grip */
  char hexgrip[1];
};
typedef struct keypair_info_s *KEYPAIR_INFO;

struct kpinfo_cb_parm_s {
  int error;
  KEYPAIR_INFO info;
};


static void
release_keypair_info (KEYPAIR_INFO info)
{
  while (info)
    {
      KEYPAIR_INFO tmp = info->next;
      xfree (info);
      info = tmp;
    }
}



/* This callback is used by agent_card_leanr and passed the content of
   all KEYPAIRINFO lines.  It merely store this data away */
static void
kpinfo_cb (void *opaque, const char *line)
{
  struct kpinfo_cb_parm_s *parm = opaque;
  KEYPAIR_INFO item;
  char *p;

  if (parm->error)
    return; /* no need to gather data after an error coccured */
  item = xtrycalloc (1, sizeof *item + strlen (line));
  if (!item)
    {
      parm->error = GNUPG_Out_Of_Core;
      return;
    }
  strcpy (item->hexgrip, line);
  for (p = item->hexgrip; hexdigitp (p); p++)
    ;
  if (p == item->hexgrip && *p == 'X' && spacep (p+1))
    {
      item->no_cert = 1;
      p++;
    }
  else if ((p - item->hexgrip) != 40 || !spacep (p))
    { /* not a 20 byte hex keygrip or not followed by a space */
      parm->error = GNUPG_Invalid_Response;
      xfree (item);
      return;
    }
  *p++ = 0;
  while (spacep (p))
    p++;
  item->id = p;
  while (*p && !spacep (p))
    p++;
  if (p == item->id)
    { /* invalid ID string */
      parm->error = GNUPG_Invalid_Response;
      xfree (item);
      return;
    }
  *p = 0; /* ignore trailing stuff */
  
  /* store it */
  item->next = parm->info;
  parm->info = item;
}


/* Create an S-expression with the shadow info.  */
static unsigned char *
make_shadow_info (const char *serialno, const char *idstring)
{
  const char *s;
  unsigned char *info, *p;
  char numbuf[21];
  int n;

  for (s=serialno, n=0; *s && s[1]; s += 2)
    n++;

  info = p = xtrymalloc (1 + 21 + n
                           + 21 + strlen (idstring) + 1 + 1);
  *p++ = '(';
  sprintf (numbuf, "%d:", n);
  p = stpcpy (p, numbuf);
  for (s=serialno; *s && s[1]; s += 2)
    *p++ = xtoi_2 (s);
  sprintf (numbuf, "%d:", strlen (idstring));
  p = stpcpy (p, numbuf);
  p = stpcpy (p, idstring);
  *p++ = ')';
  *p = 0;
  return info;
}


/* Perform the learn operation.  If ASSUAN_CONTEXT is not NULL all new
   certificates are send via Assuan */
int
agent_handle_learn (void *assuan_context)
{
  int rc;
  struct kpinfo_cb_parm_s parm;
  char *serialno = NULL;
  KEYPAIR_INFO item;
  unsigned char grip[20];
  char *p;
  int i;

  memset (&parm, 0, sizeof parm);

  /* Check whether a card is present and get the serial number */
  rc = agent_card_serialno (&serialno);
  if (rc)
    goto leave;

  /* now gather all the availabe info */
  rc = agent_card_learn (kpinfo_cb, &parm);
  if (!rc && parm.error)
    rc = parm.error;
  if (rc)
    {
      log_debug ("agent_card_learn failed: %s\n", gnupg_strerror (rc));
      goto leave;
    }

  log_info ("card has S/N: %s\n", serialno);
  for (item = parm.info; item; item = item->next)
    {
      unsigned char *pubkey, *shdkey;
      size_t n;

      if (opt.verbose)
        log_info ("          id: %s    (grip=%s)\n", item->id, item->hexgrip);

      if (item->no_cert)
        continue; /* no public key yet available */

      for (p=item->hexgrip, i=0; i < 20; p += 2, i++)
        grip[i] = xtoi_2 (p);
      
      if (!agent_key_available (grip))
        continue;
      
      /* unknown - store it */
      rc = agent_card_readkey (item->id, &pubkey);
      if (rc)
        {
          log_debug ("agent_card_readkey failed: %s\n", gnupg_strerror (rc));
          goto leave;
        }

      {
        unsigned char *shadow_info = make_shadow_info (serialno, item->id);
        if (!shadow_info)
          {
            rc = GNUPG_Out_Of_Core;
            xfree (pubkey);
            goto leave;
          }
        rc = agent_shadow_key (pubkey, shadow_info, &shdkey);
        xfree (shadow_info);
      }
      xfree (pubkey);
      if (rc)
        {
          log_error ("shadowing the key failed: %s\n", gnupg_strerror (rc));
          goto leave;
        }
      n = gcry_sexp_canon_len (shdkey, 0, NULL, NULL);
      assert (n);

      rc = agent_write_private_key (grip, shdkey, n, 0);
      xfree (shdkey);
      if (rc)
        {
          log_error ("error writing key: %s\n", gnupg_strerror (rc));
          goto leave;
        }

      if (opt.verbose)
        log_info ("stored\n");
      
      if (assuan_context)
        {
          char *derbuf;
          size_t derbuflen;

          rc = agent_card_readcert (item->id, &derbuf, &derbuflen);
          if (rc)
            {
              log_error ("error reading certificate: %s\n",
                         gnupg_strerror (rc));
              goto leave;
            }

          rc = assuan_send_data (assuan_context, derbuf, derbuflen);
          xfree (derbuf);
          if (!rc)
            rc = assuan_send_data (assuan_context, NULL, 0);
          if (!rc)
            rc = assuan_write_line (assuan_context, "END");
          if (rc)
            {
              log_error ("sending certificate failed: %s\n",
                         assuan_strerror (rc));
              rc = map_assuan_err (rc);
              goto leave;
            }
        }
    }

  
 leave:
  xfree (serialno);
  release_keypair_info (parm.info);
  return rc;
}


