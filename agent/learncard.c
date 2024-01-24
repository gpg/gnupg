/* learncard.c - Handle the LEARN command
 * Copyright (C) 2002, 2003, 2004, 2009 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
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
#include <assuan.h>

/* Structures used by the callback mechanism to convey information
   pertaining to key pairs.  */
struct keypair_info_s
{
  struct keypair_info_s *next;
  int no_cert;
  char *id;          /* points into grip */
  char hexgrip[1];   /* The keygrip (i.e. a hash over the public key
                        parameters) formatted as a hex string.
                        Allocated somewhat large to also act as
                        memeory for the above ID field. */
};
typedef struct keypair_info_s *KEYPAIR_INFO;

struct kpinfo_cb_parm_s
{
  ctrl_t ctrl;
  int error;
  KEYPAIR_INFO info;
};


/* Structures used by the callback mechanism to convey information
   pertaining to certificates.  */
struct certinfo_s {
  struct certinfo_s *next;
  int type;
  int done;
  char id[1];
};
typedef struct certinfo_s *CERTINFO;

struct certinfo_cb_parm_s
{
  ctrl_t ctrl;
  int error;
  CERTINFO info;
};


/* Structures used by the callback mechanism to convey assuan status
   lines.  */
struct sinfo_s {
  struct sinfo_s *next;
  char *data;       /* Points into keyword. */
  char keyword[1];
};
typedef struct sinfo_s *SINFO;

struct sinfo_cb_parm_s {
  int error;
  SINFO info;
};


/* Destructor for key information objects. */
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

/* Destructor for certificate information objects. */
static void
release_certinfo (CERTINFO info)
{
  while (info)
    {
      CERTINFO tmp = info->next;
      xfree (info);
      info = tmp;
    }
}

/* Destructor for status information objects. */
static void
release_sinfo (SINFO info)
{
  while (info)
    {
      SINFO tmp = info->next;
      xfree (info);
      info = tmp;
    }
}



/* This callback is used by agent_card_learn and passed the content of
   all KEYPAIRINFO lines.  It merely stores this data away */
static void
kpinfo_cb (void *opaque, const char *line)
{
  struct kpinfo_cb_parm_s *parm = opaque;
  KEYPAIR_INFO item;
  char *p;

  if (parm->error)
    return; /* no need to gather data after an error occurred */

  if ((parm->error = agent_write_status (parm->ctrl, "PROGRESS",
                                         "learncard", "k", "0", "0", NULL)))
    return;

  item = xtrycalloc (1, sizeof *item + strlen (line));
  if (!item)
    {
      parm->error = out_of_core ();
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
      parm->error = gpg_error (GPG_ERR_INV_RESPONSE);
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
      parm->error = gpg_error (GPG_ERR_INV_RESPONSE);
      xfree (item);
      return;
    }
  *p = 0; /* ignore trailing stuff */

  /* store it */
  item->next = parm->info;
  parm->info = item;
}


/* This callback is used by agent_card_learn and passed the content of
   all CERTINFO lines.  It merely stores this data away */
static void
certinfo_cb (void *opaque, const char *line)
{
  struct certinfo_cb_parm_s *parm = opaque;
  CERTINFO item;
  int type;
  char *p, *pend;

  if (parm->error)
    return; /* no need to gather data after an error occurred */

  if ((parm->error = agent_write_status (parm->ctrl, "PROGRESS",
                                         "learncard", "c", "0", "0", NULL)))
    return;

  type = strtol (line, &p, 10);
  while (spacep (p))
    p++;
  for (pend = p; *pend && !spacep (pend); pend++)
    ;
  if (p == pend || !*p)
    {
      parm->error = gpg_error (GPG_ERR_INV_RESPONSE);
      return;
    }
  *pend = 0; /* ignore trailing stuff */

  item = xtrycalloc (1, sizeof *item + strlen (p));
  if (!item)
    {
      parm->error = out_of_core ();
      return;
    }
  item->type = type;
  strcpy (item->id, p);
  /* store it */
  item->next = parm->info;
  parm->info = item;
}


/* This callback is used by agent_card_learn and passed the content of
   all SINFO lines.  It merely stores this data away */
static void
sinfo_cb (void *opaque, const char *keyword, size_t keywordlen,
          const char *data)
{
  struct sinfo_cb_parm_s *sparm = opaque;
  SINFO item;

  if (sparm->error)
    return; /* no need to gather data after an error occurred */

  item = xtrycalloc (1, sizeof *item + keywordlen + 1 + strlen (data));
  if (!item)
    {
      sparm->error = out_of_core ();
      return;
    }
  memcpy (item->keyword, keyword, keywordlen);
  item->data = item->keyword + keywordlen;
  *item->data = 0;
  item->data++;
  strcpy (item->data, data);
  /* store it */
  item->next = sparm->info;
  sparm->info = item;
}



static int
send_cert_back (ctrl_t ctrl, const char *id, void *assuan_context)
{
  int rc;
  char *derbuf;
  size_t derbuflen;

  rc = agent_card_readcert (ctrl, id, &derbuf, &derbuflen);
  if (rc)
    {
      const char *action;

      switch (gpg_err_code (rc))
        {
        case GPG_ERR_INV_ID:
        case GPG_ERR_NOT_FOUND:
          action = " - ignored";
          break;
        default:
          action = "";
          break;
        }
      if (opt.verbose || !*action)
        log_info ("error reading certificate '%s': %s%s\n",
                  id? id:"?", gpg_strerror (rc), action);

      return *action? 0 : rc;
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
                 gpg_strerror (rc));
      return rc;
    }
  return 0;
}

/* Perform the learn operation.  If ASSUAN_CONTEXT is not NULL and
   SEND is true all new certificates are send back via Assuan.  If
   REALLYFORCE is true a private key will be overwritten by a stub
   key. */
int
agent_handle_learn (ctrl_t ctrl, int send, void *assuan_context,
                    int force, int reallyforce)
{
  int rc;
  struct kpinfo_cb_parm_s parm;
  struct certinfo_cb_parm_s cparm;
  struct sinfo_cb_parm_s sparm;
  const char *serialno = NULL;
  KEYPAIR_INFO item;
  SINFO sitem;
  unsigned char grip[20];
  char *p;
  int i;
  static int certtype_list[] = {
    111, /* Root CA */
    101, /* trusted */
    102, /* useful */
    100, /* regular */
    /* We don't include 110 here because gpgsm can't handle that
       special root CA format. */
    -1 /* end of list */
  };


  memset (&parm, 0, sizeof parm);
  memset (&cparm, 0, sizeof cparm);
  memset (&sparm, 0, sizeof sparm);
  parm.ctrl = ctrl;
  cparm.ctrl = ctrl;

  /* Now gather all the available info. */
  rc = agent_card_learn (ctrl, kpinfo_cb, &parm, certinfo_cb, &cparm,
                         sinfo_cb, &sparm);
  if (!rc && (parm.error || cparm.error || sparm.error))
    rc = parm.error? parm.error : cparm.error? cparm.error : sparm.error;
  if (rc)
    {
      log_debug ("agent_card_learn failed: %s\n", gpg_strerror (rc));
      goto leave;
    }

  /* Pass on all the collected status information. */
  for (sitem = sparm.info; sitem; sitem = sitem->next)
    {
      if (!strcmp (sitem->keyword, "SERIALNO"))
        serialno = sitem->data;
      if (assuan_context)
        assuan_write_status (assuan_context, sitem->keyword, sitem->data);
    }

  if (!serialno)
    {
      rc = GPG_ERR_NOT_FOUND;
      goto leave;
    }

  log_info ("card has S/N: %s\n", serialno);

  /* Write out the certificates in a standard order. */
  for (i=0; certtype_list[i] != -1; i++)
    {
      CERTINFO citem;
      for (citem = cparm.info; citem; citem = citem->next)
        {
          if (certtype_list[i] != citem->type)
            continue;

          if (opt.verbose)
            log_info ("          id: %s    (type=%d)\n",
                      citem->id, citem->type);

          if (assuan_context && send)
            {
              rc = send_cert_back (ctrl, citem->id, assuan_context);
              if (rc)
                goto leave;
              citem->done = 1;
            }
        }
    }

  for (item = parm.info; item; item = item->next)
    {
      unsigned char *pubkey;

      if (opt.verbose)
        log_info ("          id: %s    (grip=%s)\n", item->id, item->hexgrip);

      if (item->no_cert)
        continue; /* No public key yet available. */

      if (assuan_context)
        {
          agent_write_status (ctrl, "KEYPAIRINFO",
                              item->hexgrip, item->id, NULL);
        }

      for (p=item->hexgrip, i=0; i < 20; p += 2, i++)
        grip[i] = xtoi_2 (p);

      if (!force && !agent_key_available (grip))
        continue; /* The key is already available. */

      /* Unknown key - store it. */
      rc = agent_card_readkey (ctrl, item->id, &pubkey);
      if (rc)
        {
          log_debug ("agent_card_readkey failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      {
        char *dispserialno;

        agent_card_getattr (ctrl, "$DISPSERIALNO", &dispserialno);
        rc = agent_write_shadow_key (grip, serialno, item->id, pubkey,
                                     force, reallyforce, dispserialno);
        xfree (dispserialno);
      }
      xfree (pubkey);
      if (rc)
        goto leave;

      if (opt.verbose)
        log_info ("          id: %s - shadow key created\n", item->id);

      if (assuan_context && send)
        {
          CERTINFO citem;

          /* only send the certificate if we have not done so before */
          for (citem = cparm.info; citem; citem = citem->next)
            {
              if (!strcmp (citem->id, item->id))
                break;
            }
          if (!citem)
            {
              rc = send_cert_back (ctrl, item->id, assuan_context);
              if (rc)
                goto leave;
            }
        }
    }


 leave:
  release_keypair_info (parm.info);
  release_certinfo (cparm.info);
  release_sinfo (sparm.info);
  return rc;
}
