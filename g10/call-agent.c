/* call-agent.c - Divert GPG operations to the agent.
 * Copyright (C) 2001, 2002, 2003, 2006, 2007,
 *               2008, 2009 Free Software Foundation, Inc.
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
#include <unistd.h>
#include <time.h>
#include <assert.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "gpg.h"
#include <assuan.h>
#include "util.h"
#include "membuf.h"
#include "options.h"
#include "i18n.h"
#include "asshelp.h"
#include "sysutils.h"
#include "call-agent.h"
#include "status.h"

#ifndef DBG_ASSUAN
# define DBG_ASSUAN 1
#endif

static assuan_context_t agent_ctx = NULL;
static int did_early_card_test;

struct cipher_parm_s
{
  assuan_context_t ctx;
  const char *ciphertext;
  size_t ciphertextlen;
};

struct writecert_parm_s
{
  assuan_context_t ctx;
  const unsigned char *certdata;
  size_t certdatalen;
};

struct writekey_parm_s
{
  assuan_context_t ctx;
  const unsigned char *keydata;
  size_t keydatalen;
};

struct genkey_parm_s
{
  assuan_context_t ctx;
  const char *sexp;
  size_t sexplen;
};

struct scd_genkey_parm_s
{
  struct agent_card_genkey_s *cgk;
  char *savedbytes;     /* Malloced space to save key parameter chunks.  */
};


static gpg_error_t learn_status_cb (void *opaque, const char *line);



/* If RC is not 0, write an appropriate status message. */
static void
status_sc_op_failure (int rc)
{
  switch (gpg_err_code (rc))
    {
    case 0:
      break;
    case GPG_ERR_CANCELED:
      write_status_text (STATUS_SC_OP_FAILURE, "1");
      break;
    case GPG_ERR_BAD_PIN:
      write_status_text (STATUS_SC_OP_FAILURE, "2");
      break;
    default:
      write_status (STATUS_SC_OP_FAILURE);
      break;
    }
}




/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
static int
start_agent (int for_card)
{
  int rc;

  /* Fixme: We need a context for each thread or serialize the access
     to the agent. */
  if (agent_ctx)
    rc = 0;
  else
    {
      rc = start_new_gpg_agent (&agent_ctx,
                                GPG_ERR_SOURCE_DEFAULT,
                                opt.homedir,
                                opt.agent_program,
                                opt.lc_ctype, opt.lc_messages,
                                opt.session_env,
                                opt.verbose, DBG_ASSUAN,
                                NULL, NULL);
      if (!rc)
        {
          /* Tell the agent that we support Pinentry notifications.
             No error checking so that it will work also with older
             agents.  */
          assuan_transact (agent_ctx, "OPTION allow-pinentry-notify",
                           NULL, NULL, NULL, NULL, NULL, NULL);
        }
    }

  if (!rc && for_card && !did_early_card_test)
    {
      /* Request the serial number of the card for an early test.  */
      struct agent_card_info_s info;

      memset (&info, 0, sizeof info);
      rc = assuan_transact (agent_ctx, "SCD SERIALNO openpgp",
                            NULL, NULL, NULL, NULL,
                            learn_status_cb, &info);
      if (rc)
        {
          switch (gpg_err_code (rc))
            {
            case GPG_ERR_NOT_SUPPORTED:
            case GPG_ERR_NO_SCDAEMON:
              write_status_text (STATUS_CARDCTRL, "6");
              break;
            default:
              write_status_text (STATUS_CARDCTRL, "4");
              log_info ("selecting openpgp failed: %s\n", gpg_strerror (rc));
              break;
            }
        }

      if (!rc && is_status_enabled () && info.serialno)
        {
          char *buf;

          buf = xasprintf ("3 %s", info.serialno);
          write_status_text (STATUS_CARDCTRL, buf);
          xfree (buf);
        }

      agent_release_card_info (&info);

      if (!rc)
        did_early_card_test = 1;
    }


  return rc;
}


/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary nul will
   silently be replaced by a 0xFF.  Function returns NULL to indicate
   an out of memory status. */
static char *
unescape_status_string (const unsigned char *s)
{
  return percent_plus_unescape (s, 0xff);
}


/* Take a 20 byte hexencoded string and put it into the the provided
   20 byte buffer FPR in binary format. */
static int
unhexify_fpr (const char *hexstr, unsigned char *fpr)
{
  const char *s;
  int n;

  for (s=hexstr, n=0; hexdigitp (s); s++, n++)
    ;
  if (*s || (n != 40))
    return 0; /* no fingerprint (invalid or wrong length). */
  for (s=hexstr, n=0; *s; s += 2, n++)
    fpr[n] = xtoi_2 (s);
  return 1; /* okay */
}

/* Take the serial number from LINE and return it verbatim in a newly
   allocated string.  We make sure that only hex characters are
   returned. */
static char *
store_serialno (const char *line)
{
  const char *s;
  char *p;

  for (s=line; hexdigitp (s); s++)
    ;
  p = xtrymalloc (s + 1 - line);
  if (p)
    {
      memcpy (p, line, s-line);
      p[s-line] = 0;
    }
  return p;
}



/* This is a dummy data line callback.  */
static gpg_error_t
dummy_data_cb (void *opaque, const void *buffer, size_t length)
{
  (void)opaque;
  (void)buffer;
  (void)length;
  return 0;
}

/* A simple callback used to return the serialnumber of a card.  */
static gpg_error_t
get_serialno_cb (void *opaque, const char *line)
{
  char **serialno = opaque;
  const char *keyword = line;
  const char *s;
  int keywordlen, n;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      if (*serialno)
        return gpg_error (GPG_ERR_CONFLICT); /* Unexpected status line. */
      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;
      if (!n || (n&1)|| !(spacep (s) || !*s) )
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      *serialno = xtrymalloc (n+1);
      if (!*serialno)
        return out_of_core ();
      memcpy (*serialno, line, n);
      (*serialno)[n] = 0;
    }

  return 0;
}


/* This is the default inquiry callback.  It mainly handles the
   Pinentry notifications.  */
static gpg_error_t
default_inq_cb (void *opaque, const char *line)
{
  (void)opaque;

  if (!strncmp (line, "PINENTRY_LAUNCHED", 17) && (line[17]==' '||!line[17]))
    {
      /* There is no working server mode yet thus we use
         AllowSetForegroundWindow window right here.  We might want to
         do this anyway in case gpg is called on the console. */
      gnupg_allow_set_foregound_window ((pid_t)strtoul (line+17, NULL, 10));
      /* We do not pass errors to avoid breaking other code.  */
    }
  else
    log_debug ("ignoring gpg-agent inquiry `%s'\n", line);

  return 0;
}



/* Release the card info structure INFO. */
void
agent_release_card_info (struct agent_card_info_s *info)
{
  if (!info)
    return;

  xfree (info->serialno); info->serialno = NULL;
  xfree (info->apptype); info->apptype = NULL;
  xfree (info->disp_name); info->disp_name = NULL;
  xfree (info->disp_lang); info->disp_lang = NULL;
  xfree (info->pubkey_url); info->pubkey_url = NULL;
  xfree (info->login_data); info->login_data = NULL;
  info->cafpr1valid = info->cafpr2valid = info->cafpr3valid = 0;
  info->fpr1valid = info->fpr2valid = info->fpr3valid = 0;
}

static gpg_error_t
learn_status_cb (void *opaque, const char *line)
{
  struct agent_card_info_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  int i;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      xfree (parm->serialno);
      parm->serialno = store_serialno (line);
      parm->is_v2 = (strlen (parm->serialno) >= 16
                     && xtoi_2 (parm->serialno+12) >= 2 );
    }
  else if (keywordlen == 7 && !memcmp (keyword, "APPTYPE", keywordlen))
    {
      xfree (parm->apptype);
      parm->apptype = unescape_status_string (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-NAME", keywordlen))
    {
      xfree (parm->disp_name);
      parm->disp_name = unescape_status_string (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-LANG", keywordlen))
    {
      xfree (parm->disp_lang);
      parm->disp_lang = unescape_status_string (line);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "DISP-SEX", keywordlen))
    {
      parm->disp_sex = *line == '1'? 1 : *line == '2' ? 2: 0;
    }
  else if (keywordlen == 10 && !memcmp (keyword, "PUBKEY-URL", keywordlen))
    {
      xfree (parm->pubkey_url);
      parm->pubkey_url = unescape_status_string (line);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "LOGIN-DATA", keywordlen))
    {
      xfree (parm->login_data);
      parm->login_data = unescape_status_string (line);
    }
  else if (keywordlen == 11 && !memcmp (keyword, "SIG-COUNTER", keywordlen))
    {
      parm->sig_counter = strtoul (line, NULL, 0);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "CHV-STATUS", keywordlen))
    {
      char *p, *buf;

      buf = p = unescape_status_string (line);
      if (buf)
        {
          while (spacep (p))
            p++;
          parm->chv1_cached = atoi (p);
          while (*p && !spacep (p))
            p++;
          while (spacep (p))
            p++;
          for (i=0; *p && i < 3; i++)
            {
              parm->chvmaxlen[i] = atoi (p);
              while (*p && !spacep (p))
                p++;
              while (spacep (p))
                p++;
            }
          for (i=0; *p && i < 3; i++)
            {
              parm->chvretry[i] = atoi (p);
              while (*p && !spacep (p))
                p++;
              while (spacep (p))
                p++;
            }
          xfree (buf);
        }
    }
  else if (keywordlen == 6 && !memcmp (keyword, "EXTCAP", keywordlen))
    {
      char *p, *p2, *buf;
      int abool;

      buf = p = unescape_status_string (line);
      if (buf)
        {
          for (p = strtok (buf, " "); p; p = strtok (NULL, " "))
            {
              p2 = strchr (p, '=');
              if (p2)
                {
                  *p2++ = 0;
                  abool = (*p2 == '1');
                  if (!strcmp (p, "ki"))
                    parm->extcap.ki = abool;
                  else if (!strcmp (p, "aac"))
                    parm->extcap.aac = abool;
                }
            }
          xfree (buf);
        }
    }
  else if (keywordlen == 7 && !memcmp (keyword, "KEY-FPR", keywordlen))
    {
      int no = atoi (line);
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->fpr1valid = unhexify_fpr (line, parm->fpr1);
      else if (no == 2)
        parm->fpr2valid = unhexify_fpr (line, parm->fpr2);
      else if (no == 3)
        parm->fpr3valid = unhexify_fpr (line, parm->fpr3);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "KEY-TIME", keywordlen))
    {
      int no = atoi (line);
      while (* line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->fpr1time = strtoul (line, NULL, 10);
      else if (no == 2)
        parm->fpr2time = strtoul (line, NULL, 10);
      else if (no == 3)
        parm->fpr3time = strtoul (line, NULL, 10);
    }
  else if (keywordlen == 6 && !memcmp (keyword, "CA-FPR", keywordlen))
    {
      int no = atoi (line);
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->cafpr1valid = unhexify_fpr (line, parm->cafpr1);
      else if (no == 2)
        parm->cafpr2valid = unhexify_fpr (line, parm->cafpr2);
      else if (no == 3)
        parm->cafpr3valid = unhexify_fpr (line, parm->cafpr3);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "KEY-ATTR", keywordlen))
    {
      int keyno, algo, nbits;

      sscanf (line, "%d %d %d", &keyno, &algo, &nbits);
      keyno--;
      if (keyno >= 0 && keyno < DIM (parm->key_attr))
        {
          parm->key_attr[keyno].algo = algo;
          parm->key_attr[keyno].nbits = nbits;
        }
    }

  return 0;
}

/* Call the agent to learn about a smartcard */
int
agent_learn (struct agent_card_info_s *info)
{
  int rc;

  rc = start_agent (1);
  if (rc)
    return rc;

  /* Send the serialno command to initialize the connection.  We don't
     care about the data returned.  If the card has already been
     initialized, this is a very fast command.  The main reason we
     need to do this here is to handle a card removed case so that an
     "l" command in --card-edit can be used to show ta newly inserted
     card.  We request the openpgp card because that is what we
     expect. */
  rc = assuan_transact (agent_ctx, "SCD SERIALNO openpgp",
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;


  memset (info, 0, sizeof *info);
  rc = assuan_transact (agent_ctx, "SCD LEARN --force",
                        dummy_data_cb, NULL, default_inq_cb, NULL,
                        learn_status_cb, info);
  /* Also try to get the key attributes.  */
  if (!rc)
    agent_scd_getattr ("KEY-ATTR", info);

  return rc;
}

/* Call the agent to retrieve a data object.  This function returns
   the data in the same structure as used by the learn command.  It is
   allowed to update such a structure using this commmand. */
int
agent_scd_getattr (const char *name, struct agent_card_info_s *info)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  if (!*name)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* We assume that NAME does not need escaping. */
  if (12 + strlen (name) > DIM(line)-1)
    return gpg_error (GPG_ERR_TOO_LARGE);
  stpcpy (stpcpy (line, "SCD GETATTR "), name);

  rc = start_agent (1);
  if (rc)
    return rc;

  rc = assuan_transact (agent_ctx, line, NULL, NULL, default_inq_cb, NULL,
                        learn_status_cb, info);

  return rc;
}


/* Send an setattr command to the SCdaemon.  SERIALNO is not actually
   used here but required by gpg 1.4's implementation of this code in
   cardglue.c. */
int
agent_scd_setattr (const char *name,
                   const unsigned char *value, size_t valuelen,
                   const char *serialno)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  char *p;

  (void)serialno;

  if (!*name || !valuelen)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* We assume that NAME does not need escaping. */
  if (12 + strlen (name) > DIM(line)-1)
    return gpg_error (GPG_ERR_TOO_LARGE);

  p = stpcpy (stpcpy (line, "SCD SETATTR "), name);
  *p++ = ' ';
  for (; valuelen; value++, valuelen--)
    {
      if (p >= line + DIM(line)-5 )
        return gpg_error (GPG_ERR_TOO_LARGE);
      if (*value < ' ' || *value == '+' || *value == '%')
        {
          sprintf (p, "%%%02X", *value);
          p += 3;
        }
      else if (*value == ' ')
        *p++ = '+';
      else
        *p++ = *value;
    }
  *p = 0;

  rc = start_agent (1);
  if (!rc)
    {
      rc = assuan_transact (agent_ctx, line, NULL, NULL,
                            default_inq_cb, NULL, NULL, NULL);
    }

  status_sc_op_failure (rc);
  return rc;
}



/* Handle a CERTDATA inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the END
   command. */
static gpg_error_t
inq_writecert_parms (void *opaque, const char *line)
{
  int rc;
  struct writecert_parm_s *parm = opaque;

  if (!strncmp (line, "CERTDATA", 8) && (line[8]==' '||!line[8]))
    {
      rc = assuan_send_data (parm->ctx, parm->certdata, parm->certdatalen);
    }
  else
    rc = default_inq_cb (opaque, line);

  return rc;
}


/* Send a WRITECERT command to the SCdaemon. */
int
agent_scd_writecert (const char *certidstr,
                     const unsigned char *certdata, size_t certdatalen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct writecert_parm_s parms;

  rc = start_agent (1);
  if (rc)
    return rc;

  memset (&parms, 0, sizeof parms);

  snprintf (line, DIM(line)-1, "SCD WRITECERT %s", certidstr);
  line[DIM(line)-1] = 0;
  parms.ctx = agent_ctx;
  parms.certdata = certdata;
  parms.certdatalen = certdatalen;

  rc = assuan_transact (agent_ctx, line, NULL, NULL,
                        inq_writecert_parms, &parms, NULL, NULL);

  return rc;
}



/* Handle a KEYDATA inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static gpg_error_t
inq_writekey_parms (void *opaque, const char *line)
{
  int rc;
  struct writekey_parm_s *parm = opaque;

  if (!strncmp (line, "KEYDATA", 7) && (line[7]==' '||!line[7]))
    {
      rc = assuan_send_data (parm->ctx, parm->keydata, parm->keydatalen);
    }
  else
    rc = default_inq_cb (opaque, line);

  return rc;
}


/* Send a WRITEKEY command to the SCdaemon. */
int
agent_scd_writekey (int keyno, const char *serialno,
                    const unsigned char *keydata, size_t keydatalen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct writekey_parm_s parms;

  (void)serialno;

  rc = start_agent (1);
  if (rc)
    return rc;

  memset (&parms, 0, sizeof parms);

  snprintf (line, DIM(line)-1, "SCD WRITEKEY --force OPENPGP.%d", keyno);
  line[DIM(line)-1] = 0;
  parms.ctx = agent_ctx;
  parms.keydata = keydata;
  parms.keydatalen = keydatalen;

  rc = assuan_transact (agent_ctx, line, NULL, NULL,
                        inq_writekey_parms, &parms, NULL, NULL);

  status_sc_op_failure (rc);
  return rc;
}



static gpg_error_t
scd_genkey_cb_append_savedbytes (struct scd_genkey_parm_s *parm,
                                 const char *line)
{
  gpg_error_t err = 0;
  char *p;

  if (!parm->savedbytes)
    {
      parm->savedbytes = xtrystrdup (line);
      if (!parm->savedbytes)
        err = gpg_error_from_syserror ();
    }
  else
    {
      p = xtrymalloc (strlen (parm->savedbytes) + strlen (line) + 1);
      if (!p)
        err = gpg_error_from_syserror ();
      else
        {
          strcpy (stpcpy (p, parm->savedbytes), line);
          xfree (parm->savedbytes);
          parm->savedbytes = p;
        }
    }

  return err;
}


/* Status callback for the SCD GENKEY command. */
static gpg_error_t
scd_genkey_cb (void *opaque, const char *line)
{
  struct scd_genkey_parm_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  gpg_error_t rc = 0;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 7 && !memcmp (keyword, "KEY-FPR", keywordlen))
    {
      parm->cgk->fprvalid = unhexify_fpr (line, parm->cgk->fpr);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "KEY-DATA", keywordlen))
    {
      gcry_mpi_t a;
      const char *name = line;

      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;

      if (*name == '-' && spacep (name+1))
        rc = scd_genkey_cb_append_savedbytes (parm, line);
      else
        {
          if (parm->savedbytes)
            {
              rc = scd_genkey_cb_append_savedbytes (parm, line);
              if (!rc)
                rc = gcry_mpi_scan (&a, GCRYMPI_FMT_HEX,
                                    parm->savedbytes, 0, NULL);
            }
          else
            rc = gcry_mpi_scan (&a, GCRYMPI_FMT_HEX, line, 0, NULL);
          if (rc)
            log_error ("error parsing received key data: %s\n",
                       gpg_strerror (rc));
          else if (*name == 'n' && spacep (name+1))
            parm->cgk->n = a;
          else if (*name == 'e' && spacep (name+1))
            parm->cgk->e = a;
          else
            {
              log_info ("unknown parameter name in received key data\n");
              gcry_mpi_release (a);
              rc = gpg_error (GPG_ERR_INV_PARAMETER);
            }

          xfree (parm->savedbytes);
          parm->savedbytes = NULL;
        }
    }
  else if (keywordlen == 14 && !memcmp (keyword,"KEY-CREATED-AT", keywordlen))
    {
      parm->cgk->created_at = (u32)strtoul (line, NULL, 10);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "PROGRESS", keywordlen))
    {
      write_status_text (STATUS_PROGRESS, line);
    }

  return rc;
}

/* Send a GENKEY command to the SCdaemon.  SERIALNO is not used in
   this implementation.  If CREATEDATE has been given, it will be
   passed to SCDAEMON so that the key can be created with this
   timestamp; note the user needs to use the returned timestamp as old
   versions of scddaemon don't support this option.  */
int
agent_scd_genkey (struct agent_card_genkey_s *info, int keyno, int force,
                  const char *serialno, u32 createtime)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  gnupg_isotime_t tbuf;
  struct scd_genkey_parm_s parms;

  (void)serialno;

  memset (&parms, 0, sizeof parms);
  parms.cgk = info;

  rc = start_agent (1);
  if (rc)
    return rc;

  if (createtime)
    epoch2isotime (tbuf, createtime);
  else
    *tbuf = 0;

  memset (info, 0, sizeof *info);
  snprintf (line, DIM(line)-1, "SCD GENKEY %s%s %s %d",
            *tbuf? "--timestamp=":"", tbuf,
            force? "--force":"",
            keyno);
  line[DIM(line)-1] = 0;

  memset (info, 0, sizeof *info);
  rc = assuan_transact (agent_ctx, line,
                        NULL, NULL, default_inq_cb, NULL,
                        scd_genkey_cb, &parms);

  xfree (parms.savedbytes);

  status_sc_op_failure (rc);
  return rc;
}




/* Issue an SCD SERIALNO openpgp command and if SERIALNO is not NULL
   ask the user to insert the requested card.  */
gpg_error_t
select_openpgp (const char *serialno)
{
  gpg_error_t err;

  /* Send the serialno command to initialize the connection.  Without
     a given S/N we don't care about the data returned.  If the card
     has already been initialized, this is a very fast command.  We
     request the openpgp card because that is what we expect.

     Note that an opt.limit_card_insert_tries of 1 means: No tries at
     all whereas 0 means do not limit the number of tries.  Due to the
     sue of a pinentry prompt with a cancel option we use it here in a
     boolean sense.  */
  if (!serialno || opt.limit_card_insert_tries == 1)
    err = assuan_transact (agent_ctx, "SCD SERIALNO openpgp",
                           NULL, NULL, NULL, NULL, NULL, NULL);
  else
    {
      char *this_sn = NULL;
      char *desc;
      int ask;
      char *want_sn;
      char *p;

      want_sn = xtrystrdup (serialno);
      if (!want_sn)
        return gpg_error_from_syserror ();
      p = strchr (want_sn, '/');
      if (p)
        *p = 0;

      do
        {
          ask = 0;
          err = assuan_transact (agent_ctx, "SCD SERIALNO openpgp",
                                 NULL, NULL, NULL, NULL,
                                 get_serialno_cb, &this_sn);
          if (gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT)
            ask = 1;
          else if (gpg_err_code (err) == GPG_ERR_NOT_SUPPORTED)
            ask = 2;
          else if (err)
            ;
          else if (this_sn)
            {
              if (strcmp (want_sn, this_sn))
                ask = 2;
            }

          xfree (this_sn);
          this_sn = NULL;

          if (ask)
            {
              char *formatted = NULL;
              char *ocodeset = i18n_switchto_utf8 ();

              if (!strncmp (want_sn, "D27600012401", 12)
                  && strlen (want_sn) == 32 )
                formatted = xtryasprintf ("(%.4s) %.8s",
                                          want_sn + 16, want_sn + 20);

              err = 0;
              desc = xtryasprintf
                ("%s:\n\n"
                 "  \"%s\"",
                 ask == 1
                 ? _("Please insert the card with serial number")
                 : _("Please remove the current card and "
                     "insert the one with serial number"),
                 formatted? formatted : want_sn);
              if (!desc)
                err = gpg_error_from_syserror ();
              xfree (formatted);
              i18n_switchback (ocodeset);
              if (!err)
                err = gpg_agent_get_confirmation (desc);
              xfree (desc);
            }
        }
      while (ask && !err);
      xfree (want_sn);
    }

  return err;
}



static gpg_error_t
membuf_data_cb (void *opaque, const void *buffer, size_t length)
{
  membuf_t *data = opaque;

  if (buffer)
    put_membuf (data, buffer, length);
  return 0;
}


/* Helper returning a command option to describe the used hash
   algorithm.  See scd/command.c:cmd_pksign.  */
static const char *
hash_algo_option (int algo)
{
  switch (algo)
    {
    case GCRY_MD_RMD160: return "--hash=rmd160";
    case GCRY_MD_SHA1  : return "--hash=sha1";
    case GCRY_MD_SHA224: return "--hash=sha224";
    case GCRY_MD_SHA256: return "--hash=sha256";
    case GCRY_MD_SHA384: return "--hash=sha384";
    case GCRY_MD_SHA512: return "--hash=sha512";
    case GCRY_MD_MD5   : return "--hash=md5";
    default:             return "";
    }
}

/* Send a sign command to the scdaemon via gpg-agent's pass thru
   mechanism. */
int
agent_scd_pksign (const char *serialno, int hashalgo,
                  const unsigned char *indata, size_t indatalen,
                  unsigned char **r_buf, size_t *r_buflen)
{
  int rc, i;
  char *p, line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;

  /* Note, hashalgo is not yet used but hardwired to SHA1 in SCdaemon. */

  *r_buf = NULL;
  *r_buflen = 0;

  rc = start_agent (1);
  if (gpg_err_code (rc) == GPG_ERR_CARD_NOT_PRESENT
      || gpg_err_code (rc) == GPG_ERR_NOT_SUPPORTED)
    rc = 0; /* We check later.  */
  if (rc)
    return rc;

  if (indatalen*2 + 50 > DIM(line))
    return gpg_error (GPG_ERR_GENERAL);

  rc = select_openpgp (serialno);
  if (rc)
    return rc;

  sprintf (line, "SCD SETDATA ");
  p = line + strlen (line);
  for (i=0; i < indatalen ; i++, p += 2 )
    sprintf (p, "%02X", indata[i]);
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
#if 0
  if (!hashalgo) /* Temporary test hack. */
    snprintf (line, DIM(line)-1, "SCD PKAUTH %s", serialno);
  else
#endif
    snprintf (line, DIM(line)-1, "SCD PKSIGN %s %s",
              hash_algo_option (hashalgo), serialno);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line, membuf_data_cb, &data,
                        default_inq_cb, NULL, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
    }
  else
    *r_buf = get_membuf (&data, r_buflen);

  status_sc_op_failure (rc);
  return rc;
}


/* Decrypt INDATA of length INDATALEN using the card identified by
   SERIALNO.  Return the plaintext in a newly allocated buffer stored
   at the address of R_BUF.

   Note, we currently support only RSA or more exactly algorithms
   taking one input data element. */
int
agent_scd_pkdecrypt (const char *serialno,
                     const unsigned char *indata, size_t indatalen,
                     unsigned char **r_buf, size_t *r_buflen)
{
  int rc, i;
  char *p, line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;

  *r_buf = NULL;
  rc = start_agent (1);
  if (gpg_err_code (rc) == GPG_ERR_CARD_NOT_PRESENT
      || gpg_err_code (rc) == GPG_ERR_NOT_SUPPORTED)
    rc = 0; /* We check later.  */
  if (rc)
    return rc;

  /* FIXME: use secure memory where appropriate */

  rc = select_openpgp (serialno);
  if (rc)
    return rc;

  for (len = 0; len < indatalen;)
    {
      p = stpcpy (line, "SCD SETDATA ");
      if (len)
        p = stpcpy (p, "--append ");
      for (i=0; len < indatalen && (i*2 < DIM(line)-50); i++, len++)
        {
          sprintf (p, "%02X", indata[len]);
          p += 2;
        }
      rc = assuan_transact (agent_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return rc;
    }

  init_membuf (&data, 1024);
  snprintf (line, DIM(line)-1, "SCD PKDECRYPT %s", serialno);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line,
                        membuf_data_cb, &data,
                        default_inq_cb, NULL, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
    }
  else
    {
      *r_buf = get_membuf (&data, r_buflen);
      if (!*r_buf)
        rc = gpg_error (GPG_ERR_ENOMEM);
    }

  status_sc_op_failure (rc);
  return rc;
}



/* Send a READCERT command to the SCdaemon. */
int
agent_scd_readcert (const char *certidstr,
                    void **r_buf, size_t *r_buflen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;

  *r_buf = NULL;
  rc = start_agent (1);
  if (rc)
    return rc;

  init_membuf (&data, 2048);

  snprintf (line, DIM(line)-1, "SCD READCERT %s", certidstr);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line,
                        membuf_data_cb, &data,
                        default_inq_cb, NULL, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }
  *r_buf = get_membuf (&data, r_buflen);
  if (!*r_buf)
    return gpg_error (GPG_ERR_ENOMEM);

  return 0;
}



/* Change the PIN of an OpenPGP card or reset the retry counter.
   CHVNO 1: Change the PIN
         2: For v1 cards: Same as 1.
            For v2 cards: Reset the PIN using the Reset Code.
         3: Change the admin PIN
       101: Set a new PIN and reset the retry counter
       102: For v1 cars: Same as 101.
            For v2 cards: Set a new Reset Code.
   SERIALNO is not used.
 */
int
agent_scd_change_pin (int chvno, const char *serialno)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  const char *reset = "";

  (void)serialno;

  if (chvno >= 100)
    reset = "--reset";
  chvno %= 100;

  rc = start_agent (1);
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "SCD PASSWD %s %d", reset, chvno);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line, NULL, NULL,
                        default_inq_cb, NULL, NULL, NULL);
  status_sc_op_failure (rc);
  return rc;
}


/* Perform a CHECKPIN operation.  SERIALNO should be the serial
   number of the card - optionally followed by the fingerprint;
   however the fingerprint is ignored here. */
int
agent_scd_checkpin  (const char *serialno)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  rc = start_agent (1);
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "SCD CHECKPIN %s", serialno);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line,
                        NULL, NULL,
                        default_inq_cb, NULL, NULL, NULL);
  status_sc_op_failure (rc);
  return rc;
}


/* Dummy function, only used by the gpg 1.4 implementation. */
void
agent_clear_pin_cache (const char *sn)
{
  (void)sn;
}




/* Note: All strings shall be UTF-8. On success the caller needs to
   free the string stored at R_PASSPHRASE. On error NULL will be
   stored at R_PASSPHRASE and an appropriate fpf error code
   returned. */
gpg_error_t
agent_get_passphrase (const char *cache_id,
                      const char *err_msg,
                      const char *prompt,
                      const char *desc_msg,
                      int repeat,
                      int check,
                      char **r_passphrase)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  char *arg1 = NULL;
  char *arg2 = NULL;
  char *arg3 = NULL;
  char *arg4 = NULL;
  membuf_t data;

  *r_passphrase = NULL;

  rc = start_agent (0);
  if (rc)
    return rc;

  /* Check that the gpg-agent understands the repeat option.  */
  if (assuan_transact (agent_ctx,
                       "GETINFO cmd_has_option GET_PASSPHRASE repeat",
                       NULL, NULL, NULL, NULL, NULL, NULL))
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  if (cache_id && *cache_id)
    if (!(arg1 = percent_plus_escape (cache_id)))
      goto no_mem;
  if (err_msg && *err_msg)
    if (!(arg2 = percent_plus_escape (err_msg)))
      goto no_mem;
  if (prompt && *prompt)
    if (!(arg3 = percent_plus_escape (prompt)))
      goto no_mem;
  if (desc_msg && *desc_msg)
    if (!(arg4 = percent_plus_escape (desc_msg)))
      goto no_mem;

  snprintf (line, DIM(line)-1,
            "GET_PASSPHRASE --data --repeat=%d%s -- %s %s %s %s",
            repeat,
            check? " --check --qualitybar":"",
            arg1? arg1:"X",
            arg2? arg2:"X",
            arg3? arg3:"X",
            arg4? arg4:"X");
  line[DIM(line)-1] = 0;
  xfree (arg1);
  xfree (arg2);
  xfree (arg3);
  xfree (arg4);

  init_membuf_secure (&data, 64);
  rc = assuan_transact (agent_ctx, line,
                        membuf_data_cb, &data,
                        default_inq_cb, NULL, NULL, NULL);

  if (rc)
    xfree (get_membuf (&data, NULL));
  else
    {
      put_membuf (&data, "", 1);
      *r_passphrase = get_membuf (&data, NULL);
      if (!*r_passphrase)
        rc = gpg_error_from_syserror ();
    }
  return rc;
 no_mem:
  rc = gpg_error_from_syserror ();
  xfree (arg1);
  xfree (arg2);
  xfree (arg3);
  xfree (arg4);
  return rc;
}


gpg_error_t
agent_clear_passphrase (const char *cache_id)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  if (!cache_id || !*cache_id)
    return 0;

  rc = start_agent (0);
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "CLEAR_PASSPHRASE %s", cache_id);
  line[DIM(line)-1] = 0;
  return assuan_transact (agent_ctx, line, NULL, NULL,
                          default_inq_cb, NULL, NULL, NULL);
}


/* Ask the agent to pop up a confirmation dialog with the text DESC
   and an okay and cancel button. */
gpg_error_t
gpg_agent_get_confirmation (const char *desc)
{
  int rc;
  char *tmp;
  char line[ASSUAN_LINELENGTH];

  rc = start_agent (0);
  if (rc)
    return rc;

  tmp = percent_plus_escape (desc);
  if (!tmp)
    return gpg_error_from_syserror ();
  snprintf (line, DIM(line)-1, "GET_CONFIRMATION %s", tmp);
  line[DIM(line)-1] = 0;
  xfree (tmp);

  rc = assuan_transact (agent_ctx, line, NULL, NULL,
                        default_inq_cb, NULL, NULL, NULL);
  return rc;
}


/* Return the S2K iteration count as computed by gpg-agent.  */
gpg_error_t
agent_get_s2k_count (unsigned long *r_count)
{
  gpg_error_t err;
  membuf_t data;
  char *buf;

  *r_count = 0;

  err = start_agent (0);
  if (err)
    return err;

  init_membuf (&data, 32);
  err = assuan_transact (agent_ctx, "GETINFO s2k_count",
                        membuf_data_cb, &data,
                        NULL, NULL, NULL, NULL);
  if (err)
    xfree (get_membuf (&data, NULL));
  else
    {
      put_membuf (&data, "", 1);
      buf = get_membuf (&data, NULL);
      if (!buf)
        err = gpg_error_from_syserror ();
      else
        {
          *r_count = strtoul (buf, NULL, 10);
          xfree (buf);
        }
    }
  return err;
}

