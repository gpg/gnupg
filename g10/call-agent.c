/* call-agent.c - divert operations to the agent
 * Copyright (C) 2001, 2002, 2003, 2006 Free Software Foundation, Inc.
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
#include <assuan.h>

#include "gpg.h"
#include "util.h"
#include "membuf.h"
#include "options.h"
#include "i18n.h"
#include "asshelp.h"
#include "call-agent.h"

#ifndef DBG_ASSUAN
# define DBG_ASSUAN 1
#endif

static assuan_context_t agent_ctx = NULL;

struct cipher_parm_s 
{
  assuan_context_t ctx;
  const char *ciphertext;
  size_t ciphertextlen;
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



/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
static int
start_agent (void)
{
  if (agent_ctx)
    return 0; /* Fixme: We need a context for each thread or serialize
                 the access to the agent. */

  return start_new_gpg_agent (&agent_ctx,
                              GPG_ERR_SOURCE_DEFAULT,
                              opt.homedir,
                              opt.agent_program,
                              opt.display, opt.ttyname, opt.ttytype,
                              opt.lc_ctype, opt.lc_messages,
                              opt.verbose, DBG_ASSUAN,
                              NULL, NULL);
}


/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary nul will
   silently be replaced by a 0xFF.  Function returns NULL to indicate
   an out of memory status. */
static char *
unescape_status_string (const unsigned char *s)
{
  char *buffer, *d;

  buffer = d = xtrymalloc (strlen (s)+1);
  if (!buffer)
    return NULL;
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        { 
          s++;
          *d = xtoi_2 (s);
          if (!*d)
            *d = '\xff';
          d++;
          s += 2;
        }
      else if (*s == '+')
        {
          *d++ = ' ';
          s++;
        }
      else
        *d++ = *s++;
    }
  *d = 0; 
  return buffer;
}

/* Copy the text ATEXT into the buffer P and do plus '+' and percent
   escaping.  Note that the provided buffer needs to be 3 times the
   size of ATEXT plus 1.  Returns a pointer to the leading Nul in P. */
static char *
percent_plus_escape (char *p, const char *atext)
{
  const unsigned char *s;

  for (s=atext; *s; s++)
    {
      if (*s < ' ' || *s == '+')
        {
          sprintf (p, "%%%02X", *s);
          p += 3;
        }
      else if (*s == ' ')
        *p++ = '+';
      else
        *p++ = *s;
    }
  *p = 0;
  return p;
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
  n /= 2;
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



/* Release the card info structure INFO. */
void
agent_release_card_info (struct agent_card_info_s *info)
{
  if (!info)
    return;

  xfree (info->serialno); info->serialno = NULL;
  xfree (info->disp_name); info->disp_name = NULL;
  xfree (info->disp_lang); info->disp_lang = NULL;
  xfree (info->pubkey_url); info->pubkey_url = NULL;
  xfree (info->login_data); info->login_data = NULL;
  info->cafpr1valid = info->cafpr2valid = info->cafpr3valid = 0;
  info->fpr1valid = info->fpr2valid = info->fpr3valid = 0;
}

static int
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
  
  return 0;
}

/* Call the agent to learn about a smartcard */
int
agent_learn (struct agent_card_info_s *info)
{
  int rc;

  rc = start_agent ();
  if (rc)
    return rc;

  memset (info, 0, sizeof *info);
  rc = assuan_transact (agent_ctx, "LEARN --send",
                        NULL, NULL, NULL, NULL,
                        learn_status_cb, info);
  
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

  rc = start_agent ();
  if (rc)
    return rc;

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL,
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

  rc = start_agent ();
  if (rc)
    return rc;

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  return rc;
}



/* Handle a KEYDATA inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static assuan_error_t
inq_writekey_parms (void *opaque, const char *keyword)
{
  struct writekey_parm_s *parm = opaque; 

  return assuan_send_data (parm->ctx, parm->keydata, parm->keydatalen);
}


/* Send a WRITEKEY command to the SCdaemon. */
int 
agent_scd_writekey (int keyno, const char *serialno,
                    const unsigned char *keydata, size_t keydatalen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct writekey_parm_s parms;

  rc = start_agent ();
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

  return rc;
}




/* Status callback for the SCD GENKEY command. */
static int
scd_genkey_cb (void *opaque, const char *line)
{
  struct agent_card_genkey_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  gpg_error_t rc;

  log_debug ("got status line `%s'\n", line);
  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 7 && !memcmp (keyword, "KEY-FPR", keywordlen))
    {
      parm->fprvalid = unhexify_fpr (line, parm->fpr);
    }
  if (keywordlen == 8 && !memcmp (keyword, "KEY-DATA", keywordlen))
    {
      gcry_mpi_t a;
      const char *name = line;

      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;

      rc = gcry_mpi_scan (&a, GCRYMPI_FMT_HEX, line, 0, NULL);
      if (rc)
        log_error ("error parsing received key data: %s\n", gpg_strerror (rc));
      else if (*name == 'n' && spacep (name+1))
        parm->n = a;
      else if (*name == 'e' && spacep (name+1))
        parm->e = a;
      else
        {
          log_info ("unknown parameter name in received key data\n");
          gcry_mpi_release (a);
        }
    }
  else if (keywordlen == 14 && !memcmp (keyword,"KEY-CREATED-AT", keywordlen))
    {
      parm->created_at = (u32)strtoul (line, NULL, 10);
    }

  return 0;
}

/* Send a GENKEY command to the SCdaemon.  SERIALNO is not used in
   this implementation. */
int
agent_scd_genkey (struct agent_card_genkey_s *info, int keyno, int force,
                  const char *serialno)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  rc = start_agent ();
  if (rc)
    return rc;

  memset (info, 0, sizeof *info);
  snprintf (line, DIM(line)-1, "SCD GENKEY %s%d",
            force? "--force ":"", keyno);
  line[DIM(line)-1] = 0;

  memset (info, 0, sizeof *info);
  rc = assuan_transact (agent_ctx, line,
                        NULL, NULL, NULL, NULL,
                        scd_genkey_cb, info);
  
  return rc;
}


static int
membuf_data_cb (void *opaque, const void *buffer, size_t length)
{
  membuf_t *data = opaque;

  if (buffer)
    put_membuf (data, buffer, length);
  return 0;
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

  rc = start_agent ();
  if (rc)
    return rc;

  if (indatalen*2 + 50 > DIM(line))
    return gpg_error (GPG_ERR_GENERAL);

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
    snprintf (line, DIM(line)-1, "SCD PKSIGN %s%s",
              hashalgo == GCRY_MD_RMD160? "--hash=rmd160 " : "",
              serialno);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line, membuf_data_cb, &data,
                        NULL, NULL, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }
  *r_buf = get_membuf (&data, r_buflen);

  return 0;
}


/* Decrypt INDATA of length INDATALEN using the card identified by
   SERIALNO.  Return the plaintext in a nwly allocated buffer stored
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
  rc = start_agent ();
  if (rc)
    return rc;

  /* FIXME: use secure memory where appropriate */
  if (indatalen*2 + 50 > DIM(line))
    return gpg_error (GPG_ERR_GENERAL);

  sprintf (line, "SCD SETDATA ");
  p = line + strlen (line);
  for (i=0; i < indatalen ; i++, p += 2 )
    sprintf (p, "%02X", indata[i]);
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  snprintf (line, DIM(line)-1, "SCD PKDECRYPT %s", serialno);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line,
                        membuf_data_cb, &data,
                        NULL, NULL, NULL, NULL);
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
         2: Same as 1
         3: Change the admin PIN
       101: Set a new PIN and reset the retry counter
       102: Same as 101
   SERIALNO is not used.
 */
int
agent_scd_change_pin (int chvno, const char *serialno)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  const char *reset = "";

  if (chvno >= 100)
    reset = "--reset";
  chvno %= 100;

  rc = start_agent ();
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "SCD PASSWD %s %d", reset, chvno);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line, NULL, NULL,
                        NULL, NULL, NULL, NULL);
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

  rc = start_agent ();
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "SCD CHECKPIN %s", serialno);
  line[DIM(line)-1] = 0;
  return assuan_transact (agent_ctx, line,
                          NULL, NULL,
                          NULL, NULL, NULL, NULL);
}


/* Dummy function, only used by the gpg 1.4 implementation. */
void
agent_clear_pin_cache (const char *sn)
{

}




/* Note: All strings shall be UTF-8. On success the caler needs to
   free the string stored at R_PASSPHRASE. On error NULL will be
   stored at R_PASSPHRASE and an appropriate fpf error code
   returned. */
gpg_error_t
agent_get_passphrase (const char *cache_id,
                      const char *err_msg,
                      const char *prompt,
                      const char *desc_msg,
                      char **r_passphrase)
{
  int rc;
  char *line, *p;
  char cmd[] = "GET_PASSPHRASE --data -- ";
  membuf_t data;

  *r_passphrase = NULL;

  rc = start_agent ();
  if (rc)
    return rc;

  /* We allocate 3 times the needed space for the texts so that
     there is enough space for escaping. */
  line = xtrymalloc ( strlen (cmd) + 1
                      + (cache_id? 3*strlen (cache_id): 1) + 1
                      + (err_msg?  3*strlen (err_msg): 1) + 1
                      + (prompt?   3*strlen (prompt): 1) + 1
                      + (desc_msg? 3*strlen (desc_msg): 1) + 1
                      + 1);
  if (!line)
    return gpg_error_from_syserror ();

  p = stpcpy (line, cmd);
  if (cache_id && *cache_id)
    p = percent_plus_escape (p, cache_id);
  else
    *p++ = 'X';
  *p++ = ' ';

  if (err_msg && *err_msg)
    p = percent_plus_escape (p, err_msg);
  else
    *p++ = 'X';
  *p++ = ' ';

  if (prompt && *prompt)
    p = percent_plus_escape (p, prompt);
  else
    *p++ = 'X'; 
  *p++ = ' ';

  if (desc_msg && *desc_msg)
    p = percent_plus_escape (p, desc_msg);
  else
    *p++ = 'X';
  *p = 0;

  init_membuf_secure (&data, 64);
  rc = assuan_transact (agent_ctx, line, 
                        membuf_data_cb, &data, NULL, NULL, NULL, NULL);

  if (rc)
    xfree (get_membuf (&data, NULL));
  else 
    {
      put_membuf (&data, "", 1);
      *r_passphrase = get_membuf (&data, NULL);
      if (!*r_passphrase)
        rc = gpg_error_from_syserror ();
    }
  xfree (line);
  return rc;
}


gpg_error_t
agent_clear_passphrase (const char *cache_id)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  if (!cache_id || !*cache_id)
    return 0;

  rc = start_agent ();
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "CLEAR_PASSPHRASE %s", cache_id);
  line[DIM(line)-1] = 0;
  return assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
}
