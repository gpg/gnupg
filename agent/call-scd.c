/* call-scd.c - fork of the scdaemon to do SC operations
 * Copyright (C) 2001, 2002, 2005, 2007, 2010,
 *               2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 Werner Koch
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/wait.h>
#endif
#include <npth.h>

#include "agent.h"
#include <assuan.h>
#include "../common/strlist.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

/* Definition of module local data of the CTRL structure.  */
struct scd_local_s
{
  /* We keep a list of all allocated context with an anchor at
     SCD_LOCAL_LIST (see below). */
  struct scd_local_s *next_local;

  assuan_context_t ctx;   /* NULL or session context for the SCdaemon
                             used with this connection. */
  unsigned int in_use: 1; /* CTX is in use.  */
  unsigned int invalid:1; /* CTX is invalid, should be released.  */
};


/* Callback parameter for learn card */
struct learn_parm_s
{
  void (*kpinfo_cb)(void*, const char *);
  void *kpinfo_cb_arg;
  void (*certinfo_cb)(void*, const char *);
  void *certinfo_cb_arg;
  void (*sinfo_cb)(void*, const char *, size_t, const char *);
  void *sinfo_cb_arg;
};


/* Callback parameter used by inq_getpin and inq_writekey_parms.  */
struct inq_needpin_parm_s
{
  assuan_context_t ctx;
  int (*getpin_cb)(void *, const char *, const char *, char*, size_t);
  void *getpin_cb_arg;
  const char *getpin_cb_desc;
  assuan_context_t passthru;  /* If not NULL, pass unknown inquiries
                                 up to the caller.  */

  /* The next fields are used by inq_writekey_parm.  */
  const unsigned char *keydata;
  size_t keydatalen;
};




static int
start_scd (ctrl_t ctrl)
{
  return daemon_start (DAEMON_SCD, ctrl);
}


static gpg_error_t
unlock_scd (ctrl_t ctrl, gpg_error_t err)
{
  return daemon_unlock (DAEMON_SCD, ctrl, err);
}


static assuan_context_t
daemon_ctx (ctrl_t ctrl)
{
  return daemon_type_ctx (DAEMON_SCD, ctrl);
}



/* This handler is a helper for pincache_put_cb but may also be called
 * directly for that status code with ARGS being the arguments after
 * the status keyword (and with white space removed).  */
static gpg_error_t
handle_pincache_put (const char *args)
{
  gpg_error_t err;
  const char *s, *key, *pin;
  char *keybuf = NULL;
  size_t keylen;

  key = s = args;
  while (*s && !spacep (s))
    s++;
  keylen = s - key;
  if (keylen < 3)
    {
      /* At least we need 2 slashes and slot number.  */
      log_error ("%s: ignoring invalid key\n", __func__);
      err = 0;
      goto leave;
    }

  keybuf = xtrymalloc (keylen+1);
  if (!keybuf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  memcpy (keybuf, key, keylen);
  keybuf[keylen] = 0;
  key = keybuf;

  while (spacep (s))
    s++;
  pin = s;
  if (!*pin)
    {
      /* No value - flush the cache.  The cache module knows aboput
       * the structure of the key to flush only parts.  */
      log_debug ("%s: flushing cache '%s'\n", __func__, key);
      agent_put_cache (NULL, key, CACHE_MODE_PIN, NULL, -1);
      err = 0;
      goto leave;
    }

  log_debug ("%s: caching '%s'->'%s'\n", __func__, key, pin);
  agent_put_cache (NULL, key, CACHE_MODE_PIN, pin, -1);
  err = 0;

 leave:
  xfree (keybuf);
  return err;
}


/* This status callback is to intercept the PINCACHE_PUT status
 * messages.  OPAQUE is not used.  */
static gpg_error_t
pincache_put_cb (void *opaque, const char *line)
{
  const char *s;

  (void)opaque;

  s = has_leading_keyword (line, "PINCACHE_PUT");
  if (s)
    return handle_pincache_put (s);
  else
    return 0;
}


/* Handle a PINCACHE_GET inquiry.  ARGS are the arguments of the
 * inquiry which should be a single string with the key for the cached
 * value.  CTX is the Assuan handle.  */
static gpg_error_t
handle_pincache_get (const char *args, assuan_context_t ctx)
{
  gpg_error_t err;
  const char *key;
  char *pin = NULL;

  log_debug ("%s: enter '%s'\n", __func__, args);
  key = args;
  if (strlen (key) < 5)
    {
      /* We need at least 2 slashes, one slot number and two 1 byte strings.*/
      err = gpg_error (GPG_ERR_INV_REQUEST);
      log_debug ("%s: key too short\n", __func__);
      goto leave;
    }

  pin = agent_get_cache (NULL, key, CACHE_MODE_PIN);
  if (!pin || !*pin)
    {
      xfree (pin);
      err = 0;  /* Not found is indicated by sending no data back.  */
      log_debug ("%s: not cached\n", __func__);
      goto leave;
    }
  log_debug ("%s: cache returned '%s'\n", __func__, pin);
  err = assuan_send_data (ctx, pin, strlen (pin));

 leave:
  xfree (pin);
  return err;
}



static gpg_error_t
learn_status_cb (void *opaque, const char *line)
{
  struct learn_parm_s *parm = opaque;
  gpg_error_t err = 0;
  const char *keyword = line;
  int keywordlen;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;
  if (keywordlen == 8 && !memcmp (keyword, "CERTINFO", keywordlen))
    {
      parm->certinfo_cb (parm->certinfo_cb_arg, line);
    }
  else if (keywordlen == 11 && !memcmp (keyword, "KEYPAIRINFO", keywordlen))
    {
      parm->kpinfo_cb (parm->kpinfo_cb_arg, line);
    }
  else if (keywordlen == 12 && !memcmp (keyword, "PINCACHE_PUT", keywordlen))
    err = handle_pincache_put (line);
  else if (keywordlen && *line)
    {
      parm->sinfo_cb (parm->sinfo_cb_arg, keyword, keywordlen, line);
    }

  return err;
}

/* Perform the LEARN command and return a list of all private keys
   stored on the card. */
int
agent_card_learn (ctrl_t ctrl,
                  void (*kpinfo_cb)(void*, const char *),
                  void *kpinfo_cb_arg,
                  void (*certinfo_cb)(void*, const char *),
                  void *certinfo_cb_arg,
                  void (*sinfo_cb)(void*, const char *, size_t, const char *),
                  void *sinfo_cb_arg)
{
  int rc;
  struct learn_parm_s parm;

  rc = start_scd (ctrl);
  if (rc)
    return rc;

  memset (&parm, 0, sizeof parm);
  parm.kpinfo_cb = kpinfo_cb;
  parm.kpinfo_cb_arg = kpinfo_cb_arg;
  parm.certinfo_cb = certinfo_cb;
  parm.certinfo_cb_arg = certinfo_cb_arg;
  parm.sinfo_cb = sinfo_cb;
  parm.sinfo_cb_arg = sinfo_cb_arg;
  rc = assuan_transact (daemon_ctx (ctrl), "LEARN --force",
                        NULL, NULL, NULL, NULL,
                        learn_status_cb, &parm);
  if (rc)
    return unlock_scd (ctrl, rc);

  return unlock_scd (ctrl, 0);
}



static gpg_error_t
get_serialno_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
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
  else if (keywordlen == 12 && !memcmp (keyword, "PINCACHE_PUT", keywordlen))
    err = handle_pincache_put (line);

  return err;
}


/* Return the serial number of the card or an appropriate error.  The
 * serial number is returned as a hexstring.  If the serial number is
 * not required by the caller R_SERIALNO can be NULL; this might be
 * useful to test whether a card is available. */
int
agent_card_serialno (ctrl_t ctrl, char **r_serialno, const char *demand)
{
  int rc;
  char *serialno = NULL;
  char line[ASSUAN_LINELENGTH];

  rc = start_scd (ctrl);
  if (rc)
    return rc;

  if (!demand)
    strcpy (line, "SERIALNO --all");
  else
    snprintf (line, DIM(line), "SERIALNO --demand=%s", demand);

  rc = assuan_transact (daemon_ctx (ctrl), line,
                        NULL, NULL, NULL, NULL,
                        get_serialno_cb, &serialno);
  if (rc)
    {
      xfree (serialno);
      return unlock_scd (ctrl, rc);
    }
  if (r_serialno)
    *r_serialno = serialno;
  else
    xfree (serialno);
  return unlock_scd (ctrl, 0);
}




/* Handle the NEEDPIN inquiry. */
static gpg_error_t
inq_needpin (void *opaque, const char *line)
{
  struct inq_needpin_parm_s *parm = opaque;
  const char *s;
  char *pin;
  size_t pinlen;
  int rc;

  if ((s = has_leading_keyword (line, "NEEDPIN")))
    {
      line = s;
      pinlen = 90;
      pin = gcry_malloc_secure (pinlen);
      if (!pin)
        return out_of_core ();

      rc = parm->getpin_cb (parm->getpin_cb_arg, parm->getpin_cb_desc,
                            line, pin, pinlen);
      if (!rc)
        {
          assuan_begin_confidential (parm->ctx);
          rc = assuan_send_data (parm->ctx, pin, pinlen);
          assuan_end_confidential (parm->ctx);
        }
      wipememory (pin, pinlen);
      xfree (pin);
    }
  else if ((s = has_leading_keyword (line, "POPUPPINPADPROMPT")))
    {
      rc = parm->getpin_cb (parm->getpin_cb_arg, parm->getpin_cb_desc,
                            s, NULL, 1);
    }
  else if ((s = has_leading_keyword (line, "DISMISSPINPADPROMPT")))
    {
      rc = parm->getpin_cb (parm->getpin_cb_arg, parm->getpin_cb_desc,
                            "", NULL, 0);
    }
  else if ((s = has_leading_keyword (line, "PINCACHE_GET")))
    {
      rc = handle_pincache_get (s, parm->ctx);
    }
  else if (parm->passthru)
    {
      unsigned char *value;
      size_t valuelen;
      int rest;
      int needrest = !strncmp (line, "KEYDATA", 8);

      /* Pass the inquiry up to our caller.  We limit the maximum
         amount to an arbitrary value.  As we know that the KEYDATA
         enquiry is pretty sensitive we disable logging then */
      if ((rest = (needrest
                   && !assuan_get_flag (parm->passthru, ASSUAN_CONFIDENTIAL))))
        assuan_begin_confidential (parm->passthru);
      rc = assuan_inquire (parm->passthru, line, &value, &valuelen, 8096);
      if (rest)
        assuan_end_confidential (parm->passthru);
      if (!rc)
        {
          if ((rest = (needrest
                       && !assuan_get_flag (parm->ctx, ASSUAN_CONFIDENTIAL))))
            assuan_begin_confidential (parm->ctx);
          rc = assuan_send_data (parm->ctx, value, valuelen);
          if (rest)
            assuan_end_confidential (parm->ctx);
          xfree (value);
        }
      else
        log_error ("error forwarding inquiry '%s': %s\n",
                   line, gpg_strerror (rc));
    }
  else
    {
      log_error ("unsupported inquiry '%s'\n", line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  return rc;
}


/* Helper returning a command option to describe the used hash
   algorithm.  See scd/command.c:cmd_pksign.  */
static const char *
hash_algo_option (int algo)
{
  switch (algo)
    {
    case GCRY_MD_MD5   : return "--hash=md5";
    case GCRY_MD_RMD160: return "--hash=rmd160";
    case GCRY_MD_SHA1  : return "--hash=sha1";
    case GCRY_MD_SHA224: return "--hash=sha224";
    case GCRY_MD_SHA256: return "--hash=sha256";
    case GCRY_MD_SHA384: return "--hash=sha384";
    case GCRY_MD_SHA512: return "--hash=sha512";
    default:             return "";
    }
}


/* Create a signature using the current card.  MDALGO is either 0 or
 * gives the digest algorithm.  DESC_TEXT is an additional parameter
 * passed to GETPIN_CB. */
int
agent_card_pksign (ctrl_t ctrl,
                   const char *keyid,
                   int (*getpin_cb)(void *, const char *,
                                    const char *, char*, size_t),
                   void *getpin_cb_arg,
                   const char *desc_text,
                   int mdalgo,
                   const unsigned char *indata, size_t indatalen,
                   unsigned char **r_buf, size_t *r_buflen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct inq_needpin_parm_s inqparm;

  *r_buf = NULL;
  rc = start_scd (ctrl);
  if (rc)
    return rc;

  /* FIXME: In the mdalgo case (INDATA,INDATALEN) might be long and
   * thus we can't convey it on a single Assuan line.  */
  if (!mdalgo)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  if (indatalen*2 + 50 > DIM(line))
    return unlock_scd (ctrl, gpg_error (GPG_ERR_GENERAL));

  bin2hex (indata, indatalen, stpcpy (line, "SETDATA "));

  rc = assuan_transact (daemon_ctx (ctrl), line,
                        NULL, NULL, NULL, NULL, pincache_put_cb, NULL);
  if (rc)
    return unlock_scd (ctrl, rc);

  init_membuf (&data, 1024);
  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.getpin_cb = getpin_cb;
  inqparm.getpin_cb_arg = getpin_cb_arg;
  inqparm.getpin_cb_desc = desc_text;
  inqparm.passthru = 0;
  inqparm.keydata = NULL;
  inqparm.keydatalen = 0;

  if (ctrl->use_auth_call)
    snprintf (line, sizeof line, "PKAUTH %s", keyid);
  else
    snprintf (line, sizeof line, "PKSIGN %s %s",
              hash_algo_option (mdalgo), keyid);
  rc = assuan_transact (daemon_ctx (ctrl), line,
                        put_membuf_cb, &data,
                        inq_needpin, &inqparm,
                        pincache_put_cb, NULL);

  if (rc)
    {
      size_t len;

      xfree (get_membuf (&data, &len));
      return unlock_scd (ctrl, rc);
    }

  *r_buf = get_membuf (&data, r_buflen);
  return unlock_scd (ctrl, 0);
}




/* Check whether there is any padding info from scdaemon.  */
static gpg_error_t
padding_info_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  int *r_padding = opaque;
  const char *s;

  if ((s=has_leading_keyword (line, "PADDING")))
    {
      *r_padding = atoi (s);
    }
  else if ((s=has_leading_keyword (line, "PINCACHE_PUT")))
    err = handle_pincache_put (s);

  return err;
}


/* Decipher INDATA using the current card.  Note that the returned
 * value is not an s-expression but the raw data as returned by
 * scdaemon.  The padding information is stored at R_PADDING with -1
 * for not known.  DESC_TEXT is an additional parameter passed to
 * GETPIN_CB.  */
int
agent_card_pkdecrypt (ctrl_t ctrl,
                      const char *keyid,
                      int (*getpin_cb)(void *, const char *,
                                       const char *, char*, size_t),
                      void *getpin_cb_arg,
                      const char *desc_text,
                      const unsigned char *indata, size_t indatalen,
                      char **r_buf, size_t *r_buflen, int *r_padding)
{
  int rc, i;
  char *p, line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct inq_needpin_parm_s inqparm;
  size_t len;

  *r_buf = NULL;
  *r_padding = -1; /* Unknown.  */
  rc = start_scd (ctrl);
  if (rc)
    return rc;

  /* FIXME: use secure memory where appropriate */

  for (len = 0; len < indatalen;)
    {
      p = stpcpy (line, "SETDATA ");
      if (len)
        p = stpcpy (p, "--append ");
      for (i=0; len < indatalen && (i*2 < DIM(line)-50); i++, len++)
        {
          sprintf (p, "%02X", indata[len]);
          p += 2;
        }
      rc = assuan_transact (daemon_ctx (ctrl), line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_scd (ctrl, rc);
    }

  init_membuf (&data, 1024);
  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.getpin_cb = getpin_cb;
  inqparm.getpin_cb_arg = getpin_cb_arg;
  inqparm.getpin_cb_desc = desc_text;
  inqparm.passthru = 0;
  inqparm.keydata = NULL;
  inqparm.keydatalen = 0;
  snprintf (line, DIM(line), "PKDECRYPT %s", keyid);
  rc = assuan_transact (daemon_ctx (ctrl), line,
                        put_membuf_cb, &data,
                        inq_needpin, &inqparm,
                        padding_info_cb, r_padding);

  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return unlock_scd (ctrl, rc);
    }
  *r_buf = get_membuf (&data, r_buflen);
  if (!*r_buf)
    return unlock_scd (ctrl, gpg_error (GPG_ERR_ENOMEM));

  return unlock_scd (ctrl, 0);
}



/* Read a certificate with ID into R_BUF and R_BUFLEN. */
int
agent_card_readcert (ctrl_t ctrl,
                     const char *id, char **r_buf, size_t *r_buflen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;

  *r_buf = NULL;
  rc = start_scd (ctrl);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  snprintf (line, DIM(line), "READCERT %s", id);
  rc = assuan_transact (daemon_ctx (ctrl), line,
                        put_membuf_cb, &data,
                        NULL, NULL,
                        pincache_put_cb, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return unlock_scd (ctrl, rc);
    }
  *r_buf = get_membuf (&data, r_buflen);
  if (!*r_buf)
    return unlock_scd (ctrl, gpg_error (GPG_ERR_ENOMEM));

  return unlock_scd (ctrl, 0);
}



struct readkey_status_parm_s
{
  char *keyref;
};

static gpg_error_t
readkey_status_cb (void *opaque, const char *line)
{
  struct readkey_status_parm_s *parm = opaque;
  gpg_error_t err = 0;
  char *line_buffer = NULL;
  const char *s;

  if ((s = has_leading_keyword (line, "KEYPAIRINFO"))
      && !parm->keyref)
    {
      /* The format of such a line is:
       *   KEYPAIRINFO <hexgrip> <keyref> [usage] [keytime] [algostr]
       *
       * Here we only need the keyref.  We use only the first received
       * KEYPAIRINFO; it is possible to receive several if there are
       * two or more active cards with the same key.  */
      const char *fields[2];
      int nfields;

      line_buffer = xtrystrdup (line);
      if (!line_buffer)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      if ((nfields = split_fields (line_buffer, fields, DIM (fields))) < 2)
        goto leave;  /* Not enough args; invalid status line - skip.  */

      parm->keyref = xtrystrdup (fields[1]);
      if (!parm->keyref)
        err = gpg_error_from_syserror ();
    }
  else
    err = pincache_put_cb (NULL, line);

 leave:
  xfree (line_buffer);
  return err;
}


/* Read a key with ID (keyref or keygrip) and return it in a malloced
 * buffer pointed to by R_BUF as a valid S-expression.  If R_KEYREF is
 * not NULL the keyref is stored there. */
int
agent_card_readkey (ctrl_t ctrl, const char *id,
                    unsigned char **r_buf, char **r_keyref)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len, buflen;
  struct readkey_status_parm_s parm;

  memset (&parm, 0, sizeof parm);

  *r_buf = NULL;
  if (r_keyref)
    *r_keyref = NULL;

  rc = start_scd (ctrl);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  snprintf (line, DIM(line), "READKEY%s -- %s",
            r_keyref? " --info":"", id);
  rc = assuan_transact (daemon_ctx (ctrl), line,
                        put_membuf_cb, &data,
                        NULL, NULL,
                        readkey_status_cb, &parm);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      xfree (parm.keyref);
      return unlock_scd (ctrl, rc);
    }
  *r_buf = get_membuf (&data, &buflen);
  if (!*r_buf)
    {
      xfree (parm.keyref);
      return unlock_scd (ctrl, gpg_error (GPG_ERR_ENOMEM));
    }

  if (!gcry_sexp_canon_len (*r_buf, buflen, NULL, NULL))
    {
      xfree (parm.keyref);
      xfree (*r_buf); *r_buf = NULL;
      return unlock_scd (ctrl, gpg_error (GPG_ERR_INV_VALUE));
    }
  if (r_keyref)
    *r_keyref = parm.keyref;
  else
    xfree (parm.keyref);

  return unlock_scd (ctrl, 0);
}


/* Handle a KEYDATA inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static gpg_error_t
inq_writekey_parms (void *opaque, const char *line)
{
  struct inq_needpin_parm_s *parm = opaque;

  if (has_leading_keyword (line, "KEYDATA"))
    return assuan_send_data (parm->ctx, parm->keydata, parm->keydatalen);
  else
    return inq_needpin (opaque, line);
}


/* Call scd to write a key to a card under the id KEYREF.  */
gpg_error_t
agent_card_writekey (ctrl_t ctrl,  int force, const char *serialno,
                     const char *keyref,
                     const char *keydata, size_t keydatalen,
                     int (*getpin_cb)(void *, const char *,
                                      const char *, char*, size_t),
                     void *getpin_cb_arg)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct inq_needpin_parm_s parms;

  (void)serialno; /* NULL or a number to check for the correct card.
                   * But is is not implemented.  */

  err = start_scd (ctrl);
  if (err)
    return err;

  snprintf (line, DIM(line), "WRITEKEY %s%s", force ? "--force " : "", keyref);
  parms.ctx = daemon_ctx (ctrl);
  parms.getpin_cb = getpin_cb;
  parms.getpin_cb_arg = getpin_cb_arg;
  parms.getpin_cb_desc= NULL;
  parms.passthru = 0;
  parms.keydata = keydata;
  parms.keydatalen = keydatalen;

  err = assuan_transact (daemon_ctx (ctrl), line, NULL, NULL,
                         inq_writekey_parms, &parms,
                         pincache_put_cb, NULL);
  return unlock_scd (ctrl, err);
}



/* Type used with the card_getattr_cb.  */
struct card_getattr_parm_s {
  const char *keyword;  /* Keyword to look for.  */
  size_t keywordlen;    /* strlen of KEYWORD.  */
  char *data;           /* Malloced and unescaped data.  */
  int error;            /* ERRNO value or 0 on success. */
};

/* Callback function for agent_card_getattr.  */
static gpg_error_t
card_getattr_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  struct card_getattr_parm_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;

  if (parm->data)
    return 0; /* We want only the first occurrence.  */

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == parm->keywordlen
      && !memcmp (keyword, parm->keyword, keywordlen))
    {
      parm->data = percent_plus_unescape ((const unsigned char*)line, 0xff);
      if (!parm->data)
        parm->error = errno;
    }
  else if (keywordlen == 12 && !memcmp (keyword, "PINCACHE_PUT", keywordlen))
    err = handle_pincache_put (line);

  return err;
}


/* Call the agent to retrieve a single line data object. On success
   the object is malloced and stored at RESULT; it is guaranteed that
   NULL is never stored in this case.  On error an error code is
   returned and NULL stored at RESULT. */
gpg_error_t
agent_card_getattr (ctrl_t ctrl, const char *name, char **result,
                    const char *keygrip)
{
  int err;
  struct card_getattr_parm_s parm;
  char line[ASSUAN_LINELENGTH];

  *result = NULL;

  if (!*name)
    return gpg_error (GPG_ERR_INV_VALUE);

  memset (&parm, 0, sizeof parm);
  parm.keyword = name;
  parm.keywordlen = strlen (name);

  /* We assume that NAME does not need escaping. */
  if (8 + strlen (name) > DIM(line)-1)
    return gpg_error (GPG_ERR_TOO_LARGE);
  if (keygrip == NULL)
    stpcpy (stpcpy (line, "GETATTR "), name);
  else
    snprintf (line, sizeof line, "GETATTR %s %s", name, keygrip);

  err = start_scd (ctrl);
  if (err)
    return err;

  err = assuan_transact (daemon_ctx (ctrl), line,
                         NULL, NULL, NULL, NULL,
                         card_getattr_cb, &parm);
  if (!err && parm.error)
    err = gpg_error_from_errno (parm.error);

  if (!err && !parm.data)
    err = gpg_error (GPG_ERR_NO_DATA);

  if (!err)
    *result = parm.data;
  else
    xfree (parm.data);

  return unlock_scd (ctrl, err);
}



struct card_keyinfo_parm_s {
  int error;
  struct card_key_info_s *list;
};

/* Callback function for agent_card_keylist.  */
static gpg_error_t
card_keyinfo_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  struct card_keyinfo_parm_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  struct card_key_info_s *keyinfo = NULL;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 7 && !memcmp (keyword, "KEYINFO", keywordlen))
    {
      const char *s;
      int n;
      struct card_key_info_s **l_p = &parm->list;

      /* It's going to append the information at the end.  */
      while ((*l_p))
        l_p = &(*l_p)->next;

      keyinfo = xtrycalloc (1, sizeof *keyinfo);
      if (!keyinfo)
        goto alloc_error;

      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;

      if (n != 40)
        goto parm_error;

      memcpy (keyinfo->keygrip, line, 40);
      keyinfo->keygrip[40] = 0;

      line = s;

      if (!*line)
        goto parm_error;

      while (spacep (line))
        line++;

      if (*line++ != 'T')
        goto parm_error;

      if (!*line)
        goto parm_error;

      while (spacep (line))
        line++;

      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;

      if (!n)
        goto skip;

      keyinfo->serialno = xtrymalloc (n+1);
      if (!keyinfo->serialno)
        goto alloc_error;

      memcpy (keyinfo->serialno, line, n);
      keyinfo->serialno[n] = 0;

      line = s;

      if (!*line)
        goto skip;

      while (spacep (line))
        line++;

      if (!*line)
        goto skip;

      for (s = line; *s && !spacep (s); s++)
        ;

      keyinfo->idstr = xtrymalloc (s - line + 1);
      if (!keyinfo->idstr)
        goto alloc_error;
      memcpy (keyinfo->idstr, line, s - line);
      keyinfo->idstr[s - line] = 0;

      while (spacep (s))
        s++;

      if (!*s)
        goto skip;

      keyinfo->usage = xtrystrdup (s);
      if (!keyinfo->usage)
        goto alloc_error;

    skip:
      *l_p = keyinfo;
    }
  else if (keywordlen == 12 && !memcmp (keyword, "PINCACHE_PUT", keywordlen))
    err = handle_pincache_put (line);

  return err;

 alloc_error:
  xfree (keyinfo->serialno);
  xfree (keyinfo->idstr);
  xfree (keyinfo);
  if (!parm->error)
    parm->error = gpg_error_from_syserror ();
  return 0;

 parm_error:
  xfree (keyinfo);
  if (!parm->error)
    parm->error = gpg_error (GPG_ERR_ASS_PARAMETER);
  return 0;
}


void
agent_card_free_keyinfo (struct card_key_info_s *l)
{
  struct card_key_info_s *l_next;

  for (; l; l = l_next)
    {
      l_next = l->next;
      xfree (l->serialno);
      xfree (l->idstr);
      xfree (l->usage);
      xfree (l);
    }
}

/* Call the scdaemon to check if a key of KEYGRIP is available, or
   retrieve list of available keys on cards.  With CAP, we can limit
   keys with specified capability.  On success, the allocated
   structure is stored at RESULT.  On error, an error code is returned
   and NULL is stored at RESULT.  */
gpg_error_t
agent_card_keyinfo (ctrl_t ctrl, const char *keygrip, int cap,
                    struct card_key_info_s **result)
{
  int err;
  struct card_keyinfo_parm_s parm;
  char line[ASSUAN_LINELENGTH];
  char *list_option;

  *result = NULL;

  switch (cap)
    {
    case                  0: list_option = "--list";      break;
    case GCRY_PK_USAGE_SIGN: list_option = "--list=sign"; break;
    case GCRY_PK_USAGE_ENCR: list_option = "--list=encr"; break;
    case GCRY_PK_USAGE_AUTH: list_option = "--list=auth"; break;
    default:                 return gpg_error (GPG_ERR_INV_VALUE);
    }

  memset (&parm, 0, sizeof parm);
  snprintf (line, sizeof line, "KEYINFO %s", keygrip ? keygrip : list_option);

  err = start_scd (ctrl);
  if (err)
    return err;

  err = assuan_transact (daemon_ctx (ctrl), line,
                         NULL, NULL, NULL, NULL,
                         card_keyinfo_cb, &parm);
  if (!err && parm.error)
    err = parm.error;

  if (!err)
    *result = parm.list;
  else
    agent_card_free_keyinfo (parm.list);

  return unlock_scd (ctrl, err);
}

static gpg_error_t
pass_status_thru (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  assuan_context_t ctx = opaque;
  char keyword[200];
  int i;

  if (line[0] == '#' && (!line[1] || spacep (line+1)))
    {
      /* We are called in convey comments mode.  Now, if we see a
         comment marker as keyword we forward the line verbatim to the
         the caller.  This way the comment lines from scdaemon won't
         appear as status lines with keyword '#'.  */
      assuan_write_line (ctx, line);
    }
  else
    {
      for (i=0; *line && !spacep (line) && i < DIM(keyword)-1; line++, i++)
        keyword[i] = *line;
      keyword[i] = 0;

      /* Truncate any remaining keyword stuff.  */
      for (; *line && !spacep (line); line++)
        ;
      while (spacep (line))
        line++;

      /* We do not want to pass PINCACHE_PUT through.  */
      if (!strcmp (keyword, "PINCACHE_PUT"))
        err = handle_pincache_put (line);
      else
        assuan_write_status (ctx, keyword, line);
    }
  return err;
}

static gpg_error_t
pass_data_thru (void *opaque, const void *buffer, size_t length)
{
  assuan_context_t ctx = opaque;

  assuan_send_data (ctx, buffer, length);
  return 0;
}


/* Send the line CMDLINE with command for the SCDdaemon to it and send
   all status messages back.  This command is used as a general quoting
   mechanism to pass everything verbatim to SCDAEMON.  The PIN
   inquiry is handled inside gpg-agent.  */
int
agent_card_scd (ctrl_t ctrl, const char *cmdline,
                int (*getpin_cb)(void *, const char *,
                                 const char *, char*, size_t),
                void *getpin_cb_arg, void *assuan_context)
{
  int rc;
  struct inq_needpin_parm_s inqparm;
  int saveflag;

  rc = start_scd (ctrl);
  if (rc)
    return rc;

  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.getpin_cb = getpin_cb;
  inqparm.getpin_cb_arg = getpin_cb_arg;
  inqparm.getpin_cb_desc = NULL;
  inqparm.passthru = assuan_context;
  inqparm.keydata = NULL;
  inqparm.keydatalen = 0;

  saveflag = assuan_get_flag (daemon_ctx (ctrl), ASSUAN_CONVEY_COMMENTS);
  assuan_set_flag (daemon_ctx (ctrl), ASSUAN_CONVEY_COMMENTS, 1);
  rc = assuan_transact (daemon_ctx (ctrl), cmdline,
                        pass_data_thru, assuan_context,
                        inq_needpin, &inqparm,
                        pass_status_thru, assuan_context);

  assuan_set_flag (daemon_ctx (ctrl), ASSUAN_CONVEY_COMMENTS, saveflag);
  if (rc)
    {
      return unlock_scd (ctrl, rc);
    }

  return unlock_scd (ctrl, 0);
}
