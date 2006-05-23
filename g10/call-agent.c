/* call-agent.c - divert operations to the agent
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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

#if 0  /* let Emacs display a red warning */
#error fixme: this shares a lot of code with the file in ../sm
#endif

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
#include "call-agent.h"

#ifndef DBG_ASSUAN
# define DBG_ASSUAN 1
#endif

static ASSUAN_CONTEXT agent_ctx = NULL;
static int force_pipe_server = 1; /* FIXME: set this back to 0. */

struct cipher_parm_s {
  ASSUAN_CONTEXT ctx;
  const char *ciphertext;
  size_t ciphertextlen;
};

struct genkey_parm_s {
  ASSUAN_CONTEXT ctx;
  const char *sexp;
  size_t sexplen;
};



/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
static int
start_agent (void)
{
  int rc = 0;
  char *infostr, *p;
  ASSUAN_CONTEXT ctx;
  char *dft_display = NULL;
  char *dft_ttyname = NULL;
  char *dft_ttytype = NULL;
  char *old_lc = NULL;
  char *dft_lc = NULL;

  if (agent_ctx)
    return 0; /* fixme: We need a context for each thread or serialize
                 the access to the agent. */

  infostr = force_pipe_server? NULL : getenv ("GPG_AGENT_INFO");
  if (!infostr || !*infostr)
    {
      const char *pgmname;
      const char *argv[3];
      int no_close_list[3];
      int i;

      if (opt.verbose)
        log_info (_("no running gpg-agent - starting one\n"));

      if (fflush (NULL))
        {
          gpg_error_t tmperr = gpg_error_from_errno (errno);
          log_error ("error flushing pending output: %s\n", strerror (errno));
          return tmperr;
        }

      if (!opt.agent_program || !*opt.agent_program)
        opt.agent_program = GNUPG_DEFAULT_AGENT;
      if ( !(pgmname = strrchr (opt.agent_program, '/')))
        pgmname = opt.agent_program;
      else
        pgmname++;

      argv[0] = pgmname;
      argv[1] = "--server";
      argv[2] = NULL;

      i=0;
      if (log_get_fd () != -1)
        no_close_list[i++] = log_get_fd ();
      no_close_list[i++] = fileno (stderr);
      no_close_list[i] = -1;

      /* connect to the agent and perform initial handshaking */
      rc = assuan_pipe_connect (&ctx, opt.agent_program, (char**)argv,
                                no_close_list);
    }
  else
    {
      int prot;
      int pid;

      infostr = xstrdup (infostr);
      if ( !(p = strchr (infostr, ':')) || p == infostr)
        {
          log_error (_("malformed GPG_AGENT_INFO environment variable\n"));
          xfree (infostr);
          force_pipe_server = 1;
          return start_agent ();
        }
      *p++ = 0;
      pid = atoi (p);
      while (*p && *p != ':')
        p++;
      prot = *p? atoi (p+1) : 0;
      if (prot != 1)
        {
          log_error (_("gpg-agent protocol version %d is not supported\n"),
                     prot);
          xfree (infostr);
          force_pipe_server = 1;
          return start_agent ();
        }

      rc = assuan_socket_connect (&ctx, infostr, pid);
      xfree (infostr);
      if (rc == ASSUAN_Connect_Failed)
        {
          log_error (_("can't connect to the agent - trying fall back\n"));
          force_pipe_server = 1;
          return start_agent ();
        }
    }

  if (rc)
    {
      log_error ("can't connect to the agent: %s\n", assuan_strerror (rc));
      return gpg_error (GPG_ERR_NO_AGENT);
    }
  agent_ctx = ctx;

  if (DBG_ASSUAN)
    log_debug ("connection to agent established\n");

  rc = assuan_transact (agent_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return map_assuan_err (rc);

#ifdef __GNUC__
#warning put this code into common/asshelp.c
#endif

  dft_display = getenv ("DISPLAY");
  if (opt.display || dft_display)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION display=%s",
		    opt.display ? opt.display : dft_display) < 0)
	return gpg_error_from_errno (errno);
      rc = assuan_transact (agent_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      free (optstr);
      if (rc)
	return map_assuan_err (rc);
    }
  if (!opt.ttyname)
    {
      dft_ttyname = getenv ("GPG_TTY");
      if ((!dft_ttyname || !*dft_ttyname) && ttyname (0))
        dft_ttyname = ttyname (0);
    }
  if (opt.ttyname || dft_ttyname)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION ttyname=%s",
		    opt.ttyname ? opt.ttyname : dft_ttyname) < 0)
	return gpg_error_from_errno (errno);
      rc = assuan_transact (agent_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      free (optstr);
      if (rc)
	return map_assuan_err (rc);
    }
  dft_ttytype = getenv ("TERM");
  if (opt.ttytype || (dft_ttyname && dft_ttytype))
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION ttytype=%s",
		    opt.ttyname ? opt.ttytype : dft_ttytype) < 0)
	return gpg_error_from_errno (errno);
      rc = assuan_transact (agent_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
			    NULL);
      free (optstr);
      if (rc)
	return map_assuan_err (rc);
    }
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  old_lc = setlocale (LC_CTYPE, NULL);
  if (old_lc)
    {
      old_lc = strdup (old_lc);
      if (!old_lc)
        return gpg_error_from_errno (errno);

    }
  dft_lc = setlocale (LC_CTYPE, "");
#endif
  if (opt.lc_ctype || (dft_ttyname && dft_lc))
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION lc-ctype=%s",
		    opt.lc_ctype ? opt.lc_ctype : dft_lc) < 0)
	rc = gpg_error_from_errno (errno);
      else
	{
	  rc = assuan_transact (agent_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
				NULL);
	  free (optstr);
	  if (rc)
	    rc = map_assuan_err (rc);
	}
    }
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  if (old_lc)
    {
      setlocale (LC_CTYPE, old_lc);
      free (old_lc);
    }
#endif
  if (rc)
    return rc;
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  old_lc = setlocale (LC_MESSAGES, NULL);
  if (old_lc)
    {
      old_lc = strdup (old_lc);
      if (!old_lc)
        return gpg_error_from_errno (errno);
    }
  dft_lc = setlocale (LC_MESSAGES, "");
#endif
  if (opt.lc_messages || (dft_ttyname && dft_lc))
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION lc-messages=%s",
		    opt.lc_messages ? opt.lc_messages : dft_lc) < 0)
	rc = gpg_error_from_errno (errno);
      else
	{
	  rc = assuan_transact (agent_ctx, optstr, NULL, NULL, NULL, NULL, NULL,
				NULL);
	  free (optstr);
	  if (rc)
	    rc = map_assuan_err (rc);
	}
    }
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  if (old_lc)
    {
      setlocale (LC_MESSAGES, old_lc);
      free (old_lc);
    }
#endif

  return rc;
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



#if 0
/* Handle a KEYPARMS inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static AssuanError
inq_genkey_parms (void *opaque, const char *keyword)
{
  struct genkey_parm_s *parm = opaque; 
  AssuanError rc;

  rc = assuan_send_data (parm->ctx, parm->sexp, parm->sexplen);
  return rc; 
}



/* Call the agent to generate a new key */
int
agent_genkey (KsbaConstSexp keyparms, KsbaSexp *r_pubkey)
{
  int rc;
  struct genkey_parm_s gk_parm;
  membuf_t data;
  size_t len;
  char *buf;

  *r_pubkey = NULL;
  rc = start_agent ();
  if (rc)
    return rc;

  rc = assuan_transact (agent_ctx, "RESET", NULL, NULL,
                        NULL, NULL, NULL, NULL);
  if (rc)
    return map_assuan_err (rc);

  init_membuf (&data, 1024);
  gk_parm.ctx = agent_ctx;
  gk_parm.sexp = keyparms;
  gk_parm.sexplen = gcry_sexp_canon_len (keyparms, 0, NULL, NULL);
  if (!gk_parm.sexplen)
    return gpg_error (GPG_ERR_INV_VALUE);
  rc = assuan_transact (agent_ctx, "GENKEY",
                        membuf_data_cb, &data, 
                        inq_genkey_parms, &gk_parm, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return map_assuan_err (rc);
    }
  buf = get_membuf (&data, &len);
  if (!buf)
    return gpg_error (GPG_ERR_ENOMEM);
  if (!gcry_sexp_canon_len (buf, len, NULL, NULL))
    {
      xfree (buf);
      return gpg_error (GPG_ERR_INV_SEXP);
    }
  *r_pubkey = buf;
  return 0;
}
#endif /*0*/



/* Ask the agent whether the corresponding secret key is available for
   the given keygrip. */
int
agent_havekey (const char *hexkeygrip)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  rc = start_agent ();
  if (rc)
    return rc;

  if (!hexkeygrip || strlen (hexkeygrip) != 40)
    return gpg_error (GPG_ERR_INV_VALUE);

  snprintf (line, DIM(line)-1, "HAVEKEY %s", hexkeygrip);
  line[DIM(line)-1] = 0;

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  return map_assuan_err (rc);
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

static AssuanError
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
  
  return map_assuan_err (rc);
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
  
  return map_assuan_err (rc);
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
  return map_assuan_err (rc);
}


/* Status callback for the SCD GENKEY command. */
static AssuanError
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
  
  return map_assuan_err (rc);
}


static AssuanError
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
                  char **r_buf, size_t *r_buflen)
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
    return map_assuan_err (rc);

  init_membuf (&data, 1024);
#if 0
  if (!hashalgo) /* Temporary test hack. */
    snprintf (line, DIM(line)-1, "SCD PKAUTH %s", serialno);
  else
#endif
   snprintf (line, DIM(line)-1, "SCD PKSIGN %s", serialno);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line, membuf_data_cb, &data,
                        NULL, NULL, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return map_assuan_err (rc);
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
                     char **r_buf, size_t *r_buflen)
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
    return map_assuan_err (rc);

  init_membuf (&data, 1024);
  snprintf (line, DIM(line)-1, "SCD PKDECRYPT %s", serialno);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line,
                        membuf_data_cb, &data,
                        NULL, NULL, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return map_assuan_err (rc);
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
  return map_assuan_err (rc);
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
