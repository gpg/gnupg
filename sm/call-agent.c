/* call-agent.c - divert operations to the agent
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>

#include <gcrypt.h>

#include "gpgsm.h"
#include "../assuan/assuan.h"
#include "i18n.h"


static ASSUAN_CONTEXT agent_ctx = NULL;
static int force_pipe_server = 0;

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


struct membuf {
  size_t len;
  size_t size;
  char *buf;
  int out_of_core;
};



/* A simple implemnation of a dynamic buffer.  Use init_membuf() to
   create a buffer, put_membuf to append bytes and get_membuf to
   release and return the buffer.  Allocation errors are detected but
   only returned at the final get_membuf(), this helps not to clutter
   the code with out of core checks.  */

static void
init_membuf (struct membuf *mb, int initiallen)
{
  mb->len = 0;
  mb->size = initiallen;
  mb->out_of_core = 0;
  mb->buf = xtrymalloc (initiallen);
  if (!mb->buf)
      mb->out_of_core = 1;
}

static void
put_membuf (struct membuf *mb, const void *buf, size_t len)
{
  if (mb->out_of_core)
    return;

  if (mb->len + len >= mb->size)
    {
      char *p;
      
      mb->size += len + 1024;
      p = xtryrealloc (mb->buf, mb->size);
      if (!p)
        {
          mb->out_of_core = 1;
          return;
        }
      mb->buf = p;
    }
  memcpy (mb->buf + mb->len, buf, len);
  mb->len += len;
}

static void *
get_membuf (struct membuf *mb, size_t *len)
{
  char *p;

  if (mb->out_of_core)
    {
      xfree (mb->buf);
      mb->buf = NULL;
      return NULL;
    }

  p = mb->buf;
  *len = mb->len;
  mb->buf = NULL;
  mb->out_of_core = 1; /* don't allow a reuse */
  return p;
}



/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
static int
start_agent (void)
{
  int rc;
  char *infostr, *p;
  ASSUAN_CONTEXT ctx;

  if (agent_ctx)
    return 0; /* fixme: We need a context for each thread or serialize
                 the access to the agent (which is suitable given that
                 the agent is not MT */

  infostr = force_pipe_server? NULL : getenv ("GPG_AGENT_INFO");
  if (!infostr)
    {
      const char *pgmname;
      const char *argv[3];

      log_info (_("no running gpg-agent - starting one\n"));
      
      if (fflush (NULL))
        {
          log_error ("error flushing pending output: %s\n", strerror (errno));
          return seterr (Write_Error);
        }

      if (!opt.agent_program || !*opt.agent_program)
        opt.agent_program = "../agent/gpg-agent";
      if ( !(pgmname = strrchr (opt.agent_program, '/')))
        pgmname = opt.agent_program;
      else
        pgmname++;

      argv[0] = pgmname;
      argv[1] = "--server";
      argv[2] = NULL;

      /* connect to the agent and perform initial handshaking */
      rc = assuan_pipe_connect (&ctx, opt.agent_program, (char**)argv, 0);
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
      return seterr (No_Agent);
    }
  agent_ctx = ctx;

  if (DBG_AGENT)
    log_debug ("connection to agent established\n");
  return 0;
}


static AssuanError
membuf_data_cb (void *opaque, const void *buffer, size_t length)
{
  struct membuf *data = opaque;

  put_membuf (data, buffer, length);
  return 0;
}
  



/* Call the agent to do a sign operation using the key identified by
   the hex string KEYGRIP. */
int
gpgsm_agent_pksign (const char *keygrip,
                    unsigned char *digest, size_t digestlen, int digestalgo,
                    char **r_buf, size_t *r_buflen )
{
  int rc, i;
  char *p, line[ASSUAN_LINELENGTH];
  struct membuf data;
  size_t len;

  *r_buf = NULL;
  rc = start_agent ();
  if (rc)
    return rc;

  if (digestlen*2 + 50 > DIM(line))
    return seterr (General_Error);

  rc = assuan_transact (agent_ctx, "RESET", NULL, NULL, NULL, NULL);
  if (rc)
    return map_assuan_err (rc);

  snprintf (line, DIM(line)-1, "SIGKEY %s", keygrip);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL);
  if (rc)
    return map_assuan_err (rc);

  sprintf (line, "SETHASH %d ", digestalgo);
  p = line + strlen (line);
  for (i=0; i < digestlen ; i++, p += 2 )
    sprintf (p, "%02X", digest[i]);
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL);
  if (rc)
    return map_assuan_err (rc);

  init_membuf (&data, 1024);
  rc = assuan_transact (agent_ctx, "PKSIGN",
                        membuf_data_cb, &data, NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return map_assuan_err (rc);
    }
  *r_buf = get_membuf (&data, r_buflen);

  /* FIXME: check that the returned S-Exp is valid! */

  return *r_buf? 0 : GNUPG_Out_Of_Core;
}




/* Handle a CIPHERTEXT inquiry.  Note, we only send the data,
   assuan_transact talkes care of flushing and writing the end */
static AssuanError
inq_ciphertext_cb (void *opaque, const char *keyword)
{
  struct cipher_parm_s *parm = opaque; 
  AssuanError rc;

  assuan_begin_confidential (parm->ctx);
  rc = assuan_send_data (parm->ctx, parm->ciphertext, parm->ciphertextlen);
  assuan_end_confidential (parm->ctx);
  return rc; 
}


/* Call the agent to do a decrypt operation using the key identified by
   the hex string KEYGRIP. */
int
gpgsm_agent_pkdecrypt (const char *keygrip,
                       KsbaConstSexp ciphertext, 
                       char **r_buf, size_t *r_buflen )
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct membuf data;
  struct cipher_parm_s cipher_parm;
  size_t n, len;
  char *buf, *endp;
  size_t ciphertextlen;
  
  if (!keygrip || strlen(keygrip) != 40 || !ciphertext || !r_buf || !r_buflen)
    return GNUPG_Invalid_Value;
  *r_buf = NULL;

  ciphertextlen = gcry_sexp_canon_len (ciphertext, 0, NULL, NULL);
  if (!ciphertextlen)
    return GNUPG_Invalid_Value;

  rc = start_agent ();
  if (rc)
    return rc;

  rc = assuan_transact (agent_ctx, "RESET", NULL, NULL, NULL, NULL);
  if (rc)
    return map_assuan_err (rc);

  assert ( DIM(line) >= 50 );
  snprintf (line, DIM(line)-1, "SETKEY %s", keygrip);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL);
  if (rc)
    return map_assuan_err (rc);

  init_membuf (&data, 1024);
  cipher_parm.ctx = agent_ctx;
  cipher_parm.ciphertext = ciphertext;
  cipher_parm.ciphertextlen = ciphertextlen;
  rc = assuan_transact (agent_ctx, "PKDECRYPT",
                        membuf_data_cb, &data,
                        inq_ciphertext_cb, &cipher_parm);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return map_assuan_err (rc);
    }

  put_membuf (&data, "", 1); /* make sure it is 0 terminated */
  buf = get_membuf (&data, &len);
  if (!buf)
    return seterr (Out_Of_Core);
  assert (len);
  len--; /* remove the terminating 0 */
  n = strtoul (buf, &endp, 10);
  if (!n || *endp != ':')
    return seterr (Invalid_Sexp);
  endp++;
  if (endp-buf+n > len)
    return seterr (Invalid_Sexp); /* oops len does not match internal len*/
  memmove (buf, endp, n);
  *r_buflen = n;
  *r_buf = buf;
  return 0;
}





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



/* Call the agent to generate a newkey */
int
gpgsm_agent_genkey (KsbaConstSexp keyparms, KsbaSexp *r_pubkey)
{
  int rc;
  struct genkey_parm_s gk_parm;
  struct membuf data;
  size_t len;
  char *buf;

  *r_pubkey = NULL;
  rc = start_agent ();
  if (rc)
    return rc;

  rc = assuan_transact (agent_ctx, "RESET", NULL, NULL, NULL, NULL);
  if (rc)
    return map_assuan_err (rc);

  init_membuf (&data, 1024);
  gk_parm.ctx = agent_ctx;
  gk_parm.sexp = keyparms;
  gk_parm.sexplen = gcry_sexp_canon_len (keyparms, 0, NULL, NULL);
  if (!gk_parm.sexplen)
    return GNUPG_Invalid_Value;
  rc = assuan_transact (agent_ctx, "GENKEY",
                        membuf_data_cb, &data, 
                        inq_genkey_parms, &gk_parm);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return map_assuan_err (rc);
    }
  buf = get_membuf (&data, &len);
  if (!buf)
    return GNUPG_Out_Of_Core;
  if (!gcry_sexp_canon_len (buf, len, NULL, NULL))
    {
      xfree (buf);
      return GNUPG_Invalid_Sexp;
    }
  *r_pubkey = buf;
  return 0;
}


/* Ask the agent whether the certificate is in the list of trusted
   keys */
int
gpgsm_agent_istrusted (KsbaCert cert)
{
  int rc;
  char *fpr;
  char line[ASSUAN_LINELENGTH];

  rc = start_agent ();
  if (rc)
    return rc;

  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  if (!fpr)
    {
      log_error ("error getting the fingerprint\n");
      return seterr (General_Error);
    }

  snprintf (line, DIM(line)-1, "ISTRUSTED %s", fpr);
  line[DIM(line)-1] = 0;
  xfree (fpr);

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL);
  return map_assuan_err (rc);
}


/* Ask the agent whether the a corresponding secret key is available
   for the given keygrip */
int
gpgsm_agent_havekey (const char *hexkeygrip)
{
  int rc;
  char line[ASSUAN_LINELENGTH];

  rc = start_agent ();
  if (rc)
    return rc;

  if (!hexkeygrip || strlen (hexkeygrip) != 40)
    return GNUPG_Invalid_Value;

  snprintf (line, DIM(line)-1, "HAVEKEY %s", hexkeygrip);
  line[DIM(line)-1] = 0;

  rc = assuan_transact (agent_ctx, line, NULL, NULL, NULL, NULL);
  return map_assuan_err (rc);
}
