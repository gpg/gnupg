/* call-scd.c - fork of the scdaemon to do SC operations
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

/* Fixme: For now we have serialized all access to the scdaemon which
   make sense becuase the scdaemon can't handle concurrent connections
   right now.  We should however keep a list of connections and lock
   just that connection - it migth make sense to implemtn parts of
   this in Assuan.*/

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef USE_GNU_PTH
# include <pth.h>
#endif

#include "agent.h"
#include "../assuan/assuan.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

static ASSUAN_CONTEXT scd_ctx = NULL;
#ifdef USE_GNU_PTH
static pth_mutex_t scd_lock = PTH_MUTEX_INIT;
#endif

/* callback parameter for learn card */
struct learn_parm_s {
  void (*kpinfo_cb)(void*, const char *);
  void *kpinfo_cb_arg;
};

struct inq_needpin_s {
  ASSUAN_CONTEXT ctx;
  int (*getpin_cb)(void *, const char *, char*, size_t);
  void *getpin_cb_arg;
};

struct membuf {
  size_t len;
  size_t size;
  char *buf;
  int out_of_core;
};



/* A simple implementation of a dynamic buffer.  Use init_membuf() to
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




static int 
unlock_scd (int rc)
{
#ifdef USE_GNU_PTH
  if (!pth_mutex_release (&scd_lock))
    {
      log_error ("failed to release the SCD lock\n");
      if (!rc)
        rc = GNUPG_Internal_Error;
    }
#endif
  return rc;
}

/* Fork off the SCdaemon if this has not already been done */
static int
start_scd (void)
{
  int rc;
  const char *pgmname;
  ASSUAN_CONTEXT ctx;
  const char *argv[3];

#ifdef USE_GNU_PTH
  if (!pth_mutex_acquire (&scd_lock, 0, NULL))
    {
      log_error ("failed to acquire the SCD lock\n");
      return GNUPG_Internal_Error;
    }
#endif

  if (scd_ctx)
    return 0; /* No need to serialize things because the agent is
                 expected to tun as a single-thread (or may be in
                 future using libpth) */

  if (opt.verbose)
    log_info ("no running SCdaemon - starting it\n");
      
  if (fflush (NULL))
    {
      log_error ("error flushing pending output: %s\n", strerror (errno));
      return unlock_scd (seterr (Write_Error));
    }

  /* FIXME: change the default location of the program */
  if (!opt.scdaemon_program || !*opt.scdaemon_program)
    opt.scdaemon_program = "../scd/scdaemon";
  if ( !(pgmname = strrchr (opt.scdaemon_program, '/')))
    pgmname = opt.scdaemon_program;
  else
    pgmname++;

  argv[0] = pgmname;
  argv[1] = "--server";
  argv[2] = NULL;

  /* connect to the pinentry and perform initial handshaking */
  rc = assuan_pipe_connect (&ctx, opt.scdaemon_program, (char**)argv, 0);
  if (rc)
    {
      log_error ("can't connect to the SCdaemon: %s\n",
                 assuan_strerror (rc));
      return unlock_scd (seterr (No_Scdaemon));
    }
  scd_ctx = ctx;
  
  if (DBG_ASSUAN)
    log_debug ("connection to SCdaemon established\n");
  return 0;
}



static AssuanError
learn_status_cb (void *opaque, const char *line)
{
  struct learn_parm_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;
  if (keywordlen == 11 && !memcmp (keyword, "KEYPAIRINFO", keywordlen))
    {
      parm->kpinfo_cb (parm->kpinfo_cb_arg, line);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      log_debug ("learn_status_cb: serialno `%s'\n", line);
    }
  else
    log_debug ("learn_status_cb: ignoring `%.*s'\n", keywordlen, keyword);
  
  return 0;
}

/* Perform the learn command and return a list of all private keys
   stored on the card. */
int
agent_card_learn (void (*kpinfo_cb)(void*, const char *), void *kpinfo_cb_arg)
{
  int rc;
  struct learn_parm_s parm;

  rc = start_scd ();
  if (rc)
    return rc;

  memset (&parm, 0, sizeof parm);
  parm.kpinfo_cb = kpinfo_cb;
  parm.kpinfo_cb_arg = kpinfo_cb_arg;
  rc = assuan_transact (scd_ctx, "LEARN --force",
                        NULL, NULL, NULL, NULL,
                        learn_status_cb, &parm);
  if (rc)
    return unlock_scd (map_assuan_err (rc));

  return unlock_scd (0);
}



static AssuanError
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
        return ASSUAN_Unexpected_Status;
      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;
      if (!n || (n&1)|| !(spacep (s) || !*s) )
        return ASSUAN_Invalid_Status;
      *serialno = xtrymalloc (n+1);
      if (!*serialno)
        return ASSUAN_Out_Of_Core;
      memcpy (*serialno, line, n);
      (*serialno)[n] = 0;
    }
  
  return 0;
}

/* Return the serial number of the card or an appropriate error.  The
   serial number is returned as a hexstring. */
int
agent_card_serialno (char **r_serialno)
{
  int rc;
  char *serialno = NULL;

  rc = start_scd ();
  if (rc)
    return rc;

  /* Hmm, do we really need this reset - scddaemon should do this or
     we can do this if we for some reason figure out that the
     operation might have failed due to a missing RESET.  Hmmm, I feel
     this is really SCdaemon's duty */
  rc = assuan_transact (scd_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_scd (map_assuan_err (rc));

  rc = assuan_transact (scd_ctx, "SERIALNO",
                        NULL, NULL, NULL, NULL,
                        get_serialno_cb, &serialno);
  if (rc)
    {
      xfree (serialno);
      return unlock_scd (map_assuan_err (rc));
    }
  *r_serialno = serialno;
  return unlock_scd (0);
}


static AssuanError
membuf_data_cb (void *opaque, const void *buffer, size_t length)
{
  struct membuf *data = opaque;

  if (buffer)
    put_membuf (data, buffer, length);
  return 0;
}
  
/* Handle the NEEDPIN inquiry. */
static AssuanError
inq_needpin (void *opaque, const char *line)
{
  struct inq_needpin_s *parm = opaque;
  char *pin;
  size_t pinlen;
  int rc;

  if (!(!strncmp (line, "NEEDPIN", 7) && (line[7] == ' ' || !line[7])))
    {
      log_error ("unsupported inquiry `%s'\n", line);
      return ASSUAN_Inquire_Unknown;
    }
  line += 7;

  pinlen = 90;
  pin = gcry_malloc_secure (pinlen);
  if (!pin)
    return ASSUAN_Out_Of_Core;

  rc = parm->getpin_cb (parm->getpin_cb_arg, line, pin, pinlen);
  if (rc)
    rc = ASSUAN_Canceled;
  if (!rc)
    rc = assuan_send_data (parm->ctx, pin, pinlen);
  xfree (pin);

  return rc;
}



/* Create a signature using the current card */
int
agent_card_pksign (const char *keyid,
                   int (*getpin_cb)(void *, const char *, char*, size_t),
                   void *getpin_cb_arg,
                   const unsigned char *indata, size_t indatalen,
                   char **r_buf, size_t *r_buflen)
{
  int rc, i;
  char *p, line[ASSUAN_LINELENGTH];
  struct membuf data;
  struct inq_needpin_s inqparm;
  size_t len;
  unsigned char *sigbuf;
  size_t sigbuflen;

  *r_buf = NULL;
  rc = start_scd ();
  if (rc)
    return rc;

  if (indatalen*2 + 50 > DIM(line))
    return unlock_scd (seterr (General_Error));

  sprintf (line, "SETDATA ");
  p = line + strlen (line);
  for (i=0; i < indatalen ; i++, p += 2 )
    sprintf (p, "%02X", indata[i]);
  rc = assuan_transact (scd_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_scd (map_assuan_err (rc));

  init_membuf (&data, 1024);
  inqparm.ctx = scd_ctx;
  inqparm.getpin_cb = getpin_cb;
  inqparm.getpin_cb_arg = getpin_cb_arg;
  snprintf (line, DIM(line)-1, "PKSIGN %s", keyid);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (scd_ctx, line,
                        membuf_data_cb, &data,
                        inq_needpin, &inqparm,
                        NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return unlock_scd (map_assuan_err (rc));
    }
  sigbuf = get_membuf (&data, &sigbuflen);

  /* create an S-expression from it which is formatted like this:
     "(7:sig-val(3:rsa(1:sSIGBUFLEN:SIGBUF)))" */
  *r_buflen = 21 + 11 + sigbuflen + 4;
  *r_buf = xtrymalloc (*r_buflen);
  if (!*r_buf)
    {
      xfree (*r_buf);
      return unlock_scd (GNUPG_Out_Of_Core);
    }
  p = stpcpy (*r_buf, "(7:sig-val(3:rsa(1:s" );
  sprintf (p, "%u:", (unsigned int)sigbuflen);
  p += strlen (p);
  memcpy (p, sigbuf, sigbuflen);
  p += sigbuflen;
  strcpy (p, ")))");
  xfree (sigbuf);

  assert (gcry_sexp_canon_len (*r_buf, *r_buflen, NULL, NULL));
  return unlock_scd (0);
}

/* Decipher INDATA using the current card. Note that the returned value is */
int
agent_card_pkdecrypt (const char *keyid,
                   int (*getpin_cb)(void *, const char *, char*, size_t),
                   void *getpin_cb_arg,
                   const unsigned char *indata, size_t indatalen,
                   char **r_buf, size_t *r_buflen)
{
  int rc, i;
  char *p, line[ASSUAN_LINELENGTH];
  struct membuf data;
  struct inq_needpin_s inqparm;
  size_t len;

  *r_buf = NULL;
  rc = start_scd ();
  if (rc)
    return rc;

  /* FIXME: use secure memory where appropriate */
  if (indatalen*2 + 50 > DIM(line))
    return unlock_scd (seterr (General_Error));

  sprintf (line, "SETDATA ");
  p = line + strlen (line);
  for (i=0; i < indatalen ; i++, p += 2 )
    sprintf (p, "%02X", indata[i]);
  rc = assuan_transact (scd_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_scd (map_assuan_err (rc));

  init_membuf (&data, 1024);
  inqparm.ctx = scd_ctx;
  inqparm.getpin_cb = getpin_cb;
  inqparm.getpin_cb_arg = getpin_cb_arg;
  snprintf (line, DIM(line)-1, "PKDECRYPT %s", keyid);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (scd_ctx, line,
                        membuf_data_cb, &data,
                        inq_needpin, &inqparm,
                        NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return unlock_scd (map_assuan_err (rc));
    }
  *r_buf = get_membuf (&data, r_buflen);
  if (!*r_buf)
    return unlock_scd (GNUPG_Out_Of_Core);

  return unlock_scd (0);
}



/* Read a certificate with ID into R_BUF and R_BUFLEN. */
int
agent_card_readcert (const char *id, char **r_buf, size_t *r_buflen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct membuf data;
  size_t len;

  *r_buf = NULL;
  rc = start_scd ();
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  snprintf (line, DIM(line)-1, "READCERT %s", id);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (scd_ctx, line,
                        membuf_data_cb, &data,
                        NULL, NULL,
                        NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return unlock_scd (map_assuan_err (rc));
    }
  *r_buf = get_membuf (&data, r_buflen);
  if (!*r_buf)
    return unlock_scd (GNUPG_Out_Of_Core);

  return unlock_scd (0);
}



/* Read a key with ID and return it in an allocate buffer pointed to
   by r_BUF as a valid S-expression. */
int
agent_card_readkey (const char *id, unsigned char **r_buf)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct membuf data;
  size_t len, buflen;

  *r_buf = NULL;
  rc = start_scd ();
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  snprintf (line, DIM(line)-1, "READKEY %s", id);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (scd_ctx, line,
                        membuf_data_cb, &data,
                        NULL, NULL,
                        NULL, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return unlock_scd (map_assuan_err (rc));
    }
  *r_buf = get_membuf (&data, &buflen);
  if (!*r_buf)
    return unlock_scd (GNUPG_Out_Of_Core);

  if (!gcry_sexp_canon_len (*r_buf, buflen, NULL, NULL))
    {
      xfree (*r_buf); *r_buf = NULL;
      return unlock_scd (GNUPG_Invalid_Value);
    }

  return unlock_scd (0);
}



