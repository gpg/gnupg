/* call-dirmngr.c - communication with the dromngr 
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

static ASSUAN_CONTEXT dirmngr_ctx = NULL;

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



/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
static int
start_dirmngr (void)
{
  int rc;
  char *infostr, *p;

  if (dirmngr_ctx)
    return 0; /* fixme: We need a context for each thread or serialize
                 the access to the agent (which is suitable given that
                 the agent is not MT */

  infostr = getenv ("DIRMNGR_INFO");
  if (!infostr)
    {
      const char *pgmname;
      ASSUAN_CONTEXT ctx;
      const char *argv[3];

      log_info (_("no running dirmngr - starting one\n"));
      
      if (fflush (NULL))
        {
          log_error ("error flushing pending output: %s\n", strerror (errno));
          return seterr (Write_Error);
        }

      if (!opt.dirmngr_program || !*opt.dirmngr_program)
        opt.dirmngr_program = "/usr/sbin/dirmngr";
      if ( !(pgmname = strrchr (opt.dirmngr_program, '/')))
        pgmname = opt.dirmngr_program;
      else
        pgmname++;

      argv[0] = pgmname;
      argv[1] = "--server";
      argv[2] = NULL;

      /* connect to the agent and perform initial handshaking */
      rc = assuan_pipe_connect (&ctx, opt.dirmngr_program, (char**)argv, 0);
      if (rc)
        {
          log_error ("can't connect to the dirmngr: %s\n", assuan_strerror (rc));
          return seterr (No_Dirmngr);
        }
      dirmngr_ctx = ctx;
    }
  else
    {
      infostr = xstrdup (infostr);
      if ( !(p = strchr (infostr, ':')) || p == infostr
           /* || (p-infostr)+1 >= sizeof client_addr.sun_path */)
        {
          log_error (_("malformed DIRMNGR_INFO environment variable\n"));
          xfree (infostr);
          return seterr (General_Error);
        }
      *p = 0;
      log_error (_("socket based dirmngr communication not yet implemented\n"));
      return seterr (Not_Implemented);
    }

  log_debug ("connection to dirmngr established\n");
  return 0;
}



/* Handle a SENDCERT inquiry. */
static AssuanError
inq_certificate (void *opaque, const char *line)
{
  AssuanError rc;

  if (strncmp (line, "SENDCERT ", 9) || !line[9])
    {
      log_error ("unsupported inquiry `%s'\n", line);
      return ASSUAN_Inquire_Unknown;
    }

  /*  rc = assuan_send_data (parm->ctx, parm->sexp, parm->sexplen);*/
  rc = 0;
  return rc; 
}



/* Call the directory manager to check whether the certificate is valid
   Returns 0 for valid or usually one of the errors:

  GNUPG_Certificate_Revoked
  GNUPG_No_CRL_Known
  GNUPG_CRL_Too_Old
 */
int
gpgsm_dirmngr_isvalid (KsbaCert cert)
{
  int rc;
  char *certid;
  char line[ASSUAN_LINELENGTH];

  rc = start_dirmngr ();
  if (rc)
    return rc;

  certid = gpgsm_get_certid (cert);
  if (!certid)
    {
      log_error ("error getting the certificate ID\n");
      return seterr (General_Error);
    }

  snprintf (line, DIM(line)-1, "ISVALID %s", certid);
  line[DIM(line)-1] = 0;
  xfree (certid);

  rc = assuan_transact (dirmngr_ctx, line, NULL, NULL, inq_certificate, NULL);
  return map_assuan_err (rc);
}



