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
static int force_pipe_server = 0;

struct inq_certificate_parm_s {
  ASSUAN_CONTEXT ctx;
  KsbaCert cert;
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
  ASSUAN_CONTEXT ctx;

  if (dirmngr_ctx)
    return 0; /* fixme: We need a context for each thread or serialize
                 the access to the dirmngr */

  infostr = force_pipe_server? NULL : getenv ("DIRMNGR_INFO");
  if (!infostr)
    {
      const char *pgmname;
      const char *argv[3];

      if (opt.verbose)
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
    }
  else
    {
      int prot;
      int pid;

      infostr = xstrdup (infostr);
      if ( !(p = strchr (infostr, ':')) || p == infostr)
        {
          log_error (_("malformed DIRMNGR_INFO environment variable\n"));
          xfree (infostr);
          force_pipe_server = 1;
          return start_dirmngr ();
        }
      *p++ = 0;
      pid = atoi (p);
      while (*p && *p != ':')
        p++;
      prot = *p? atoi (p+1) : 0;
      if (prot != 1)
        {
          log_error (_("dirmngr protocol version %d is not supported\n"),
                     prot);
          xfree (infostr);
          force_pipe_server = 1;
          return start_dirmngr ();
        }

      rc = assuan_socket_connect (&ctx, infostr, pid);
      xfree (infostr);
      if (rc == ASSUAN_Connect_Failed)
        {
          log_error (_("can't connect to the dirmngr - trying fall back\n"));
          force_pipe_server = 1;
          return start_dirmngr ();
        }
    }

  if (rc)
    {
      log_error ("can't connect to the dirmngr: %s\n", assuan_strerror (rc));
      return seterr (No_Dirmngr);
    }
  dirmngr_ctx = ctx;

  if (DBG_ASSUAN)
    log_debug ("connection to dirmngr established\n");
  return 0;
}



/* Handle a SENDCERT inquiry. */
static AssuanError
inq_certificate (void *opaque, const char *line)
{
  struct inq_certificate_parm_s *parm = opaque;
  AssuanError rc;
  const unsigned char *der;
  size_t derlen;

  if (!(!strncmp (line, "SENDCERT", 8) && (line[8] == ' ' || !line[8])))
    {
      log_error ("unsupported inquiry `%s'\n", line);
      return ASSUAN_Inquire_Unknown;
    }
  line += 8;

  if (!*line)
    { /* send the current certificate */
      der = ksba_cert_get_image (parm->cert, &derlen);
      if (!der)
        rc = ASSUAN_Inquire_Error;
      else
        rc = assuan_send_data (parm->ctx, der, derlen);
    }
  else 
    { /* send the given certificate */
      int err;
      KsbaCert cert;

      err = gpgsm_find_cert (line, &cert);
      if (err)
        {
          log_error ("certificate not found: %s\n", gnupg_strerror (err));
          rc = ASSUAN_Inquire_Error;
        }
      else
        {
          der = ksba_cert_get_image (cert, &derlen);
          if (!der)
            rc = ASSUAN_Inquire_Error;
          else
            rc = assuan_send_data (parm->ctx, der, derlen);
          ksba_cert_release (cert);
        }
    }

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
  struct inq_certificate_parm_s parm;

  rc = start_dirmngr ();
  if (rc)
    return rc;

  certid = gpgsm_get_certid (cert);
  if (!certid)
    {
      log_error ("error getting the certificate ID\n");
      return seterr (General_Error);
    }

  parm.ctx = dirmngr_ctx;
  parm.cert = cert;

  snprintf (line, DIM(line)-1, "ISVALID %s", certid);
  line[DIM(line)-1] = 0;
  xfree (certid);

  rc = assuan_transact (dirmngr_ctx, line, NULL, NULL,
                        inq_certificate, &parm, NULL, NULL);
  return map_assuan_err (rc);
}


