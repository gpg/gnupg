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

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

static ASSUAN_CONTEXT scd_ctx = NULL;

/* callback parameter for learn card */
struct learn_parm_s {
  int lines;
  size_t size;
  char *buffer;
};




/* Fork off the SCdaemon if this has not already been done */
static int
start_scd (void)
{
  int rc;
  const char *pgmname;
  ASSUAN_CONTEXT ctx;
  const char *argv[3];

  if (scd_ctx)
    return 0; /* No need to serialize things because the agent is
                 expected to tun as a single-thread (or may be in
                 future using libpth) */

  log_debug ("no running SCdaemon - starting it\n");
      
  if (fflush (NULL))
    {
      log_error ("error flushing pending output: %s\n", strerror (errno));
      return seterr (Write_Error);
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
      return seterr (No_Scdaemon);
    }
  scd_ctx = ctx;
  
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
      log_debug ("learn_status_cb: keypair `%s'\n", line);
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
agent_learn_card (void)
{
  int rc;
  struct learn_parm_s parm;

  rc = start_scd ();
  if (rc)
    return rc;

  rc = assuan_transact (scd_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return map_assuan_err (rc);

  memset (&parm, 0, sizeof parm);

  rc = assuan_transact (scd_ctx, "LEARN --force",
                        NULL, NULL, NULL, NULL,
                        learn_status_cb, &parm);
  if (rc)
    return map_assuan_err (rc);

  return 0;
}

