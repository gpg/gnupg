/* gpg-connect-agent.c - Tool to connect to the agent.
 *	Copyright (C) 2005 Free Software Foundation, Inc.
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
#include <assuan.h>

#include "i18n.h"
#include "../common/util.h"
#include "../common/asshelp.h"



/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,
    oQuiet      = 'q',
    oVerbose	= 'v',

    oNoVerbose	= 500,
    oHomedir

  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] =
  {
    { 301, NULL, 0, N_("@\nOptions:\n ") },
    
    { oVerbose, "verbose",  0, N_("verbose") },
    { oQuiet, "quiet",      0, N_("quiet") },

    /* hidden options */
    { oNoVerbose, "no-verbose",  0, "@"},
    { oHomedir, "homedir", 2, "@" },   
    {0}
  };


/* We keep all global options in the structure OPT.  */
struct
{
  int verbose;		/* Verbosity level.  */
  int quiet;		/* Be extra quiet.  */
  const char *homedir;  /* Configuration directory name */

} opt;


/*-- local prototypes --*/
static int read_and_print_response (assuan_context_t ctx);
static assuan_context_t start_agent (void);




/* Print usage information and and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "gpg-connect-agent (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
      break;
    case 1:
    case 40: p = _("Usage: gpg-connect-agent [options] (-h for help)");
      break;
    case 41:
      p = _("Syntax: gpg-connect-agent [options]\n"
            "Connect to a running agent and send commands\n");
      break;
    case 31: p = "\nHome: "; break;
    case 32: p = opt.homedir; break;
    case 33: p = "\n"; break;

    default: p = NULL; break;
    }
  return p;
}


/* Initialize the gettext system. */
static void
i18n_init(void)
{
#ifdef USE_SIMPLE_GETTEXT
  set_gettext_file (PACKAGE_GT);
#else
# ifdef ENABLE_NLS
  setlocale (LC_ALL, "" );
  bindtextdomain (PACKAGE_GT, LOCALEDIR);
  textdomain (PACKAGE_GT);
# endif
#endif
}


/* gpg-connect-agent's entry point. */
int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  const char *fname;
  int no_more_options = 0;
  assuan_context_t ctx;
  char *line;
  size_t linesize;
  int rc;

  set_strusage (my_strusage);
  log_set_prefix ("gpg-connect-agent", 1);

  i18n_init();

  opt.homedir = default_homedir ();

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags =  1;  /* Do not remove the args.  */
  while (!no_more_options && optfile_parse (NULL, NULL, NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
	case oQuiet:     opt.quiet = 1; break;
        case oVerbose:   opt.verbose++; break;
        case oNoVerbose: opt.verbose = 0; break;
        case oHomedir:   opt.homedir = pargs.r.ret_str; break;

        default: pargs.err = 2; break;
	}
    }

  if (log_get_errorcount (0))
    exit (2);
  
  fname = argc ? *argv : NULL;

  ctx = start_agent ();
  line = NULL;
  linesize = 0;
  for (;;)
    {
      int n;
      size_t maxlength;

      maxlength = 2048;
      n = read_line (stdin, &line, &linesize, &maxlength);
      if (n < 0)
        {
          log_error (_("error reading input: %s\n"), strerror (errno));
          exit (1);
        }
      if (!n)
        break; /* EOF */
      if (!maxlength)
        {
          log_error (_("line too long - skipped\n"));
          continue;
        }
      if (memchr (line, 0, n))
        log_info (_("line shortened due to embedded Nul character\n"));
      if (line[n-1] == '\n')
        line[n-1] = 0;
      rc = assuan_write_line (ctx, line);
      if (rc)
        {
          log_info (_("sending line failed: %s\n"), assuan_strerror (rc) );
          continue;
        }
      if (*line == '#' || !*line)
        continue; /* Don't expect a response for a coment line. */

      rc = read_and_print_response (ctx);
      if (rc)
        log_info (_("receiving line failed: %s\n"), assuan_strerror (rc) );
    }

  if (opt.verbose)
    log_info ("closing connection to agent\n");
  
  return 0; 
}


/* Read all response lines from server and print them.  Returns 0 on
   success or an assuan error code. */
static int
read_and_print_response (assuan_context_t ctx)
{
  char *line;
  int linelen;
  assuan_error_t rc;

  for (;;)
    {
      do 
        {
          rc = assuan_read_line (ctx, &line, &linelen);
          if (rc)
            return rc;
        }    
      while (*line == '#' || !linelen);

      if (linelen >= 1
          && line[0] == 'D' && line[1] == ' ')
        {
          fwrite (line, linelen, 1, stdout);
          putchar ('\n');
        }
      else if (linelen >= 1
               && line[0] == 'S' 
               && (line[1] == '\0' || line[1] == ' '))
        {
          fwrite (line, linelen, 1, stdout);
          putchar ('\n');
        }  
      else if (linelen >= 2
               && line[0] == 'O' && line[1] == 'K'
               && (line[2] == '\0' || line[2] == ' '))
        {
          fwrite (line, linelen, 1, stdout);
          putchar ('\n');
          return 0;
        }
      else if (linelen >= 3
               && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
               && (line[3] == '\0' || line[3] == ' '))
        {
          fwrite (line, linelen, 1, stdout);
          putchar ('\n');
          return 0;
        }  
      else if (linelen >= 7
               && line[0] == 'I' && line[1] == 'N' && line[2] == 'Q'
               && line[3] == 'U' && line[4] == 'I' && line[5] == 'R'
               && line[6] == 'E' 
               && (line[7] == '\0' || line[7] == ' '))
        {
          fwrite (line, linelen, 1, stdout);
          putchar ('\n');
          return 0;
        }
      else if (linelen >= 3
               && line[0] == 'E' && line[1] == 'N' && line[2] == 'D'
               && (line[3] == '\0' || line[3] == ' '))
        {
          fwrite (line, linelen, 1, stdout);
          putchar ('\n');
          /* Received from server, thus more responses are expected.  */
        }
      else
        return ASSUAN_Invalid_Response;
    }
}




/* Connect to teh agebnt and send the standard options.  */
static assuan_context_t
start_agent (void)
{
  int rc = 0;
  char *infostr, *p;
  assuan_context_t ctx;

  infostr = getenv ("GPG_AGENT_INFO");
  if (!infostr || !*infostr)
    {
      char *sockname;

      /* Check whether we can connect at the standard socket.  */
      sockname = make_filename (opt.homedir, "S.gpg-agent", NULL);
      rc = assuan_socket_connect (&ctx, sockname, 0);
      xfree (sockname);
    }
  else
    {
      int prot;
      int pid;

      infostr = xstrdup (infostr);
      if ( !(p = strchr (infostr, PATHSEP_C)) || p == infostr)
        {
          log_error (_("malformed GPG_AGENT_INFO environment variable\n"));
          xfree (infostr);
          exit (1);
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
          exit (1);
        }

      rc = assuan_socket_connect (&ctx, infostr, pid);
      xfree (infostr);
    }

  if (rc)
    {
      log_error ("can't connect to the agent: %s\n", assuan_strerror (rc));
      exit (1);
    }

  if (opt.verbose)
    log_info ("connection to agent established\n");

  rc = assuan_transact (ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    {
      log_error (_("error sending %s command: %s\n"), "RESET", 
                 assuan_strerror (rc));
      exit (1);
    }

  rc = send_pinentry_environment (ctx, GPG_ERR_SOURCE_DEFAULT,
                                  NULL, NULL, NULL, NULL, NULL);
  if (rc)
    {
      log_error (_("error sending standard options: %s\n"), gpg_strerror (rc));
      exit (1);
    }

  return ctx;
}
