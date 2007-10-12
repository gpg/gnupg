/* gpg-connect-agent.c - Tool to connect to the agent.
 *	Copyright (C) 2005, 2007 Free Software Foundation, Inc.
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
#include <ctype.h>
#include <assuan.h>

#include "i18n.h"
#include "../common/util.h"
#include "../common/asshelp.h"
#include "../common/sysutils.h"
#include "../common/membuf.h"

/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,
    oQuiet      = 'q',
    oVerbose	= 'v',
    oRawSocket  = 'S',
    oExec       = 'E',
    oRun        = 'r',

    oNoVerbose	= 500,
    oHomedir,
    oHex,
    oDecode,
    oNoExtConnect

  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] =
  {
    { 301, NULL, 0, N_("@\nOptions:\n ") },
    
    { oVerbose, "verbose",  0, N_("verbose") },
    { oQuiet, "quiet",      0, N_("quiet") },
    { oHex,   "hex",        0, N_("print data out hex encoded") },
    { oDecode,"decode",     0, N_("decode received data lines") },
    { oRawSocket, "raw-socket", 2, N_("|NAME|connect to Assuan socket NAME")},
    { oExec, "exec", 0, N_("run the Assuan server given on the command line")},
    { oNoExtConnect, "no-ext-connect",
                            0, N_("do not use extended connect mode")},
    { oRun,  "run", 2,         N_("|FILE|run commands from FILE on startup")},
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
  int hex;              /* Print data lines in hex format. */
  int decode;           /* Decode received data lines.  */
  const char *raw_socket; /* Name of socket to connect in raw mode. */
  int exec;             /* Run the pgm given on the command line. */
  unsigned int connect_flags;    /* Flags used for connecting. */
  int enable_varsubst;  /* Set if variable substitution is enabled.  */
} opt;



/* Definitions for /definq commands and a global linked list with all
   the definitions. */
struct definq_s
{
  struct definq_s *next;
  char *name;     /* Name of inquiry or NULL for any name. */
  int is_prog;     /* True if this is a program to run. */
  char file[1];   /* Name of file or program. */
};
typedef struct definq_s *definq_t;

static definq_t definq_list;
static definq_t *definq_list_tail = &definq_list;


/* Variable definitions and glovbal table.  */
struct variable_s
{
  struct variable_s *next;
  char *value;  /* Malloced value - always a string.  */
  char name[1]; /* Name of the variable.  */
};
typedef struct variable_s *variable_t;

static variable_t variable_table;

/* This is used to store the pid of the server.  */
static pid_t server_pid = (pid_t)(-1);


/* A list of open file descriptors. */
static struct
{
  int inuse;
#ifdef HAVE_W32_SYSTEM
  HANDLE handle;
#endif
} open_fd_table[256];


/*-- local prototypes --*/
static int read_and_print_response (assuan_context_t ctx, int *r_goterr);
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


static char *
gnu_getcwd (void)
{
  char *buffer;
  size_t size = 100;

  for (;;)
    {
      buffer = xmalloc (size+1);
      if (getcwd (buffer, size) == buffer)
        return buffer;
      xfree (buffer);
      if (errno != ERANGE)
        return NULL;
      size *= 2;
    }
}



static const char *
set_var (const char *name, const char *value)
{
  variable_t var;

  for (var = variable_table; var; var = var->next)
    if (!strcmp (var->name, name))
      break;
  if (!var)
    {
      var = xmalloc (sizeof *var + strlen (name));
      var->value = NULL;
      strcpy (var->name, name);
      var->next = variable_table;
      variable_table = var;
    }
  xfree (var->value);
  var->value = value? xstrdup (value) : NULL;
  return var->value;
}    


static void
set_int_var (const char *name, int value)
{
  char numbuf[35];

  snprintf (numbuf, sizeof numbuf, "%d", value);
  set_var (name, numbuf);
}


/* Return the value of a variable.  That value is valid until a
   variable of the name is changed.  Return NULL if not found.  Note
   that envvars are copied to our variable list at the first access
   and not at oprogram start.  */
static const char *
get_var (const char *name)
{
  variable_t var;
  const char *s;

  if (!*name)
    return "";
  for (var = variable_table; var; var = var->next)
    if (!strcmp (var->name, name))
      break;
  if (!var && (s = getenv (name)))
    return set_var (name, s);
  if (!var || !var->value)
    return NULL;
  return var->value;
}



/* Substitute variables in LINE and return a new allocated buffer if
   required.  The function might modify LINE if the expanded version
   fits into it.  */
static char *
substitute_line (char *buffer)
{
  char *line = buffer;
  char *p, *pend;
  const char *value;
  size_t valuelen, n;
  char *result = NULL;

  while (*line)
    {
      p = strchr (line, '$');
      if (!p)
        return result; /* No more variables.  */
      
      if (p[1] == '$') /* Escaped dollar sign. */
        {
          memmove (p, p+1, strlen (p+1)+1);
          line = p + 1;
          continue;
        }
      if (p[1] == '{')
        {
          for (pend=p+2; *pend && *pend != '}' ; pend++)
            ;
          if (!*pend)
            return result; /* Unclosed - don't substitute.  */
        }
      else
        {
          for (pend=p+1; *pend && !spacep (pend) && *pend != '$' ; pend++)
            ;
        }
      if (p[1] == '{' && *pend == '}')
        {
          *pend++ = 0;
          value = get_var (p+2);
        }
      else if (*pend)
        {
          int save = *pend;
          *pend = 0;
          value = get_var (p+1);
          *pend = save;
        }
      else
        value = get_var (p+1);
      if (!value)
        value = "";
      valuelen = strlen (value);
      if (valuelen <= pend - p)
        {
          memcpy (p, value, valuelen);
          p += valuelen;
          n = pend - p;
          if (n)
            memmove (p, p+n, strlen (p+n)+1);
          line = p;
        }
      else
        {
          char *src = result? result : buffer;
          char *dst;

          dst = xmalloc (strlen (src) + valuelen + 1);
          n = p - src;
          memcpy (dst, src, n);
          memcpy (dst + n, value, valuelen);
          n += valuelen;
          strcpy (dst + n, pend);
          line = dst + n;
          free (result);
          result = dst;
        }
    }
  return result;
}



static void
assign_variable (char *line, int syslet)
{
  char *name, *p, *tmp, *free_me;

  /* Get the  name. */
  name = line;
  for (p=name; *p && !spacep (p); p++)
    ;
  if (*p)
    *p++ = 0;
  while (spacep (p))
    p++;

  if (!*p)
    set_var (name, NULL); /* Remove variable.  */ 
  else if (syslet)
    {
      free_me = opt.enable_varsubst? substitute_line (p) : NULL;
      if (free_me)
        p = free_me;
      if (!strcmp (p, "cwd"))
        {
          tmp = gnu_getcwd ();
          if (!tmp)
            log_error ("getcwd failed: %s\n", strerror (errno));
          set_var (name, tmp);
          xfree (tmp);
        }
      else if (!strcmp (p, "homedir"))
        set_var (name, opt.homedir);
      else if (!strcmp (p, "sysconfdir"))
        set_var (name, gnupg_sysconfdir ());
      else if (!strcmp (p, "bindir"))
        set_var (name, gnupg_bindir ());
      else if (!strcmp (p, "libdir"))
        set_var (name, gnupg_libdir ());
      else if (!strcmp (p, "libexecdir"))
        set_var (name, gnupg_libexecdir ());
      else if (!strcmp (p, "datadir"))
        set_var (name, gnupg_datadir ());
      else if (!strcmp (p, "serverpid"))
        set_int_var (name, (int)server_pid);
      else
        {
          log_error ("undefined tag `%s'\n", p);
          log_info  ("valid tags are: cwd, {home,bin,lib,libexec,data}dir, "
                     "serverpid\n");
        }
      xfree (free_me);
    }
  else 
    {
      tmp = opt.enable_varsubst? substitute_line (p) : NULL;
      if (tmp)
        {
          set_var (name, tmp);
          xfree (tmp);
        }
      else
        set_var (name, p);
    }
}


static void
show_variables (void)
{
  variable_t var;

  for (var = variable_table; var; var = var->next)
    if (var->value)
      printf ("%-20s %s\n", var->name, var->value);
}


/* Store an inquire response pattern.  Note, that this function may
   change the content of LINE.  We assume that leading white spaces
   are already removed. */
static void
add_definq (char *line, int is_prog)
{
  definq_t d;
  char *name, *p;

  /* Get name. */
  name = line;
  for (p=name; *p && !spacep (p); p++)
    ;
  if (*p)
    *p++ = 0;
  while (spacep (p))
    p++;

  d = xmalloc (sizeof *d + strlen (p) );
  strcpy (d->file, p);
  d->is_prog = is_prog;
  if ( !strcmp (name, "*"))
    d->name = NULL;
  else
    d->name = xstrdup (name);

  d->next = NULL;
  *definq_list_tail = d;
  definq_list_tail = &d->next;
}


/* Show all inquiry defintions. */
static void
show_definq (void)
{
  definq_t d;

  for (d=definq_list; d; d = d->next)
    if (d->name)
      printf ("%-20s %c %s\n", d->name, d->is_prog? 'p':'f', d->file);
  for (d=definq_list; d; d = d->next)
    if (!d->name)
      printf ("%-20s %c %s\n", "*", d->is_prog? 'p':'f', d->file);
}


/* Clear all inquiry definitions. */
static void
clear_definq (void)
{
  while (definq_list)
    { 
      definq_t tmp = definq_list->next;
      xfree (definq_list->name);
      xfree (definq_list);
      definq_list = tmp;
    }
  definq_list_tail = &definq_list;
}      


static void
do_sendfd (assuan_context_t ctx, char *line)
{
  FILE *fp;
  char *name, *mode, *p;
  int rc, fd;

  /* Get file name. */
  name = line;
  for (p=name; *p && !spacep (p); p++)
    ;
  if (*p)
    *p++ = 0;
  while (spacep (p))
    p++;

  /* Get mode.  */
  mode = p;
  if (!*mode)
    mode = "r";
  else
    {
      for (p=mode; *p && !spacep (p); p++)
        ;
      if (*p)
        *p++ = 0;
    }

  /* Open and send. */
  fp = fopen (name, mode);
  if (!fp)
    {
      log_error ("can't open `%s' in \"%s\" mode: %s\n",
                 name, mode, strerror (errno));
      return;
    }
  fd = fileno (fp);

  if (opt.verbose)
    log_error ("file `%s' opened in \"%s\" mode, fd=%d\n",
               name, mode, fd);

  rc = assuan_sendfd (ctx, INT2FD (fd) );
  if (rc)
    log_error ("sending descriptor %d failed: %s\n", fd, gpg_strerror (rc));
  fclose (fp);
}


static void
do_recvfd (assuan_context_t ctx, char *line)
{
  log_info ("This command has not yet been implemented\n");
}


static void
do_open (char *line)
{
  FILE *fp;
  char *varname, *name, *mode, *p;
  int fd;

#ifdef HAVE_W32_SYSTEM
  if (server_pid == (pid_t)(-1))
    {
      log_error ("the pid of the server is unknown\n");
      log_info ("use command \"/serverpid\" first\n");
      return;
    }
#endif

  /* Get variable name. */
  varname = line;
  for (p=varname; *p && !spacep (p); p++)
    ;
  if (*p)
    *p++ = 0;
  while (spacep (p))
    p++;

  /* Get file name. */
  name = p;
  for (p=name; *p && !spacep (p); p++)
    ;
  if (*p)
    *p++ = 0;
  while (spacep (p))
    p++;

  /* Get mode.  */
  mode = p;
  if (!*mode)
    mode = "r";
  else
    {
      for (p=mode; *p && !spacep (p); p++)
        ;
      if (*p)
        *p++ = 0;
    }

  /* Open and send. */
  fp = fopen (name, mode);
  if (!fp)
    {
      log_error ("can't open `%s' in \"%s\" mode: %s\n",
                 name, mode, strerror (errno));
      return;
    }
  fd = fileno (fp);
  if (fd >= 0 && fd < DIM (open_fd_table))
    {
      open_fd_table[fd].inuse = 1;
#ifdef HAVE_W32_SYSTEM
      {
        HANDLE prochandle, handle, newhandle;

        handle = (void*)_get_osfhandle (fd);
     
        prochandle = OpenProcess (PROCESS_DUP_HANDLE, FALSE, server_pid);
        if (!prochandle)
          {
            log_error ("failed to open the server process\n");
            close (fd);
            return;
          }

        if (!DuplicateHandle (GetCurrentProcess(), handle,
                              prochandle, &newhandle, 0,
                              TRUE, DUPLICATE_SAME_ACCESS ))
          {
            log_error ("failed to duplicate the handle\n");
            close (fd);
            CloseHandle (prochandle);
            return;
          }
        CloseHandle (prochandle);
        open_fd_table[fd].handle = newhandle;
      }
      if (opt.verbose)
        log_info ("file `%s' opened in \"%s\" mode, fd=%d  (libc=%d)\n",
                   name, mode, (int)open_fd_table[fd].handle, fd);
      set_int_var (varname, (int)open_fd_table[fd].handle);
#else  
      if (opt.verbose)
        log_info ("file `%s' opened in \"%s\" mode, fd=%d\n",
                   name, mode, fd);
      set_int_var (varname, fd);
#endif
    }
  else
    {
      log_error ("can't put fd %d into table\n", fd);
      close (fd);
    }
}


static void
do_close (char *line)
{
  int fd = atoi (line);

#ifdef HAVE_W32_SYSTEM
  int i;

  for (i=0; i < DIM (open_fd_table); i++)
    if ( open_fd_table[i].inuse && open_fd_table[i].handle == (void*)fd)
      break;
  if (i < DIM (open_fd_table))
    fd = i;
  else
    {
      log_error ("given fd (system handle) has not been opened\n");
      return;
    }
#endif

  if (fd < 0 || fd >= DIM (open_fd_table))
    {
      log_error ("invalid fd\n");
      return;
    }

  if (!open_fd_table[fd].inuse)
    {
      log_error ("given fd has not been opened\n");
      return;
    }
#ifdef HAVE_W32_SYSTEM
  CloseHandle (open_fd_table[fd].handle); /* Close duped handle.  */
#endif
  close (fd);
  open_fd_table[fd].inuse = 0;
}


static void
do_showopen (void)
{
  int i;

  for (i=0; i < DIM (open_fd_table); i++)
    if (open_fd_table[i].inuse)
      {
#ifdef HAVE_W32_SYSTEM
        printf ("%-15d (libc=%d)\n", (int)open_fd_table[i].handle, i);
#else
        printf ("%-15d\n", i);
#endif
      }
}



static int
getinfo_pid_cb (void *opaque, const void *buffer, size_t length)
{
  membuf_t *mb = opaque;
  put_membuf (mb, buffer, length);
  return 0;
}

/* Get the pid of the server and store it locally.  */
static void
do_serverpid (assuan_context_t ctx)
{
  int rc;
  membuf_t mb;
  char *buffer;
  
  init_membuf (&mb, 100);
  rc = assuan_transact (ctx, "GETINFO pid", getinfo_pid_cb, &mb,
                        NULL, NULL, NULL, NULL);
  put_membuf (&mb, "", 1);
  buffer = get_membuf (&mb, NULL);
  if (rc || !buffer)
    log_error ("command \"%s\" failed: %s\n", 
               "GETINFO pid", gpg_strerror (rc));
  else
    {
      server_pid = (pid_t)strtoul (buffer, NULL, 10);
      if (opt.verbose)
        log_info ("server's PID is %lu\n", (unsigned long)server_pid);
    }
  xfree (buffer);
}


/* gpg-connect-agent's entry point. */
int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  int no_more_options = 0;
  assuan_context_t ctx;
  char *line, *p;
  char *tmpline;
  size_t linesize;
  int rc;
  int cmderr;
  const char *opt_run = NULL;
  FILE *script_fp = NULL;

  set_strusage (my_strusage);
  log_set_prefix ("gpg-connect-agent", 1);

  /* Make sure that our subsystems are ready.  */
  init_common_subsystems ();

  assuan_set_assuan_err_source (0);

  i18n_init();

  opt.homedir = default_homedir ();
  opt.connect_flags = 1; /* Use extended connect mode.  */

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
        case oHex:       opt.hex = 1; break;
        case oDecode:    opt.decode = 1; break;
        case oRawSocket: opt.raw_socket = pargs.r.ret_str; break;
        case oExec:      opt.exec = 1; break;
        case oNoExtConnect: opt.connect_flags &= ~(1); break;
        case oRun:       opt_run = pargs.r.ret_str; break;

        default: pargs.err = 2; break;
	}
    }

  if (log_get_errorcount (0))
    exit (2);

  if (opt.exec)
    {
      if (!argc)
        {
          log_error (_("option \"%s\" requires a program "
                       "and optional arguments\n"), "--exec" );
          exit (1);
        }
    }
  else if (argc)
    usage (1);

  if (opt.exec && opt.raw_socket)
    log_info (_("option \"%s\" ignored due to \"%s\"\n"),
              "--raw-socket", "--exec");

  if (opt_run && !(script_fp = fopen (opt_run, "r")))
    {
      log_error ("cannot open run file `%s': %s\n",
                 opt_run, strerror (errno));
      exit (1);
    }


  if (opt.exec)
    {
      int no_close[3];

      no_close[0] = fileno (stderr);
      no_close[1] = log_get_fd ();
      no_close[2] = -1;
      rc = assuan_pipe_connect_ext (&ctx, *argv, (const char **)argv,
                                    no_close, NULL, NULL,
                                    opt.connect_flags);
      if (rc)
        {
          log_error ("assuan_pipe_connect_ext failed: %s\n",
                     gpg_strerror (rc));
          exit (1);
        }

      if (opt.verbose)
        log_info ("server `%s' started\n", *argv);

    }
  else if (opt.raw_socket)
    {
      rc = assuan_socket_connect_ext (&ctx, opt.raw_socket, 0,
                                      opt.connect_flags);
      if (rc)
        {
          log_error ("can't connect to socket `%s': %s\n",
                     opt.raw_socket, gpg_strerror (rc));
          exit (1);
        }

      if (opt.verbose)
        log_info ("connection to socket `%s' established\n", opt.raw_socket);
    }
  else
    ctx = start_agent ();

  /* See whether there is a line pending from the server (in case
     assuan did not run the initial handshaking).  */
  if (assuan_pending_line (ctx))
    {
      rc = read_and_print_response (ctx, &cmderr);
      if (rc)
        log_info (_("receiving line failed: %s\n"), gpg_strerror (rc) );
    }

 
  line = NULL;
  linesize = 0;
  for (;;)
    {
      int n;
      size_t maxlength;

      maxlength = 2048;
      n = read_line (script_fp? script_fp:stdin, &line, &linesize, &maxlength);
      if (n < 0)
        {
          log_error (_("error reading input: %s\n"), strerror (errno));
          if (script_fp)
            {
              fclose (script_fp);
              script_fp = NULL;
              log_error ("stopping script execution\n");
              continue;
            }
          exit (1);
        }
      if (!n)
        {
          /* EOF */
          if (script_fp)
            {
              fclose (script_fp);
              script_fp = NULL;
              if (opt.verbose)
                log_info ("end of script\n");
              continue;
            }
          break; 
        }
      if (!maxlength)
        {
          log_error (_("line too long - skipped\n"));
          continue;
        }
      if (memchr (line, 0, n))
        log_info (_("line shortened due to embedded Nul character\n"));
      if (line[n-1] == '\n')
        line[n-1] = 0;
      if (*line == '/')
        {
          /* Handle control commands. */
          char *cmd = line+1;

          for (p=cmd; *p && !spacep (p); p++)
            ;
          if (*p)
            *p++ = 0;
          while (spacep (p))
            p++;
          if (!strcmp (cmd, "let"))
            {
              assign_variable (p, 0);
            }
          else if (!strcmp (cmd, "slet"))
            {
              assign_variable (p, 1);
            }
          else if (!strcmp (cmd, "showvar"))
            {
              show_variables ();
            }
          else if (!strcmp (cmd, "definqfile"))
            {
              add_definq (p, 0);
            }
          else if (!strcmp (cmd, "definqprog"))
            {
              add_definq (p, 1);
            }
          else if (!strcmp (cmd, "showdef"))
            {
              show_definq ();
            }
          else if (!strcmp (cmd, "cleardef"))
            {
              clear_definq ();
            }
          else if (!strcmp (cmd, "echo"))
            {
              tmpline = opt.enable_varsubst? substitute_line (p) : NULL;
              if (tmpline)
                {
                  puts (tmpline);
                  xfree (tmpline);
                }
              else
                puts (p);
            }
          else if (!strcmp (cmd, "sendfd"))
            {
              do_sendfd (ctx, p);
              continue;
            }
          else if (!strcmp (cmd, "recvfd"))
            {
              do_recvfd (ctx, p);
              continue;
            }
          else if (!strcmp (cmd, "open"))
            {
              do_open (p);
            }
          else if (!strcmp (cmd, "close"))
            {
              do_close (p);
            }
          else if (!strcmp (cmd, "showopen"))
            {
              do_showopen ();
            }
          else if (!strcmp (cmd, "serverpid"))
            {
              do_serverpid (ctx);
            }
          else if (!strcmp (cmd, "hex"))
            opt.hex = 1;
          else if (!strcmp (cmd, "nohex"))
            opt.hex = 0;
          else if (!strcmp (cmd, "decode"))
            opt.decode = 1;
          else if (!strcmp (cmd, "nodecode"))
            opt.decode = 0;
          else if (!strcmp (cmd, "subst"))
            opt.enable_varsubst = 1;
          else if (!strcmp (cmd, "nosubst"))
            opt.enable_varsubst = 0;
          else if (!strcmp (cmd, "run"))
            {
              char *p2;
              for (p2=p; *p2 && !spacep (p2); p2++)
                ;
              if (*p2)
                *p2++ = 0;
              while (spacep (p2))
                p++;
              if (*p2)
                {
                  log_error ("syntax error in run command\n");
                  if (script_fp)
                    {
                      fclose (script_fp);
                      script_fp = NULL;
                    }
                }
              else if (script_fp)
                {
                  log_error ("cannot nest run commands - stop\n");
                  fclose (script_fp);
                  script_fp = NULL;
                }
              else if (!(script_fp = fopen (p, "r")))
                {
                  log_error ("cannot open run file `%s': %s\n",
                             p, strerror (errno));
                }
              else if (opt.verbose)
                log_info ("running commands from `%s'\n", p);
            }
          else if (!strcmp (cmd, "bye"))
            {
              break;
            }
          else if (!strcmp (cmd, "help"))
            {
              puts (
"Available commands:\n"
"/echo ARGS             Echo ARGS.\n"
"/let  NAME VALUE       Set variable NAME to VALUE.\n"
"/slet NAME TAG         Set variable NAME to the value described by TAG.\n" 
"/showvar               Show all variables.\n"
"/definqfile NAME FILE\n"
"    Use content of FILE for inquiries with NAME.\n"
"    NAME may be \"*\" to match any inquiry.\n"
"/definqprog NAME PGM\n"
"    Run PGM for inquiries matching NAME and pass the\n"
"    entire line to it as arguments.\n"
"/showdef               Print all definitions.\n"
"/cleardef              Delete all definitions.\n"
"/sendfd FILE MODE      Open FILE and pass descriptor to server.\n"
"/recvfd                Receive FD from server and print.\n"
"/open VAR FILE MODE    Open FILE and assign the descrptor to VAR.\n" 
"/close FD              Close file with descriptor FD.\n"
"/showopen              Show descriptors of all open files.\n"
"/serverpid             Retrieve the pid of the server.\n"
"/[no]hex               Enable hex dumping of received data lines.\n"
"/[no]decode            Enable decoding of received data lines.\n"
"/[no]subst             Enable varibale substitution.\n"
"/run FILE              Run commands from FILE.\n"
"/bye                   Terminate gpg-connect-agent.\n"
"/help                  Print this help.");
            }
          else
            log_error (_("unknown command `%s'\n"), cmd );
      
          continue;
        }

      if (opt.verbose && script_fp)
        puts (line);

      tmpline = opt.enable_varsubst? substitute_line (line) : NULL;
      if (tmpline)
        {
          rc = assuan_write_line (ctx, tmpline);
          xfree (tmpline);
        }
      else
        rc = assuan_write_line (ctx, line);
      if (rc)
        {
          log_info (_("sending line failed: %s\n"), gpg_strerror (rc) );
	  break;
        }
      if (*line == '#' || !*line)
        continue; /* Don't expect a response for a comment line. */

      rc = read_and_print_response (ctx, &cmderr);
      if (rc)
        log_info (_("receiving line failed: %s\n"), gpg_strerror (rc) );
      if ((rc || cmderr) && script_fp)
        {
          log_error ("stopping script execution\n");
          fclose (script_fp);
          script_fp = NULL;
        }
          

      /* FIXME: If the last command was BYE or the server died for
	 some other reason, we won't notice until we get the next
	 input command.  Probing the connection with a non-blocking
	 read could help to notice termination or other problems
	 early.  */
    }

  if (opt.verbose)
    log_info ("closing connection to agent\n");
  
  return 0; 
}


/* Handle an Inquire from the server.  Return False if it could not be
   handled; in this case the caller shll complete the operation.  LINE
   is the complete line as received from the server.  This function
   may change the content of LINE. */
static int
handle_inquire (assuan_context_t ctx, char *line)
{
  const char *name;
  definq_t d;
  FILE *fp;
  char buffer[1024];
  int rc, n;

  /* Skip the command and trailing spaces. */
  for (; *line && !spacep (line); line++)
    ;
  while (spacep (line))
    line++;
  /* Get the name. */
  name = line;
  for (; *line && !spacep (line); line++)
    ;
  if (*line)
    *line++ = 0;

  /* Now match it against our list. he second loop is todetect the
     match all entry. **/
  for (d=definq_list; d; d = d->next)
    if (d->name && !strcmp (d->name, name))
        break;
  if (!d)
    for (d=definq_list; d; d = d->next)
      if (!d->name)
        break;
  if (!d)
    {
      if (opt.verbose)
        log_info ("no handler for inquiry `%s' found\n", name);
      return 0;
    }

  if (d->is_prog)
    {
      fp = popen (d->file, "r");
      if (!fp)
        log_error ("error executing `%s': %s\n", d->file, strerror (errno));
      else if (opt.verbose)
        log_error ("handling inquiry `%s' by running `%s'\n", name, d->file);
    }
  else
    {
      fp = fopen (d->file, "rb");
      if (!fp)
        log_error ("error opening `%s': %s\n", d->file, strerror (errno));
      else if (opt.verbose)
        log_error ("handling inquiry `%s' by returning content of `%s'\n",
                   name, d->file);
    }
  if (!fp)
    return 0;

  while ( (n = fread (buffer, 1, sizeof buffer, fp)) )
    {
      rc = assuan_send_data (ctx, buffer, n);
      if (rc)
        {
          log_error ("sending data back failed: %s\n", gpg_strerror (rc) );
          break;
        }
    }
  if (ferror (fp))
    log_error ("error reading from `%s': %s\n", d->file, strerror (errno));

  rc = assuan_send_data (ctx, NULL, 0);
  if (rc)
    log_error ("sending data back failed: %s\n", gpg_strerror (rc) );

  if (d->is_prog)
    {
      if (pclose (fp))
        log_error ("error running `%s': %s\n", d->file, strerror (errno));
    }
  else
    fclose (fp);
  return 1;
}


/* Read all response lines from server and print them.  Returns 0 on
   success or an assuan error code.  Set R_GOTERR to true if the
   command did not returned OK.  */
static int
read_and_print_response (assuan_context_t ctx, int *r_goterr)
{
  char *line;
  size_t linelen;
  assuan_error_t rc;
  int i, j;
  int need_lf = 0;

  *r_goterr = 0;
  for (;;)
    {
      do 
        {
          rc = assuan_read_line (ctx, &line, &linelen);
          if (rc)
            return rc;

          if (opt.verbose > 1 && *line == '#')
            {
              fwrite (line, linelen, 1, stdout);
              putchar ('\n');
            }
        }    
      while (*line == '#' || !linelen);

      if (linelen >= 1
          && line[0] == 'D' && line[1] == ' ')
        {
          if (opt.hex)
            {
              for (i=2; i < linelen; )
                {
                  int save_i = i;

                  printf ("D[%04X] ", i-2);
                  for (j=0; j < 16 ; j++, i++)
                    {
                      if (j == 8)
                        putchar (' ');
                      if (i < linelen)
                        printf (" %02X", ((unsigned char*)line)[i]);
                      else
                        fputs ("   ", stdout);
                    }
                  fputs ("   ", stdout);
                  i= save_i;
                  for (j=0; j < 16; j++, i++)
                    {
                      unsigned int c = ((unsigned char*)line)[i];
                      if ( i >= linelen )
                        putchar (' ');
                      else if (isascii (c) && isprint (c) && !iscntrl (c))
                        putchar (c);
                      else
                        putchar ('.');
                    }
                  putchar ('\n');
                }
            }
          else if (opt.decode)
            {
              const unsigned char *s;
              int need_d = 1;
              int c = 0;

              for (j=2, s=(unsigned char*)line+2; j < linelen; j++, s++ )
                {
                  if (need_d)
                    {
                      fputs ("D ", stdout);
                      need_d = 0;
                    }
                  if (*s == '%' && j+2 < linelen)
                    { 
                      s++; j++;
                      c = xtoi_2 ( s );
                      s++; j++;
                    }
                  else
                    c = *s;
                  if (c == '\n')
                    need_d = 1;
                  putchar (c);
                }
              need_lf = (c != '\n');
            }
          else
            {
              fwrite (line, linelen, 1, stdout);
              putchar ('\n');
            }
        }
      else 
        {
          if (need_lf)
            {
              putchar ('\n');
              need_lf = 0;
            }

          if (linelen >= 1
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
              *r_goterr = 1;
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
              if (!handle_inquire (ctx, line))
                assuan_write_line (ctx, "CANCEL");
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
            return gpg_error (GPG_ERR_ASS_INV_RESPONSE);
        }
    }
}




/* Connect to the agent and send the standard options.  */
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
      while (*p && *p != PATHSEP_C)
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
      log_error ("can't connect to the agent: %s\n", gpg_strerror (rc));
      exit (1);
    }

  if (opt.verbose)
    log_info ("connection to agent established\n");

  rc = assuan_transact (ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    {
      log_error (_("error sending %s command: %s\n"), "RESET", 
                 gpg_strerror (rc));
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
