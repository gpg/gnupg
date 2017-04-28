/* gpg-connect-agent.c - Tool to connect to the agent.
 * Copyright (C) 2005, 2007, 2008, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <assuan.h>
#include <unistd.h>
#include <assert.h>

#include "../common/i18n.h"
#include "../common/util.h"
#include "../common/asshelp.h"
#include "../common/sysutils.h"
#include "../common/membuf.h"
#include "../common/ttyio.h"
#ifdef HAVE_W32_SYSTEM
#  include "../common/exechelp.h"
#endif
#include "../common/init.h"


#define CONTROL_D ('D' - 'A' + 1)
#define octdigitp(p) (*(p) >= '0' && *(p) <= '7')

/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,
    oQuiet      = 'q',
    oVerbose	= 'v',
    oRawSocket  = 'S',
    oTcpSocket  = 'T',
    oExec       = 'E',
    oRun        = 'r',
    oSubst      = 's',

    oNoVerbose	= 500,
    oHomedir,
    oAgentProgram,
    oDirmngrProgram,
    oHex,
    oDecode,
    oNoExtConnect,
    oDirmngr,
    oUIServer,
    oNoAutostart,

  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet, "quiet",     N_("quiet")),
  ARGPARSE_s_n (oHex,   "hex",       N_("print data out hex encoded")),
  ARGPARSE_s_n (oDecode,"decode",    N_("decode received data lines")),
  ARGPARSE_s_n (oDirmngr,"dirmngr",  N_("connect to the dirmngr")),
  ARGPARSE_s_n (oUIServer, "uiserver", "@"),
  ARGPARSE_s_s (oRawSocket, "raw-socket",
                N_("|NAME|connect to Assuan socket NAME")),
  ARGPARSE_s_s (oTcpSocket, "tcp-socket",
                N_("|ADDR|connect to Assuan server at ADDR")),
  ARGPARSE_s_n (oExec, "exec",
                N_("run the Assuan server given on the command line")),
  ARGPARSE_s_n (oNoExtConnect, "no-ext-connect",
                N_("do not use extended connect mode")),
  ARGPARSE_s_s (oRun,  "run",
                N_("|FILE|run commands from FILE on startup")),
  ARGPARSE_s_n (oSubst, "subst",     N_("run /subst on startup")),

  ARGPARSE_s_n (oNoAutostart, "no-autostart", "@"),
  ARGPARSE_s_n (oNoVerbose, "no-verbose", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@" ),
  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oDirmngrProgram, "dirmngr-program", "@"),

  ARGPARSE_end ()
};


/* We keep all global options in the structure OPT.  */
struct
{
  int verbose;		/* Verbosity level.  */
  int quiet;		/* Be extra quiet.  */
  int autostart;        /* Start the server if not running.  */
  const char *homedir;  /* Configuration directory name */
  const char *agent_program;  /* Value of --agent-program.  */
  const char *dirmngr_program;  /* Value of --dirmngr-program.  */
  int hex;              /* Print data lines in hex format. */
  int decode;           /* Decode received data lines.  */
  int use_dirmngr;      /* Use the dirmngr and not gpg-agent.  */
  int use_uiserver;     /* Use the standard UI server.  */
  const char *raw_socket; /* Name of socket to connect in raw mode. */
  const char *tcp_socket; /* Name of server to connect in tcp mode. */
  int exec;             /* Run the pgm given on the command line. */
  unsigned int connect_flags;    /* Flags used for connecting. */
  int enable_varsubst;  /* Set if variable substitution is enabled.  */
  int trim_leading_spaces;
} opt;



/* Definitions for /definq commands and a global linked list with all
   the definitions. */
struct definq_s
{
  struct definq_s *next;
  char *name;     /* Name of inquiry or NULL for any name. */
  int is_var;     /* True if FILE is a variable name. */
  int is_prog;    /* True if FILE is a program to run. */
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


/* To implement loops we store entire lines in a linked list.  */
struct loopline_s
{
  struct loopline_s *next;
  char line[1];
};
typedef struct loopline_s *loopline_t;


/* This is used to store the pid of the server.  */
static pid_t server_pid = (pid_t)(-1);

/* The current datasink file or NULL.  */
static FILE *current_datasink;

/* A list of open file descriptors. */
static struct
{
  int inuse;
#ifdef HAVE_W32_SYSTEM
  HANDLE handle;
#endif
} open_fd_table[256];


/*-- local prototypes --*/
static char *substitute_line_copy (const char *buffer);
static int read_and_print_response (assuan_context_t ctx, int withhash,
                                    int *r_goterr);
static assuan_context_t start_agent (void);




/* Print usage information and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "@GPG@-connect-agent (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p = _("Usage: @GPG@-connect-agent [options] (-h for help)");
      break;
    case 41:
      p = _("Syntax: @GPG@-connect-agent [options]\n"
            "Connect to a running agent and send commands\n");
      break;
    case 31: p = "\nHome: "; break;
    case 32: p = gnupg_homedir (); break;
    case 33: p = "\n"; break;

    default: p = NULL; break;
    }
  return p;
}


/* Unescape STRING and returned the malloced result.  The surrounding
   quotes must already be removed from STRING.  */
static char *
unescape_string (const char *string)
{
  const unsigned char *s;
  int esc;
  size_t n;
  char *buffer;
  unsigned char *d;

  n = 0;
  for (s = (const unsigned char*)string, esc=0; *s; s++)
    {
      if (esc)
        {
          switch (*s)
            {
            case 'b':
            case 't':
            case 'v':
            case 'n':
            case 'f':
            case 'r':
            case '"':
            case '\'':
            case '\\': n++; break;
            case 'x':
              if (s[1] && s[2] && hexdigitp (s+1) && hexdigitp (s+2))
                n++;
              break;

            default:
              if (s[1] && s[2]
                  && octdigitp (s) && octdigitp (s+1) && octdigitp (s+2))
                n++;
              break;
	    }
          esc = 0;
        }
      else if (*s == '\\')
        esc = 1;
      else
        n++;
    }

  buffer = xmalloc (n+1);
  d = (unsigned char*)buffer;
  for (s = (const unsigned char*)string, esc=0; *s; s++)
    {
      if (esc)
        {
          switch (*s)
            {
            case 'b':  *d++ = '\b'; break;
            case 't':  *d++ = '\t'; break;
            case 'v':  *d++ = '\v'; break;
            case 'n':  *d++ = '\n'; break;
            case 'f':  *d++ = '\f'; break;
            case 'r':  *d++ = '\r'; break;
            case '"':  *d++ = '\"'; break;
            case '\'': *d++ = '\''; break;
            case '\\': *d++ = '\\'; break;
            case 'x':
              if (s[1] && s[2] && hexdigitp (s+1) && hexdigitp (s+2))
                {
                  s++;
                  *d++ = xtoi_2 (s);
                  s++;
                }
              break;

            default:
              if (s[1] && s[2]
                  && octdigitp (s) && octdigitp (s+1) && octdigitp (s+2))
                {
                  *d++ = (atoi_1 (s)*64) + (atoi_1 (s+1)*8) + atoi_1 (s+2);
                  s += 2;
                }
              break;
	    }
          esc = 0;
        }
      else if (*s == '\\')
        esc = 1;
      else
        *d++ = *s;
    }
  *d = 0;
  return buffer;
}


/* Do the percent unescaping and return a newly malloced string.
   If WITH_PLUS is set '+' characters will be changed to space. */
static char *
unpercent_string (const char *string, int with_plus)
{
  const unsigned char *s;
  unsigned char *buffer, *p;
  size_t n;

  n = 0;
  for (s=(const unsigned char *)string; *s; s++)
    {
      if (*s == '%' && s[1] && s[2])
        {
          s++;
          n++;
          s++;
        }
      else if (with_plus && *s == '+')
        n++;
      else
        n++;
    }

  buffer = xmalloc (n+1);
  p = buffer;
  for (s=(const unsigned char *)string; *s; s++)
    {
      if (*s == '%' && s[1] && s[2])
        {
          s++;
          *p++ = xtoi_2 (s);
          s++;
        }
      else if (with_plus && *s == '+')
        *p++ = ' ';
      else
        *p++ = *s;
    }
  *p = 0;
  return (char*)buffer;
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


/* Perform some simple arithmetic operations.  Caller must release
   the return value.  On error the return value is NULL.  */
static char *
arithmetic_op (int operator, const char *operands)
{
  long result, value;
  char numbuf[35];

  while ( spacep (operands) )
    operands++;
  if (!*operands)
    return NULL;
  result = strtol (operands, NULL, 0);
  while (*operands && !spacep (operands) )
    operands++;
  if (operator == '!')
    result = !result;

  while (*operands)
    {
      while ( spacep (operands) )
        operands++;
      if (!*operands)
        break;
      value = strtol (operands, NULL, 0);
      while (*operands && !spacep (operands) )
        operands++;
      switch (operator)
        {
        case '+': result += value; break;
        case '-': result -= value; break;
        case '*': result *= value; break;
        case '/':
          if (!value)
            return NULL;
          result /= value;
          break;
        case '%':
          if (!value)
            return NULL;
          result %= value;
          break;
        case '!': result = !value; break;
        case '|': result = result || value; break;
        case '&': result = result && value; break;
        default:
          log_error ("unknown arithmetic operator '%c'\n", operator);
          return NULL;
        }
    }
  snprintf (numbuf, sizeof numbuf, "%ld", result);
  return xstrdup (numbuf);
}



/* Extended version of get_var.  This returns a malloced string and
   understand the function syntax: "func args".

   Defined functions are

     get - Return a value described by the next argument:
           cwd        - The current working directory.
           homedir    - The gnupg homedir.
           sysconfdir - GnuPG's system configuration directory.
           bindir     - GnuPG's binary directory.
           libdir     - GnuPG's library directory.
           libexecdir - GnuPG's library directory for executable files.
           datadir    - GnuPG's data directory.
           serverpid  - The PID of the current server.

     unescape ARGS
           Remove C-style escapes from string.  Note that "\0" and
           "\x00" terminate the string implictly.  Use "\x7d" to
           represent the closing brace.  The args start right after
           the first space after the function name.

     unpercent ARGS
     unpercent+ ARGS
           Remove percent style ecaping from string.  Note that "%00
           terminates the string implicitly.  Use "%7d" to represetn
           the closing brace.  The args start right after the first
           space after the function name.  "unpercent+" also maps '+'
           to space.

     percent ARGS
     percent+ ARGS
           Escape the args using the percent style.  Tabs, formfeeds,
           linefeeds, carriage return, and the plus sign are also
           escaped.  "percent+" also maps spaces to plus characters.

     errcode ARG
           Assuming ARG is an integer, return the gpg-error code.

     errsource ARG
           Assuming ARG is an integer, return the gpg-error source.

     errstring ARG
           Assuming ARG is an integer return a formatted fpf error string.


   Example: get_var_ext ("get sysconfdir") -> "/etc/gnupg"

  */
static char *
get_var_ext (const char *name)
{
  static int recursion_count;
  const char *s;
  char *result;
  char *p;
  char *free_me = NULL;
  int intvalue;

  if (recursion_count > 50)
    {
      log_error ("variables nested too deeply\n");
      return NULL;
    }

  recursion_count++;
  free_me = opt.enable_varsubst? substitute_line_copy (name) : NULL;
  if (free_me)
    name = free_me;
  for (s=name; *s && !spacep (s); s++)
    ;
  if (!*s)
    {
      s = get_var (name);
      result = s? xstrdup (s): NULL;
    }
  else if ( (s - name) == 3 && !strncmp (name, "get", 3))
    {
      while ( spacep (s) )
        s++;
      if (!strcmp (s, "cwd"))
        {
          result = gnupg_getcwd ();
          if (!result)
            log_error ("getcwd failed: %s\n", strerror (errno));
        }
      else if (!strcmp (s, "homedir"))
        result = xstrdup (gnupg_homedir ());
      else if (!strcmp (s, "sysconfdir"))
        result = xstrdup (gnupg_sysconfdir ());
      else if (!strcmp (s, "bindir"))
        result = xstrdup (gnupg_bindir ());
      else if (!strcmp (s, "libdir"))
        result = xstrdup (gnupg_libdir ());
      else if (!strcmp (s, "libexecdir"))
        result = xstrdup (gnupg_libexecdir ());
      else if (!strcmp (s, "datadir"))
        result = xstrdup (gnupg_datadir ());
      else if (!strcmp (s, "serverpid"))
        result = xasprintf ("%d", (int)server_pid);
      else
        {
          log_error ("invalid argument '%s' for variable function 'get'\n", s);
          log_info  ("valid are: cwd, "
                     "{home,bin,lib,libexec,data}dir, serverpid\n");
          result = NULL;
        }
    }
  else if ( (s - name) == 8 && !strncmp (name, "unescape", 8))
    {
      s++;
      result = unescape_string (s);
    }
  else if ( (s - name) == 9 && !strncmp (name, "unpercent", 9))
    {
      s++;
      result = unpercent_string (s, 0);
    }
  else if ( (s - name) == 10 && !strncmp (name, "unpercent+", 10))
    {
      s++;
      result = unpercent_string (s, 1);
    }
  else if ( (s - name) == 7 && !strncmp (name, "percent", 7))
    {
      s++;
      result = percent_escape (s, "+\t\r\n\f\v");
    }
  else if ( (s - name) == 8 && !strncmp (name, "percent+", 8))
    {
      s++;
      result = percent_escape (s, "+\t\r\n\f\v");
      for (p=result; *p; p++)
        if (*p == ' ')
          *p = '+';
    }
  else if ( (s - name) == 7 && !strncmp (name, "errcode", 7))
    {
      s++;
      intvalue = (int)strtol (s, NULL, 0);
      result = xasprintf ("%d", gpg_err_code (intvalue));
    }
  else if ( (s - name) == 9 && !strncmp (name, "errsource", 9))
    {
      s++;
      intvalue = (int)strtol (s, NULL, 0);
      result = xasprintf ("%d", gpg_err_source (intvalue));
    }
  else if ( (s - name) == 9 && !strncmp (name, "errstring", 9))
    {
      s++;
      intvalue = (int)strtol (s, NULL, 0);
      result = xasprintf ("%s <%s>",
                          gpg_strerror (intvalue), gpg_strsource (intvalue));
    }
  else if ( (s - name) == 1 && strchr ("+-*/%!|&", *name))
    {
      result = arithmetic_op (*name, s+1);
    }
  else
    {
      log_error ("unknown variable function '%.*s'\n", (int)(s-name), name);
      result = NULL;
    }

  xfree (free_me);
  recursion_count--;
  return result;
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
  char *freeme = NULL;

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
          int count = 0;

          for (pend=p+2; *pend; pend++)
            {
              if (*pend == '{')
                count++;
              else if (*pend == '}')
                {
                  if (--count < 0)
                    break;
                }
            }
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
          int save = *pend;
          *pend = 0;
          freeme = get_var_ext (p+2);
          value = freeme;
          *pend++ = save;
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
          xfree (result);
          result = dst;
        }
      xfree (freeme);
      freeme = NULL;
    }
  return result;
}

/* Same as substitute_line but do not modify BUFFER.  */
static char *
substitute_line_copy (const char *buffer)
{
  char *result, *p;

  p = xstrdup (buffer?buffer:"");
  result = substitute_line (p);
  if (!result)
    result = p;
  else
    xfree (p);
  return result;
}


static void
assign_variable (char *line, int syslet)
{
  char *name, *p, *tmp, *free_me, *buffer;

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
      free_me = opt.enable_varsubst? substitute_line_copy (p) : NULL;
      if (free_me)
        p = free_me;
      buffer = xmalloc (4 + strlen (p) + 1);
      strcpy (stpcpy (buffer, "get "), p);
      tmp = get_var_ext (buffer);
      xfree (buffer);
      set_var (name, tmp);
      xfree (tmp);
      xfree (free_me);
    }
  else
    {
      tmp = opt.enable_varsubst? substitute_line_copy (p) : NULL;
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
add_definq (char *line, int is_var, int is_prog)
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
  d->is_var  = is_var;
  d->is_prog = is_prog;
  if ( !strcmp (name, "*"))
    d->name = NULL;
  else
    d->name = xstrdup (name);

  d->next = NULL;
  *definq_list_tail = d;
  definq_list_tail = &d->next;
}


/* Show all inquiry definitions. */
static void
show_definq (void)
{
  definq_t d;

  for (d=definq_list; d; d = d->next)
    if (d->name)
      printf ("%-20s %c %s\n",
              d->name, d->is_var? 'v' : d->is_prog? 'p':'f', d->file);
  for (d=definq_list; d; d = d->next)
    if (!d->name)
      printf ("%-20s %c %s\n", "*",
              d->is_var? 'v': d->is_prog? 'p':'f', d->file);
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
      log_error ("can't open '%s' in \"%s\" mode: %s\n",
                 name, mode, strerror (errno));
      return;
    }
  fd = fileno (fp);

  if (opt.verbose)
    log_error ("file '%s' opened in \"%s\" mode, fd=%d\n",
               name, mode, fd);

  rc = assuan_sendfd (ctx, INT2FD (fd) );
  if (rc)
    log_error ("sending descriptor %d failed: %s\n", fd, gpg_strerror (rc));
  fclose (fp);
}


static void
do_recvfd (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
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
      log_error ("can't open '%s' in \"%s\" mode: %s\n",
                 name, mode, strerror (errno));
      return;
    }
  fd = fileno (fp);
  if (fd >= 0 && fd < DIM (open_fd_table))
    {
      open_fd_table[fd].inuse = 1;
#ifdef HAVE_W32CE_SYSTEM
# warning fixme: implement our pipe emulation.
#endif
#if defined(HAVE_W32_SYSTEM) && !defined(HAVE_W32CE_SYSTEM)
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
        log_info ("file '%s' opened in \"%s\" mode, fd=%d  (libc=%d)\n",
                   name, mode, (int)open_fd_table[fd].handle, fd);
      set_int_var (varname, (int)open_fd_table[fd].handle);
#else
      if (opt.verbose)
        log_info ("file '%s' opened in \"%s\" mode, fd=%d\n",
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



static gpg_error_t
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


/* Return true if the command is either "HELP" or "SCD HELP".  */
static int
help_cmd_p (const char *line)
{
  if (!ascii_strncasecmp (line, "SCD", 3)
      && (spacep (line+3) || !line[3]))
    {
      for (line += 3; spacep (line); line++)
        ;
    }

  return (!ascii_strncasecmp (line, "HELP", 4)
          && (spacep (line+4) || !line[4]));
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
  gpgrt_stream_t script_fp = NULL;
  int use_tty, keep_line;
  struct {
    int collecting;
    loopline_t head;
    loopline_t *tail;
    loopline_t current;
    unsigned int nestlevel;
    int oneshot;
    char *condition;
  } loopstack[20];
  int        loopidx;
  char **cmdline_commands = NULL;

  early_system_init ();
  gnupg_rl_initialize ();
  set_strusage (my_strusage);
  log_set_prefix ("gpg-connect-agent", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);

  assuan_set_gpg_err_source (0);


  opt.autostart = 1;
  opt.connect_flags = 1;

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
        case oHomedir:   gnupg_set_homedir (pargs.r.ret_str); break;
        case oAgentProgram: opt.agent_program = pargs.r.ret_str;  break;
        case oDirmngrProgram: opt.dirmngr_program = pargs.r.ret_str;  break;
        case oNoAutostart:    opt.autostart = 0; break;
        case oHex:       opt.hex = 1; break;
        case oDecode:    opt.decode = 1; break;
        case oDirmngr:   opt.use_dirmngr = 1; break;
        case oUIServer:  opt.use_uiserver = 1; break;
        case oRawSocket: opt.raw_socket = pargs.r.ret_str; break;
        case oTcpSocket: opt.tcp_socket = pargs.r.ret_str; break;
        case oExec:      opt.exec = 1; break;
        case oNoExtConnect: opt.connect_flags &= ~(1); break;
        case oRun:       opt_run = pargs.r.ret_str; break;
        case oSubst:
          opt.enable_varsubst = 1;
          opt.trim_leading_spaces = 1;
          break;

        default: pargs.err = 2; break;
	}
    }

  if (log_get_errorcount (0))
    exit (2);

  /* --uiserver is a shortcut for a specific raw socket.  This comes
       in particular handy on Windows. */
  if (opt.use_uiserver)
    {
      opt.raw_socket = make_absfilename (gnupg_homedir (), "S.uiserver", NULL);
    }

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("Note: '%s' is not considered an option\n"), argv[i]);
    }


  use_tty = (gnupg_isatty (fileno (stdin)) && gnupg_isatty (fileno (stdout)));

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
    cmdline_commands = argv;

  if (opt.exec && opt.raw_socket)
    {
      opt.raw_socket = NULL;
      log_info (_("option \"%s\" ignored due to \"%s\"\n"),
                "--raw-socket", "--exec");
    }
  if (opt.exec && opt.tcp_socket)
    {
      opt.tcp_socket = NULL;
      log_info (_("option \"%s\" ignored due to \"%s\"\n"),
                "--tcp-socket", "--exec");
    }
  if (opt.tcp_socket && opt.raw_socket)
    {
      opt.tcp_socket = NULL;
      log_info (_("option \"%s\" ignored due to \"%s\"\n"),
                "--tcp-socket", "--raw-socket");
    }

  if (opt_run && !(script_fp = gpgrt_fopen (opt_run, "r")))
    {
      log_error ("cannot open run file '%s': %s\n",
                 opt_run, strerror (errno));
      exit (1);
    }


  if (opt.exec)
    {
      assuan_fd_t no_close[3];

      no_close[0] = assuan_fd_from_posix_fd (es_fileno (es_stderr));
      no_close[1] = assuan_fd_from_posix_fd (log_get_fd ());
      no_close[2] = ASSUAN_INVALID_FD;

      rc = assuan_new (&ctx);
      if (rc)
	{
          log_error ("assuan_new failed: %s\n", gpg_strerror (rc));
	  exit (1);
	}

      rc = assuan_pipe_connect
	(ctx, *argv, (const char **)argv, no_close, NULL, NULL,
	 (opt.connect_flags & 1) ? ASSUAN_PIPE_CONNECT_FDPASSING : 0);
      if (rc)
        {
          log_error ("assuan_pipe_connect_ext failed: %s\n",
                     gpg_strerror (rc));
          exit (1);
        }

      if (opt.verbose)
        log_info ("server '%s' started\n", *argv);

    }
  else if (opt.raw_socket)
    {
      rc = assuan_new (&ctx);
      if (rc)
	{
          log_error ("assuan_new failed: %s\n", gpg_strerror (rc));
	  exit (1);
	}

      rc = assuan_socket_connect
	(ctx, opt.raw_socket, 0,
	 (opt.connect_flags & 1) ? ASSUAN_SOCKET_CONNECT_FDPASSING : 0);
      if (rc)
        {
          log_error ("can't connect to socket '%s': %s\n",
                     opt.raw_socket, gpg_strerror (rc));
          exit (1);
        }

      if (opt.verbose)
        log_info ("connection to socket '%s' established\n", opt.raw_socket);
    }
  else if (opt.tcp_socket)
    {
      char *url;

      url = xstrconcat ("assuan://", opt.tcp_socket, NULL);

      rc = assuan_new (&ctx);
      if (rc)
	{
          log_error ("assuan_new failed: %s\n", gpg_strerror (rc));
	  exit (1);
	}

      rc = assuan_socket_connect (ctx, opt.tcp_socket, 0, 0);
      if (rc)
        {
          log_error ("can't connect to server '%s': %s\n",
                     opt.tcp_socket, gpg_strerror (rc));
          exit (1);
        }

      if (opt.verbose)
        log_info ("connection to socket '%s' established\n", url);

      xfree (url);
    }
  else
    ctx = start_agent ();

  /* See whether there is a line pending from the server (in case
     assuan did not run the initial handshaking).  */
  if (assuan_pending_line (ctx))
    {
      rc = read_and_print_response (ctx, 0, &cmderr);
      if (rc)
        log_info (_("receiving line failed: %s\n"), gpg_strerror (rc) );
    }


  for (loopidx=0; loopidx < DIM (loopstack); loopidx++)
    loopstack[loopidx].collecting = 0;
  loopidx = -1;
  line = NULL;
  linesize = 0;
  keep_line = 1;
  for (;;)
    {
      int n;
      size_t maxlength = 2048;

      assert (loopidx < (int)DIM (loopstack));
      if (loopidx >= 0 && loopstack[loopidx].current)
        {
          keep_line = 0;
          xfree (line);
          line = xstrdup (loopstack[loopidx].current->line);
          n = strlen (line);
          /* Never go beyond of the final /end.  */
          if (loopstack[loopidx].current->next)
            loopstack[loopidx].current = loopstack[loopidx].current->next;
          else if (!strncmp (line, "/end", 4) && (!line[4]||spacep(line+4)))
            ;
          else
            log_fatal ("/end command vanished\n");
        }
      else if (cmdline_commands && *cmdline_commands && !script_fp)
        {
          keep_line = 0;
          xfree (line);
          line = xstrdup (*cmdline_commands);
          cmdline_commands++;
          n = strlen (line);
          if (n >= maxlength)
            maxlength = 0;
        }
      else if (use_tty && !script_fp)
        {
          keep_line = 0;
          xfree (line);
          line = tty_get ("> ");
          n = strlen (line);
          if (n==1 && *line == CONTROL_D)
            n = 0;
          if (n >= maxlength)
            maxlength = 0;
        }
      else
        {
          if (!keep_line)
            {
              xfree (line);
              line = NULL;
              linesize = 0;
              keep_line = 1;
            }
          n = gpgrt_read_line (script_fp ? script_fp : gpgrt_stdin,
                               &line, &linesize, &maxlength);
        }
      if (n < 0)
        {
          log_error (_("error reading input: %s\n"), strerror (errno));
          if (script_fp)
            {
              gpgrt_fclose (script_fp);
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
              gpgrt_fclose (script_fp);
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

      if (opt.trim_leading_spaces)
        {
          const char *s = line;

          while (spacep (s))
            s++;
          if (s != line)
            {
              for (p=line; *s;)
                *p++ = *s++;
              *p = 0;
              n = p - line;
            }
        }

      if (loopidx+1 >= 0 && loopstack[loopidx+1].collecting)
        {
          loopline_t ll;

          ll = xmalloc (sizeof *ll + strlen (line));
          ll->next = NULL;
          strcpy (ll->line, line);
          *loopstack[loopidx+1].tail = ll;
          loopstack[loopidx+1].tail = &ll->next;

          if (!strncmp (line, "/end", 4) && (!line[4]||spacep(line+4)))
            loopstack[loopidx+1].nestlevel--;
          else if (!strncmp (line, "/while", 6) && (!line[6]||spacep(line+6)))
            loopstack[loopidx+1].nestlevel++;

          if (loopstack[loopidx+1].nestlevel)
            continue;
          /* We reached the corresponding /end.  */
          loopstack[loopidx+1].collecting = 0;
          loopidx++;
        }

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
              /* Deprecated - never used in a released version.  */
              assign_variable (p, 1);
            }
          else if (!strcmp (cmd, "showvar"))
            {
              show_variables ();
            }
          else if (!strcmp (cmd, "definq"))
            {
              tmpline = opt.enable_varsubst? substitute_line (p) : NULL;
              if (tmpline)
                {
                  add_definq (tmpline, 1, 0);
                  xfree (tmpline);
                }
              else
                add_definq (p, 1, 0);
            }
          else if (!strcmp (cmd, "definqfile"))
            {
              tmpline = opt.enable_varsubst? substitute_line (p) : NULL;
              if (tmpline)
                {
                  add_definq (tmpline, 0, 0);
                  xfree (tmpline);
                }
              else
                add_definq (p, 0, 0);
            }
          else if (!strcmp (cmd, "definqprog"))
            {
              tmpline = opt.enable_varsubst? substitute_line (p) : NULL;
              if (tmpline)
                {
                  add_definq (tmpline, 0, 1);
                  xfree (tmpline);
                }
              else
                add_definq (p, 0, 1);
            }
          else if (!strcmp (cmd, "datafile"))
            {
              const char *fname;

              if (current_datasink)
                {
                  if (current_datasink != stdout)
                    fclose (current_datasink);
                  current_datasink = NULL;
                }
              tmpline = opt.enable_varsubst? substitute_line (p) : NULL;
              fname = tmpline? tmpline : p;
              if (fname && !strcmp (fname, "-"))
                current_datasink = stdout;
              else if (fname && *fname)
                {
                  current_datasink = fopen (fname, "wb");
                  if (!current_datasink)
                    log_error ("can't open '%s': %s\n",
                               fname, strerror (errno));
                }
              xfree (tmpline);
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
              tmpline = opt.enable_varsubst? substitute_line (p) : NULL;
              if (tmpline)
                {
                  do_sendfd (ctx, tmpline);
                  xfree (tmpline);
                }
              else
                do_sendfd (ctx, p);
              continue;
            }
          else if (!strcmp (cmd, "recvfd"))
            {
              tmpline = opt.enable_varsubst? substitute_line (p) : NULL;
              if (tmpline)
                {
                  do_recvfd (ctx, tmpline);
                  xfree (tmpline);
                }
              else
                do_recvfd (ctx, p);
              continue;
            }
          else if (!strcmp (cmd, "open"))
            {
              tmpline = opt.enable_varsubst? substitute_line (p) : NULL;
              if (tmpline)
                {
                  do_open (tmpline);
                  xfree (tmpline);
                }
              else
                do_open (p);
            }
          else if (!strcmp (cmd, "close"))
            {
              tmpline = opt.enable_varsubst? substitute_line (p) : NULL;
              if (tmpline)
                {
                  do_close (tmpline);
                  xfree (tmpline);
                }
              else
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
            {
              opt.enable_varsubst = 1;
              opt.trim_leading_spaces = 1;
            }
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
                      gpgrt_fclose (script_fp);
                      script_fp = NULL;
                    }
                }
              else if (script_fp)
                {
                  log_error ("cannot nest run commands - stop\n");
                  gpgrt_fclose (script_fp);
                  script_fp = NULL;
                }
              else if (!(script_fp = gpgrt_fopen (p, "r")))
                {
                  log_error ("cannot open run file '%s': %s\n",
                             p, strerror (errno));
                }
              else if (opt.verbose)
                log_info ("running commands from '%s'\n", p);
            }
          else if (!strcmp (cmd, "while"))
            {
              if (loopidx+2 >= (int)DIM(loopstack))
                {
                  log_error ("blocks are nested too deep\n");
                  /* We should better die or break all loop in this
                     case as recovering from this error won't be
                     easy.  */
                }
              else
                {
                  loopstack[loopidx+1].head = NULL;
                  loopstack[loopidx+1].tail = &loopstack[loopidx+1].head;
                  loopstack[loopidx+1].current = NULL;
                  loopstack[loopidx+1].nestlevel = 1;
                  loopstack[loopidx+1].oneshot = 0;
                  loopstack[loopidx+1].condition = xstrdup (p);
                  loopstack[loopidx+1].collecting = 1;
                }
            }
          else if (!strcmp (cmd, "if"))
            {
              if (loopidx+2 >= (int)DIM(loopstack))
                {
                  log_error ("blocks are nested too deep\n");
                }
              else
                {
                  /* Note that we need to evaluate the condition right
                     away and not just at the end of the block as we
                     do with a WHILE. */
                  loopstack[loopidx+1].head = NULL;
                  loopstack[loopidx+1].tail = &loopstack[loopidx+1].head;
                  loopstack[loopidx+1].current = NULL;
                  loopstack[loopidx+1].nestlevel = 1;
                  loopstack[loopidx+1].oneshot = 1;
                  loopstack[loopidx+1].condition = substitute_line_copy (p);
                  loopstack[loopidx+1].collecting = 1;
                }
            }
          else if (!strcmp (cmd, "end"))
            {
              if (loopidx < 0)
                log_error ("stray /end command encountered - ignored\n");
              else
                {
                  char *tmpcond;
                  const char *value;
                  long condition;

                  /* Evaluate the condition.  */
                  tmpcond = xstrdup (loopstack[loopidx].condition);
                  if (loopstack[loopidx].oneshot)
                    {
                      xfree (loopstack[loopidx].condition);
                      loopstack[loopidx].condition = xstrdup ("0");
                    }
                  tmpline = substitute_line (tmpcond);
                  value = tmpline? tmpline : tmpcond;
                  /* "true" or "yes" are commonly used to mean TRUE;
                     all other strings will evaluate to FALSE due to
                     the strtoul.  */
                  if (!ascii_strcasecmp (value, "true")
                      || !ascii_strcasecmp (value, "yes"))
                    condition = 1;
                  else
                    condition = strtol (value, NULL, 0);
                  xfree (tmpline);
                  xfree (tmpcond);

                  if (condition)
                    {
                      /* Run loop.  */
                      loopstack[loopidx].current = loopstack[loopidx].head;
                    }
                  else
                    {
                      /* Cleanup.  */
                      while (loopstack[loopidx].head)
                        {
                          loopline_t tmp = loopstack[loopidx].head->next;
                          xfree (loopstack[loopidx].head);
                          loopstack[loopidx].head = tmp;
                        }
                      loopstack[loopidx].tail = NULL;
                      loopstack[loopidx].current = NULL;
                      loopstack[loopidx].nestlevel = 0;
                      loopstack[loopidx].collecting = 0;
                      loopstack[loopidx].oneshot = 0;
                      xfree (loopstack[loopidx].condition);
                      loopstack[loopidx].condition = NULL;
                      loopidx--;
                    }
                }
            }
          else if (!strcmp (cmd, "bye"))
            {
              break;
            }
          else if (!strcmp (cmd, "sleep"))
            {
              gnupg_sleep (1);
            }
          else if (!strcmp (cmd, "help"))
            {
              puts (
"Available commands:\n"
"/echo ARGS             Echo ARGS.\n"
"/let  NAME VALUE       Set variable NAME to VALUE.\n"
"/showvar               Show all variables.\n"
"/definq NAME VAR       Use content of VAR for inquiries with NAME.\n"
"/definqfile NAME FILE  Use content of FILE for inquiries with NAME.\n"
"/definqprog NAME PGM   Run PGM for inquiries with NAME.\n"
"/datafile [NAME]       Write all D line content to file NAME.\n"
"/showdef               Print all definitions.\n"
"/cleardef              Delete all definitions.\n"
"/sendfd FILE MODE      Open FILE and pass descriptor to server.\n"
"/recvfd                Receive FD from server and print.\n"
"/open VAR FILE MODE    Open FILE and assign the file descriptor to VAR.\n"
"/close FD              Close file with descriptor FD.\n"
"/showopen              Show descriptors of all open files.\n"
"/serverpid             Retrieve the pid of the server.\n"
"/[no]hex               Enable hex dumping of received data lines.\n"
"/[no]decode            Enable decoding of received data lines.\n"
"/[no]subst             Enable variable substitution.\n"
"/run FILE              Run commands from FILE.\n"
"/if VAR                Begin conditional block controlled by VAR.\n"
"/while VAR             Begin loop controlled by VAR.\n"
"/end                   End loop or condition\n"
"/bye                   Terminate gpg-connect-agent.\n"
"/help                  Print this help.");
            }
          else
            log_error (_("unknown command '%s'\n"), cmd );

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

      rc = read_and_print_response (ctx, help_cmd_p (line), &cmderr);
      if (rc)
        log_info (_("receiving line failed: %s\n"), gpg_strerror (rc) );
      if ((rc || cmderr) && script_fp)
        {
          log_error ("stopping script execution\n");
          gpgrt_fclose (script_fp);
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

  /* XXX: We would like to release the context here, but libassuan
     nicely says good bye to the server, which results in a SIGPIPE if
     the server died.  Unfortunately, libassuan does not ignore
     SIGPIPE when used with UNIX sockets, hence we simply leak the
     context here.  */
  if (0)
    assuan_release (ctx);
  else
    gpgrt_annotate_leaked_object (ctx);
  xfree (line);
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
  FILE *fp = NULL;
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

  /* Now match it against our list.  The second loop is there to
     detect the match-all entry. */
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
        log_info ("no handler for inquiry '%s' found\n", name);
      return 0;
    }

  if (d->is_var)
    {
      char *tmpvalue = get_var_ext (d->file);
      if (tmpvalue)
        rc = assuan_send_data (ctx, tmpvalue, strlen (tmpvalue));
      else
        rc = assuan_send_data (ctx, "", 0);
      xfree (tmpvalue);
      if (rc)
        log_error ("sending data back failed: %s\n", gpg_strerror (rc) );
    }
  else
    {
      if (d->is_prog)
        {
#ifdef HAVE_W32CE_SYSTEM
          fp = NULL;
#else
          fp = popen (d->file, "r");
#endif
          if (!fp)
            log_error ("error executing '%s': %s\n",
                       d->file, strerror (errno));
          else if (opt.verbose)
            log_error ("handling inquiry '%s' by running '%s'\n",
                       name, d->file);
        }
      else
        {
          fp = fopen (d->file, "rb");
          if (!fp)
            log_error ("error opening '%s': %s\n", d->file, strerror (errno));
          else if (opt.verbose)
            log_error ("handling inquiry '%s' by returning content of '%s'\n",
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
        log_error ("error reading from '%s': %s\n", d->file, strerror (errno));
    }

  rc = assuan_send_data (ctx, NULL, 0);
  if (rc)
    log_error ("sending data back failed: %s\n", gpg_strerror (rc) );

  if (d->is_var)
    ;
  else if (d->is_prog)
    {
#ifndef HAVE_W32CE_SYSTEM
      if (pclose (fp))
        log_error ("error running '%s': %s\n", d->file, strerror (errno));
#endif
    }
  else
    fclose (fp);
  return 1;
}


/* Read all response lines from server and print them.  Returns 0 on
   success or an assuan error code.  If WITHHASH istrue, comment lines
   are printed.  Sets R_GOTERR to true if the command did not returned
   OK.  */
static int
read_and_print_response (assuan_context_t ctx, int withhash, int *r_goterr)
{
  char *line;
  size_t linelen;
  gpg_error_t rc;
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

          if ((withhash || opt.verbose > 1) && *line == '#')
            {
              fwrite (line, linelen, 1, stdout);
              putchar ('\n');
            }
        }
      while (*line == '#' || !linelen);

      if (linelen >= 1
          && line[0] == 'D' && line[1] == ' ')
        {
          if (current_datasink)
            {
              const unsigned char *s;
              int c = 0;

              for (j=2, s=(unsigned char*)line+2; j < linelen; j++, s++ )
                {
                  if (*s == '%' && j+2 < linelen)
                    {
                      s++; j++;
                      c = xtoi_2 ( s );
                      s++; j++;
                    }
                  else
                    c = *s;
                  putc (c, current_datasink);
                }
            }
          else if (opt.hex)
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
              if (!current_datasink || current_datasink != stdout)
                putchar ('\n');
              need_lf = 0;
            }

          if (linelen >= 1
              && line[0] == 'S'
              && (line[1] == '\0' || line[1] == ' '))
            {
              if (!current_datasink || current_datasink != stdout)
                {
                  fwrite (line, linelen, 1, stdout);
                  putchar ('\n');
                }
            }
          else if (linelen >= 2
                   && line[0] == 'O' && line[1] == 'K'
                   && (line[2] == '\0' || line[2] == ' '))
            {
              if (!current_datasink || current_datasink != stdout)
                {
                  fwrite (line, linelen, 1, stdout);
                  putchar ('\n');
                }
              set_int_var ("?", 0);
              return 0;
            }
          else if (linelen >= 3
                   && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
                   && (line[3] == '\0' || line[3] == ' '))
            {
              int errval;

              errval = strtol (line+3, NULL, 10);
              if (!errval)
                errval = -1;
              set_int_var ("?", errval);
              if (!current_datasink || current_datasink != stdout)
                {
                  fwrite (line, linelen, 1, stdout);
                  putchar ('\n');
                }
              *r_goterr = 1;
              return 0;
            }
          else if (linelen >= 7
                   && line[0] == 'I' && line[1] == 'N' && line[2] == 'Q'
                   && line[3] == 'U' && line[4] == 'I' && line[5] == 'R'
                   && line[6] == 'E'
                   && (line[7] == '\0' || line[7] == ' '))
            {
              if (!current_datasink || current_datasink != stdout)
                {
                  fwrite (line, linelen, 1, stdout);
                  putchar ('\n');
                }
              if (!handle_inquire (ctx, line))
                assuan_write_line (ctx, "CANCEL");
            }
          else if (linelen >= 3
                   && line[0] == 'E' && line[1] == 'N' && line[2] == 'D'
                   && (line[3] == '\0' || line[3] == ' '))
            {
              if (!current_datasink || current_datasink != stdout)
                {
                  fwrite (line, linelen, 1, stdout);
                  putchar ('\n');
                }
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
  gpg_error_t err;
  assuan_context_t ctx;
  session_env_t session_env;

  session_env = session_env_new ();
  if (!session_env)
    log_fatal ("error allocating session environment block: %s\n",
               strerror (errno));
  if (opt.use_dirmngr)
    err = start_new_dirmngr (&ctx,
                             GPG_ERR_SOURCE_DEFAULT,
                             opt.dirmngr_program,
                             opt.autostart,
                             !opt.quiet, 0,
                             NULL, NULL);
  else
    err = start_new_gpg_agent (&ctx,
                               GPG_ERR_SOURCE_DEFAULT,
                               opt.agent_program,
                               NULL, NULL,
                               session_env,
                               opt.autostart,
                               !opt.quiet, 0,
                               NULL, NULL);

  session_env_release (session_env);
  if (err)
    {
      if (!opt.autostart
          && (gpg_err_code (err)
              == (opt.use_dirmngr? GPG_ERR_NO_DIRMNGR : GPG_ERR_NO_AGENT)))
        {
          /* In the no-autostart case we don't make gpg-connect-agent
             fail on a missing server.  */
          log_info (opt.use_dirmngr?
                    _("no dirmngr running in this session\n"):
                    _("no gpg-agent running in this session\n"));
          exit (0);
        }
      else
        {
          log_error (_("error sending standard options: %s\n"),
                     gpg_strerror (err));
          exit (1);
        }
    }

  return ctx;
}
