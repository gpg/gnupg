/* asschk.c - Assuan Server Checker
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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

/* This is a simple stand-alone Assuan server test program.  We don't
   want to use the assuan library because we don't want to hide errors
   in that library.

   The script language is line based.  Empty lines or lines containing
   only white spaces are ignored, line with a hash sign as first non
   white space character are treated as comments.

   A simple macro mechanism is implemnted.  Macros are expanded before
   a line is processed but after comment processing.  Macros are only
   expanded once and non existing macros expand to the empty string.
   A macro is dereferenced by prefixing its name with a dollar sign;
   the end of the name is currently indicated by a white space, a
   dollar sign or a slash.  To use a dollor sign verbatim, double it.

   A macro is assigned by prefixing a statement with the macro name
   and an equal sign.  The value is assigned verbatim if it does not
   resemble a command, otherwise the return value of the command will
   get assigned.  The command "let" may be used to assign values
   unambigiously and it should be used if the value starts with a
   letter.

   Conditions are not yes implemented except for a simple evaluation
   which yields false for an empty string or the string "0".  The
   result may be negated by prefixing with a '!'.

   The general syntax of a command is:

   [<name> =] <statement> [<args>]

   If NAME is not specifed but the statement returns a value it is
   assigned to the name "?" so that it can be referenced using "$?".
   The following commands are implemented:

   let <value>
      Return VALUE.

   echo <value>
      Print VALUE.

   openfile <filename>
      Open file FILENAME for read access and return the file descriptor.

   createfile <filename>
      Create file FILENAME, open for write access and return the file
      descriptor.

   pipeserver <program>
      Connect to the Assuan server PROGRAM.

   send <line>
      Send LINE to the server.

   expect-ok
      Expect an OK response from the server.  Status and data out put
      is ignored.

   expect-err
      Expect an ERR response from the server.  Status and data out put
      is ignored.

   count-status <code>
      Initialize the assigned variable to 0 and assign it as an counter for
      status code CODE.  This command must be called with an assignment.

   quit
      Terminate the process.

   quit-if <condition>
      Terminate the process if CONDITION evaluates to true.

   fail-if <condition>
      Terminate the process with an exit code of 1 if CONDITION
      evaluates to true.

   cmpfiles <first> <second>
      Returns true when the content of the files FIRST and SECOND match.

   getenv <name>
      Return the value of the environment variable NAME.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
# define ATTR_PRINTF(f,a)  __attribute__ ((format (printf,f,a)))
#else
# define ATTR_PRINTF(f,a)
#endif

#if __STDC_VERSION__ < 199901L
# if __GNUC__ >= 2 && !defined (__func__)
#  define __func__ __FUNCTION__
# else
/* Let's try our luck here.  Some systems may provide __func__ without
   providing __STDC_VERSION__ 199901L.  */
#  if 0
#   define __func__ "<unknown>"
#  endif
# endif
#endif

#define spacep(p) (*(p) == ' ' || *(p) == '\t')

#define MAX_LINELEN 2048

typedef enum {
  LINE_OK = 0,
  LINE_ERR,
  LINE_STAT,
  LINE_DATA,
  LINE_END,
} LINETYPE;

typedef enum {
  VARTYPE_SIMPLE = 0,
  VARTYPE_FD,
  VARTYPE_COUNTER
} VARTYPE;


struct variable_s {
  struct variable_s *next;
  VARTYPE type;
  unsigned int count;
  char *value;
  char name[1];
};
typedef struct variable_s *VARIABLE;


static void die (const char *format, ...)  ATTR_PRINTF(1,2);


/* Name of this program to be printed in error messages. */
static const char *invocation_name;

/* Talk a bit about what is going on. */
static int opt_verbose;

/* Option to ignore the echo command. */
static int opt_no_echo;

/* File descriptors used to communicate with the current server. */
static int server_send_fd = -1;
static int server_recv_fd = -1;

/* The Assuan protocol limits the line length to 1024, so we can
   safely use a (larger) buffer.  The buffer is filled using the
   read_assuan(). */
static char recv_line[MAX_LINELEN];
/* Tell the status of the current line. */
static LINETYPE recv_type;

/* This is our variable storage. */
static VARIABLE variable_list;


static void
die (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", invocation_name);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  putc ('\n', stderr);

  exit (1);
}

#define die_0(format)          (die) ("%s: " format, __func__)
#define die_1(format, a)       (die) ("%s: " format, __func__, (a))
#define die_2(format, a, b)    (die) ("%s: " format, __func__, (a),(b))
#define die_3(format, a, b, c) (die) ("%s: " format, __func__, (a),(b),(c))

static void
err (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", invocation_name);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  putc ('\n', stderr);
}

static void *
xmalloc (size_t n)
{
  void *p = malloc (n);
  if (!p)
    die ("out of core");
  return p;
}

static void *
xcalloc (size_t n, size_t m)
{
  void *p = calloc (n, m);
  if (!p)
    die ("out of core");
  return p;
}

static char *
xstrdup (const char *s)
{
  char *p = xmalloc (strlen (s)+1);
  strcpy (p, s);
  return p;
}


/* Write LENGTH bytes from BUFFER to FD. */
static int
writen (int fd, const char *buffer, size_t length)
{
  while (length)
    {
      int nwritten = write (fd, buffer, length);

      if (nwritten < 0)
        {
          if (errno == EINTR)
            continue;
          return -1; /* write error */
        }
      length -= nwritten;
      buffer += nwritten;
    }
  return 0;  /* okay */
}




/* Assuan specific stuff. */

/* Read a line from FD, store it in the global recv_line, analyze the
   type and store that in recv_type.  The function terminates on a
   communication error.  Returns a pointer into the inputline to the
   first byte of the arguments.  The parsing is very strict to match
   exaclty what we want to send. */
static char *
read_assuan (int fd)
{
  /* FIXME: For general robustness, the pending stuff needs to be
     associated with FD.  */
  static char pending[MAX_LINELEN];
  static size_t pending_len;
  size_t nleft = sizeof recv_line;
  char *buf = recv_line;
  char *p;

  while (nleft > 0)
    {
      int n;

      if (pending_len)
        {
          if (pending_len >= nleft)
            die_0 ("received line too large");
          memcpy (buf, pending, pending_len);
          n = pending_len;
          pending_len = 0;
        }
      else
        {
          do
            {
              n = read (fd, buf, nleft);
            }
          while (n < 0 && errno == EINTR);
        }

      if (opt_verbose && n >= 0 )
	{
	  int i;

	  printf ("%s: read \"", __func__);
	  for (i = 0; i < n; i ++)
	    putc (buf[i], stdout);
	  printf ("\"\n");
	}

      if (n < 0)
        die_2 ("reading fd %d failed: %s", fd, strerror (errno));
      else if (!n)
        die_1 ("received incomplete line on fd %d", fd);
      p = buf;
      nleft -= n;
      buf += n;

      for (; n && *p != '\n'; n--, p++)
        ;
      if (n)
        {
          if (n>1)
            {
              n--;
              memcpy (pending, p + 1, n);
              pending_len = n;
            }
	  *p = '\0';
          break;
        }
    }
  if (!nleft)
    die_0 ("received line too large");

  p = recv_line;
  if (p[0] == 'O' && p[1] == 'K' && (p[2] == ' ' || !p[2]))
    {
      recv_type = LINE_OK;
      p += 3;
    }
  else if (p[0] == 'E' && p[1] == 'R' && p[2] == 'R'
           && (p[3] == ' ' || !p[3]))
    {
      recv_type = LINE_ERR;
      p += 4;
    }
  else if (p[0] == 'S' && (p[1] == ' ' || !p[1]))
    {
      recv_type = LINE_STAT;
      p += 2;
    }
  else if (p[0] == 'D' && p[1] == ' ')
    {
      recv_type = LINE_DATA;
      p += 2;
    }
  else if (p[0] == 'E' && p[1] == 'N' &&  p[2] == 'D' && !p[3])
    {
      recv_type = LINE_END;
      p += 3;
    }
  else
    die_1 ("invalid line type (%.5s)", p);

  return p;
}

/* Write LINE to the server using FD.  It is expected that the line
   contains the terminating linefeed as last character. */
static void
write_assuan (int fd, const char *line)
{
  char buffer[1026];
  size_t n = strlen (line);

  if (n > 1024)
    die_0 ("line too long for Assuan protocol");
  strcpy (buffer, line);
  if (!n || buffer[n-1] != '\n')
    buffer[n++] = '\n';

  if (writen (fd, buffer, n))
      die_3 ("sending line (\"%s\") to %d failed: %s", buffer, fd,
	   strerror (errno));
}


/* Start the server with path PGMNAME and connect its stdout and
   strerr to a newly created pipes; the file descriptors are then
   store in the gloabl variables SERVER_SEND_FD and
   SERVER_RECV_FD. The initial handcheck is performed.*/
static void
start_server (const char *pgmname)
{
  int rp[2];
  int wp[2];
  pid_t pid;

  if (pipe (rp) < 0)
    die_1 ("pipe creation failed: %s", strerror (errno));
  if (pipe (wp) < 0)
    die_1 ("pipe creation failed: %s", strerror (errno));

  fflush (stdout);
  fflush (stderr);
  pid = fork ();
  if (pid < 0)
    die_0 ("fork failed");

  if (!pid)
    {
      const char *arg0;

      arg0 = strrchr (pgmname, '/');
      if (arg0)
        arg0++;
      else
        arg0 = pgmname;

      if (wp[0] != STDIN_FILENO)
        {
          if (dup2 (wp[0], STDIN_FILENO) == -1)
            die_1 ("dup2 failed in child: %s", strerror (errno));
          close (wp[0]);
        }
      if (rp[1] != STDOUT_FILENO)
        {
          if (dup2 (rp[1], STDOUT_FILENO) == -1)
            die_1 ("dup2 failed in child: %s", strerror (errno));
          close (rp[1]);
        }
      if (!opt_verbose)
        {
	  int fd = open ("/dev/null", O_WRONLY);
	  if (fd == -1)
	    die_1 ("can't open '/dev/null': %s", strerror (errno));
          if (dup2 (fd, STDERR_FILENO) == -1)
            die_1 ("dup2 failed in child: %s", strerror (errno));
	  close (fd);
        }

      close (wp[1]);
      close (rp[0]);
      execl (pgmname, arg0, "--server", NULL);
      die_2 ("exec failed for '%s': %s", pgmname, strerror (errno));
    }
  close (wp[0]);
  close (rp[1]);
  server_send_fd = wp[1];
  server_recv_fd = rp[0];

  read_assuan (server_recv_fd);
  if (recv_type != LINE_OK)
    die_0 ("no greating message");
}





/* Script intepreter. */

static void
unset_var (const char *name)
{
  VARIABLE var;

  for (var=variable_list; var && strcmp (var->name, name); var = var->next)
    ;
  if (!var)
    return;
/*    fprintf (stderr, "unsetting '%s'\n", name); */

  if (var->type == VARTYPE_FD && var->value)
    {
      int fd;

      fd = atoi (var->value);
      if (fd != -1 && fd != 0 && fd != 1 && fd != 2)
          close (fd);
    }

  free (var->value);
  var->value = NULL;
  var->type = 0;
  var->count = 0;
}


static void
set_type_var (const char *name, const char *value, VARTYPE type)
{
  VARIABLE var;

  if (!name)
    name = "?";
  for (var=variable_list; var && strcmp (var->name, name); var = var->next)
    ;
  if (!var)
    {
      var = xcalloc (1, sizeof *var + strlen (name));
      strcpy (var->name, name);
      var->next = variable_list;
      variable_list = var;
    }
  else
    {
      free (var->value);
      var->value = NULL;
    }

  if (var->type == VARTYPE_FD && var->value)
    {
      int fd;

      fd = atoi (var->value);
      if (fd != -1 && fd != 0 && fd != 1 && fd != 2)
          close (fd);
    }

  var->type = type;
  var->count = 0;
  if (var->type == VARTYPE_COUNTER)
    {
      /* We need some extra sapce as scratch area for get_var. */
      var->value = xmalloc (strlen (value) + 1 + 20);
      strcpy (var->value, value);
    }
  else
    var->value = xstrdup (value);
}

static void
set_var (const char *name, const char *value)
{
  set_type_var (name, value, 0);
}


static const char *
get_var (const char *name)
{
  VARIABLE var;

  for (var=variable_list; var && strcmp (var->name, name); var = var->next)
    ;
  if (!var)
    return NULL;
  if (var->type == VARTYPE_COUNTER && var->value)
    { /* Use the scratch space allocated by set_var. */
      char *p = var->value + strlen(var->value)+1;
      sprintf (p, "%u", var->count);
      return p;
    }
  else
    return var->value;
}


/* Incremente all counter type variables with NAME in their VALUE. */
static void
inc_counter (const char *name)
{
  VARIABLE var;

  if (!*name)
    return;
  for (var=variable_list; var; var = var->next)
    {
      if (var->type == VARTYPE_COUNTER
          && var->value && !strcmp (var->value, name))
        var->count++;
    }
}


/* Expand variables in LINE and return a new allocated buffer if
   required.  The function might modify LINE if the expanded version
   fits into it. */
static char *
expand_line (char *buffer)
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
        return result; /* nothing more to expand */

      if (p[1] == '$') /* quoted */
        {
          memmove (p, p+1, strlen (p+1)+1);
          line = p + 1;
          continue;
        }
      for (pend=p+1; *pend && !spacep (pend)
           && *pend != '$' && *pend != '/'; pend++)
        ;
      if (*pend)
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


/* Evaluate COND and return the result. */
static int
eval_boolean (const char *cond)
{
  int true = 1;

  for ( ; *cond == '!'; cond++)
    true = !true;
  if (!*cond || (*cond == '0' && !cond[1]))
    return !true;
  return true;
}





static void
cmd_let (const char *assign_to, char *arg)
{
  set_var (assign_to, arg);
}


static void
cmd_echo (const char *assign_to, char *arg)
{
  (void)assign_to;
  if (!opt_no_echo)
    printf ("%s\n", arg);
}

static void
cmd_send (const char *assign_to, char *arg)
{
  (void)assign_to;
  if (opt_verbose)
    fprintf (stderr, "sending '%s'\n", arg);
  write_assuan (server_send_fd, arg);
}

static void
handle_status_line (char *arg)
{
  char *p;

  for (p=arg; *p && !spacep (p); p++)
    ;
  if (*p)
    {
      int save = *p;
      *p = 0;
      inc_counter (arg);
      *p = save;
    }
  else
    inc_counter (arg);
}

static void
cmd_expect_ok (const char *assign_to, char *arg)
{
  (void)assign_to;
  (void)arg;

  if (opt_verbose)
    fprintf (stderr, "expecting OK\n");
  do
    {
      char *p = read_assuan (server_recv_fd);
      if (opt_verbose > 1)
        fprintf (stderr, "got line '%s'\n", recv_line);
      if (recv_type == LINE_STAT)
        handle_status_line (p);
    }
  while (recv_type != LINE_OK && recv_type != LINE_ERR);
  if (recv_type != LINE_OK)
    die_1 ("expected OK but got '%s'", recv_line);
}

static void
cmd_expect_err (const char *assign_to, char *arg)
{
  (void)assign_to;
  (void)arg;

  if (opt_verbose)
    fprintf (stderr, "expecting ERR\n");
  do
    {
      char *p = read_assuan (server_recv_fd);
      if (opt_verbose > 1)
        fprintf (stderr, "got line '%s'\n", recv_line);
      if (recv_type == LINE_STAT)
        handle_status_line (p);
    }
  while (recv_type != LINE_OK && recv_type != LINE_ERR);
  if (recv_type != LINE_ERR)
    die_1 ("expected ERR but got '%s'", recv_line);
}

static void
cmd_count_status (const char *assign_to, char *arg)
{
  char *p;

  if (!*assign_to || !*arg)
    die_0 ("syntax error: count-status requires an argument and a variable");

  for (p=arg; *p && !spacep (p); p++)
    ;
  if (*p)
    {
      for (*p++ = 0; spacep (p); p++)
        ;
      if (*p)
        die_0 ("cmpfiles: syntax error");
    }
  set_type_var (assign_to, arg, VARTYPE_COUNTER);
}

static void
cmd_openfile (const char *assign_to, char *arg)
{
  int fd;
  char numbuf[20];

  do
    fd = open (arg, O_RDONLY);
  while (fd == -1 && errno == EINTR);
  if (fd == -1)
    die_2 ("error opening '%s': %s", arg, strerror (errno));

  sprintf (numbuf, "%d", fd);
  set_type_var (assign_to, numbuf, VARTYPE_FD);
}

static void
cmd_createfile (const char *assign_to, char *arg)
{
  int fd;
  char numbuf[20];

  do
    fd = open (arg, O_WRONLY|O_CREAT|O_TRUNC, 0666);
  while (fd == -1 && errno == EINTR);
  if (fd == -1)
    die_2 ("error creating '%s': %s", arg, strerror (errno));

  sprintf (numbuf, "%d", fd);
  set_type_var (assign_to, numbuf, VARTYPE_FD);
}


static void
cmd_pipeserver (const char *assign_to, char *arg)
{
  (void)assign_to;

  if (!*arg)
    die_0 ("syntax error: servername missing");

  start_server (arg);
}


static void
cmd_quit_if(const char *assign_to, char *arg)
{
  (void)assign_to;

  if (eval_boolean (arg))
    exit (0);
}

static void
cmd_fail_if(const char *assign_to, char *arg)
{
  (void)assign_to;

  if (eval_boolean (arg))
    exit (1);
}


static void
cmd_cmpfiles (const char *assign_to, char *arg)
{
  char *p = arg;
  char *second;
  FILE *fp1, *fp2;
  char buffer1[2048]; /* note: both must be of equal size. */
  char buffer2[2048];
  size_t nread1, nread2;
  int rc = 0;

  set_var (assign_to, "0");
  for (p=arg; *p && !spacep (p); p++)
    ;
  if (!*p)
    die_0 ("cmpfiles: syntax error");
  for (*p++ = 0; spacep (p); p++)
    ;
  second = p;
  for (; *p && !spacep (p); p++)
    ;
  if (*p)
    {
      for (*p++ = 0; spacep (p); p++)
        ;
      if (*p)
        die_0 ("cmpfiles: syntax error");
    }

  fp1 = fopen (arg, "rb");
  if (!fp1)
    {
      err ("can't open '%s': %s", arg, strerror (errno));
      return;
    }
  fp2 = fopen (second, "rb");
  if (!fp2)
    {
      err ("can't open '%s': %s", second, strerror (errno));
      fclose (fp1);
      return;
    }
  while ( (nread1 = fread (buffer1, 1, sizeof buffer1, fp1)))
    {
      if (ferror (fp1))
        break;
      nread2 = fread (buffer2, 1, sizeof buffer2, fp2);
      if (ferror (fp2))
        break;
      if (nread1 != nread2 || memcmp (buffer1, buffer2, nread1))
        {
          rc = 1;
          break;
        }
    }
  if (feof (fp1) && feof (fp2) && !rc)
    {
      if (opt_verbose)
        err ("files match");
      set_var (assign_to, "1");
    }
  else if (!rc)
    err ("cmpfiles: read error: %s", strerror (errno));
  else
    err ("cmpfiles: mismatch");
  fclose (fp1);
  fclose (fp2);
}

static void
cmd_getenv (const char *assign_to, char *arg)
{
  const char *s;
  s = *arg? getenv (arg):"";
  set_var (assign_to, s? s:"");
}




/* Process the current script line LINE. */
static int
interpreter (char *line)
{
  static struct {
    const char *name;
    void (*fnc)(const char*, char*);
  } cmdtbl[] = {
    { "let"       , cmd_let },
    { "echo"      , cmd_echo },
    { "send"      , cmd_send },
    { "expect-ok" , cmd_expect_ok },
    { "expect-err", cmd_expect_err },
    { "count-status", cmd_count_status },
    { "openfile"  , cmd_openfile },
    { "createfile", cmd_createfile },
    { "pipeserver", cmd_pipeserver },
    { "quit"      , NULL },
    { "quit-if"   , cmd_quit_if },
    { "fail-if"   , cmd_fail_if },
    { "cmpfiles"  , cmd_cmpfiles },
    { "getenv"    , cmd_getenv },
    { NULL }
  };
  char *p, *save_p;
  int i, save_c;
  char *stmt = NULL;
  char *assign_to = NULL;
  char *must_free = NULL;

  for ( ;spacep (line); line++)
    ;
  if (!*line || *line == '#')
    return 0; /* empty or comment */
  p = expand_line (line);
  if (p)
    {
      must_free = p;
      line = p;
      for ( ;spacep (line); line++)
        ;
      if (!*line || *line == '#')
        {
          free (must_free);
          return 0; /* empty or comment */
        }
    }
  for (p=line; *p && !spacep (p) && *p != '='; p++)
    ;
  if (*p == '=')
    {
      *p = 0;
      assign_to = line;
    }
  else if (*p)
    {
      for (*p++ = 0; spacep (p); p++)
        ;
      if (*p == '=')
        assign_to = line;
    }
  if (!*line)
    die_0 ("syntax error");
  stmt = line;
  save_c = 0;
  save_p = NULL;
  if (assign_to)
    { /* this is an assignment */
      for (p++; spacep (p); p++)
        ;
      if (!*p)
        {
          unset_var (assign_to);
          free (must_free);
          return 0;
        }
      stmt = p;
      for (; *p && !spacep (p); p++)
        ;
      if (*p)
        {
          save_p = p;
          save_c = *p;
          for (*p++ = 0; spacep (p);  p++)
            ;
        }
    }
  for (i=0; cmdtbl[i].name && strcmp (stmt, cmdtbl[i].name); i++)
    ;
  if (!cmdtbl[i].name)
    {
      if (!assign_to)
        die_1 ("invalid statement '%s'\n", stmt);
      if (save_p)
        *save_p = save_c;
      set_var (assign_to, stmt);
      free (must_free);
      return 0;
    }

  if (cmdtbl[i].fnc)
    cmdtbl[i].fnc (assign_to, p);
  free (must_free);
  return cmdtbl[i].fnc? 0:1;
}



int
main (int argc, char **argv)
{
  char buffer[2048];
  char *p, *pend;

  if (!argc)
    invocation_name = "asschk";
  else
    {
      invocation_name = *argv++;
      argc--;
      p = strrchr (invocation_name, '/');
      if (p)
        invocation_name = p+1;
    }


  set_var ("?","1"); /* defaults to true */

  for (; argc; argc--, argv++)
    {
      p = *argv;
      if (*p != '-')
        break;
      if (!strcmp (p, "--verbose"))
        opt_verbose++;
      else if (!strcmp (p, "--no-echo"))
        opt_no_echo++;
      else if (*p == '-' && p[1] == 'D')
        {
          p += 2;
          pend = strchr (p, '=');
          if (pend)
            {
              int tmp = *pend;
              *pend = 0;
              set_var (p, pend+1);
              *pend = tmp;
            }
          else
            set_var (p, "1");
        }
      else if (*p == '-' && p[1] == '-' && !p[2])
        {
          argc--; argv++;
          break;
        }
      else
        break;
    }
  if (argc)
    die ("usage: asschk [--verbose] {-D<name>[=<value>]}");


  while (fgets (buffer, sizeof buffer, stdin))
    {
      p = strchr (buffer,'\n');
      if (!p)
        die_0 ("incomplete script line");
      *p = 0;
      if (interpreter (buffer))
        break;
      fflush (stdout);
    }
  return 0;
}
