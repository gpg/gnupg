/* symcryptrun.c - Tool to call simple symmetric encryption tools.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */


/* Sometimes simple encryption tools are already in use for a long
   time and there is a desire to integrate them into the GnuPG
   framework.  The protocols and encryption methods might be
   non-standard or not even properly documented, so that a
   full-fledged encryption tool with an interface like gpg is not
   doable.  This simple wrapper program provides a solution: It
   operates by calling the encryption/decryption module and providing
   the passphrase for a key (or even the key directly) using the
   standard pinentry mechanism through gpg-agent.  */

/* This program is invoked in the following way:

   symcryptrun --class CLASS --program PROGRAM --keyfile KEYFILE \
     [--decrypt | --encrypt]

   For encryption, the plain text must be provided on STDIN, and the
   ciphertext will be output to STDOUT.  For decryption vice versa.

   CLASS can currently only be "confucius".

   PROGRAM must be the path to the crypto engine.

   KEYFILE must contain the secret key, which may be protected by a
   passphrase.  The passphrase is retrieved via the pinentry program.


   The GPG Agent _must_ be running before starting symcryptrun.

   The possible exit status codes:

   0	Success
   1	Some error occurred
   2	No valid passphrase was provided
   3	The operation was canceled by the user

   Other classes may be added in the future.  */

#define SYMC_BAD_PASSPHRASE	2
#define SYMC_CANCELED		3


#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef HAVE_PTY_H
#include <pty.h>
#else
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#endif

#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#include <ctype.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif
#include <gpg-error.h>

#include "../common/i18n.h"
#include "../common/util.h"
#include "../common/init.h"
#include "../common/sysutils.h"

/* FIXME: Bah.  For spwq_secure_free.  */
#define SIMPLE_PWQUERY_IMPLEMENTATION 1
#include "../common/simple-pwquery.h"


/* From simple-gettext.c.  */

/* We assume to have 'unsigned long int' value with at least 32 bits.  */
#define HASHWORDBITS 32

/* The so called 'hashpjw' function by P.J. Weinberger
   [see Aho/Sethi/Ullman, COMPILERS: Principles, Techniques and Tools,
   1986, 1987 Bell Telephone Laboratories, Inc.]  */

static __inline__ ulong
hash_string( const char *str_param )
{
    unsigned long int hval, g;
    const char *str = str_param;

    hval = 0;
    while (*str != '\0')
    {
	hval <<= 4;
	hval += (unsigned long int) *str++;
	g = hval & ((unsigned long int) 0xf << (HASHWORDBITS - 4));
	if (g != 0)
	{
	  hval ^= g >> (HASHWORDBITS - 8);
	  hval ^= g;
	}
    }
    return hval;
}


/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,
    oQuiet      = 'q',
    oVerbose	= 'v',

    oNoVerbose	= 500,
    oOptions,
    oNoOptions,
    oLogFile,
    oHomedir,
    oClass,
    oProgram,
    oKeyfile,
    oDecrypt,
    oEncrypt,
    oInput
  };


/* The list of commands and options.  */
static ARGPARSE_OPTS opts[] =
  {
    { 301, NULL, 0, N_("@\nCommands:\n ") },

    { oDecrypt, "decrypt", 0, N_("decryption modus") },
    { oEncrypt, "encrypt", 0, N_("encryption modus") },

    { 302, NULL, 0, N_("@\nOptions:\n ") },

    { oClass, "class", 2, N_("tool class (confucius)") },
    { oProgram, "program", 2, N_("program filename") },

    { oKeyfile, "keyfile", 2, N_("secret key file (required)") },
    { oInput, "inputfile", 2, N_("input file name (default stdin)") },
    { oVerbose, "verbose",  0, N_("verbose") },
    { oQuiet, "quiet",      0, N_("quiet") },
    { oLogFile, "log-file", 2, N_("use a log file for the server") },
    { oOptions,  "options"  , 2, N_("|FILE|read options from FILE") },

    /* Hidden options.  */
    { oNoVerbose, "no-verbose",  0, "@" },
    { oHomedir, "homedir", 2, "@" },
    { oNoOptions, "no-options", 0, "@" },/* shortcut for --options /dev/null */

    {0}
  };


/* We keep all global options in the structure OPT.  */
struct
{
  int verbose;		/* Verbosity level.  */
  int quiet;		/* Be extra quiet.  */
  const char *homedir;  /* Configuration directory name */

  char *class;
  char *program;
  char *keyfile;
  char *input;
} opt;


/* Print usage information and provide strings for help.  */
static const char *
my_strusage (int level)
{
  const char *p;

  switch (level)
    {
    case 11: p = "symcryptrun (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p = _("Usage: symcryptrun [options] (-h for help)");
      break;
    case 41:
      p = _("Syntax: symcryptrun --class CLASS --program PROGRAM "
	    "--keyfile KEYFILE [options...] COMMAND [inputfile]\n"
            "Call a simple symmetric encryption tool\n");
      break;
    case 31: p = "\nHome: "; break;
    case 32: p = gnupg_homedir (); break;
    case 33: p = "\n"; break;

    default: p = NULL; break;
    }
  return p;
}



/* This is in the GNU C library in unistd.h.  */

#ifndef TEMP_FAILURE_RETRY
/* Evaluate EXPRESSION, and repeat as long as it returns -1 with 'errno'
   set to EINTR.  */

# define TEMP_FAILURE_RETRY(expression) \
  (__extension__                                                              \
    ({ long int __result;                                                     \
       do __result = (long int) (expression);                                 \
       while (__result == -1L && errno == EINTR);                             \
       __result; }))
#endif

/* Unlink a file, and shred it if SHRED is true.  */
int
remove_file (char *name, int shred)
{
  if (!shred)
    return unlink (name);
  else
    {
      int status;
      pid_t pid;

      pid = fork ();
      if (pid == 0)
	{
	  /* Child.  */

	  /* -f forces file to be writable, and -u unlinks it afterwards.  */
	  char *args[] = { SHRED, "-uf", name, NULL };

	  execv (SHRED, args);
	  _exit (127);
	}
      else if (pid < 0)
	{
	  /* Fork failed.  */
	  status = -1;
	}
      else
	{
	  /* Parent.  */

	  if (TEMP_FAILURE_RETRY (waitpid (pid, &status, 0)) != pid)
	    status = -1;
	}

      if (!WIFEXITED (status))
	{
	  log_error (_("%s on %s aborted with status %i\n"),
		     SHRED, name, status);
	  unlink (name);
	  return 1;
	}
      else if (WEXITSTATUS (status))
	{
	  log_error (_("%s on %s failed with status %i\n"), SHRED, name,
		     WEXITSTATUS (status));
	  unlink (name);
	  return 1;
	}

      return 0;
    }
}


/* Class Confucius.

   "Don't worry that other people don't know you;
   worry that you don't know other people."            Analects--1.16.  */

/* Create temporary directory with mode 0700.  Returns a dynamically
   allocated string with the filename of the directory.  */
static char *
confucius_mktmpdir (void)
{
  char *name, *p;

  p = getenv ("TMPDIR");
  if (!p || !*p)
    p = "/tmp";
  if (p[strlen (p) - 1] == '/')
    name = xstrconcat (p, "gpg-XXXXXX", NULL);
  else
    name = xstrconcat (p, "/", "gpg-XXXXXX", NULL);
  if (!name || !gnupg_mkdtemp (name))
    {
      log_error (_("can't create temporary directory '%s': %s\n"),
                 name?name:"", strerror (errno));
      return NULL;
    }

  return name;
}


/* Buffer size for I/O operations.  */
#define CONFUCIUS_BUFSIZE 4096

/* Buffer size for output lines.  */
#define CONFUCIUS_LINESIZE 4096


/* Copy the file IN to OUT, either of which may be "-".  If PLAIN is
   true, and the copying fails, and OUT is not STDOUT, then shred the
   file instead unlinking it.  */
static int
confucius_copy_file (char *infile, char *outfile, int plain)
{
  FILE *in;
  int in_is_stdin = 0;
  FILE *out;
  int out_is_stdout = 0;
  char data[CONFUCIUS_BUFSIZE];
  ssize_t data_len;

  if (infile[0] == '-' && infile[1] == '\0')
    {
      /* FIXME: Is stdin in binary mode?  */
      in = stdin;
      in_is_stdin = 1;
    }
  else
    {
      in = fopen (infile, "rb");
      if (!in)
	{
	  log_error (_("could not open %s for writing: %s\n"),
		     infile, strerror (errno));
	  return 1;
	}
    }

  if (outfile[0] == '-' && outfile[1] == '\0')
    {
      /* FIXME: Is stdout in binary mode?  */
      out = stdout;
      out_is_stdout = 1;
    }
  else
    {
      out = fopen (outfile, "wb");
      if (!out)
	{
	  log_error (_("could not open %s for writing: %s\n"),
		     infile, strerror (errno));
	  return 1;
	}
    }

  /* Now copy the data.  */
  while ((data_len = fread (data, 1, sizeof (data), in)) > 0)
    {
      if (fwrite (data, 1, data_len, out) != data_len)
	{
	  log_error (_("error writing to %s: %s\n"), outfile,
		     strerror (errno));
	  goto copy_err;
	}
    }
  if (data_len < 0 || ferror (in))
    {
      log_error (_("error reading from %s: %s\n"), infile, strerror (errno));
      goto copy_err;
    }

  /* Close IN if appropriate.  */
  if (!in_is_stdin && fclose (in) && ferror (in))
    {
      log_error (_("error closing %s: %s\n"), infile, strerror (errno));
      goto copy_err;
    }

  /* Close OUT if appropriate.  */
  if (!out_is_stdout && fclose (out) && ferror (out))
    {
      log_error (_("error closing %s: %s\n"), infile, strerror (errno));
      goto copy_err;
    }

  return 0;

 copy_err:
  if (!out_is_stdout)
    remove_file (outfile, plain);

  return 1;
}


/* Get a passphrase in secure storage (if possible).  If AGAIN is
   true, then this is a repeated attempt.  If CANCELED is not a null
   pointer, it will be set to true or false, depending on if the user
   canceled the operation or not.  On error (including cancellation), a
   null pointer is returned.  The passphrase must be deallocated with
   confucius_drop_pass.  CACHEID is the ID to be used for passphrase
   caching and can be NULL to disable caching.  */
char *
confucius_get_pass (const char *cacheid, int again, int *canceled)
{
  int err;
  char *pw;
  char *orig_codeset;

  if (canceled)
    *canceled = 0;

  orig_codeset = i18n_switchto_utf8 ();
  pw = simple_pwquery (cacheid,
                       again ? _("does not match - try again"):NULL,
                       _("Passphrase:"), NULL, 0, &err);
  i18n_switchback (orig_codeset);

  if (!pw)
    {
      if (err)
        log_error (_("error while asking for the passphrase: %s\n"),
                   gpg_strerror (err));
      else
        {
	  log_info (_("cancelled\n"));
	  if (canceled)
	    *canceled = 1;
	}
    }

  return pw;
}


/* Drop a passphrase retrieved with confucius_get_pass.  */
void
confucius_drop_pass (char *pass)
{
  if (pass)
    spwq_secure_free (pass);
}


/* Run a confucius crypto engine.  If MODE is oEncrypt, encryption is
   requested.  If it is oDecrypt, decryption is requested.  INFILE and
   OUTFILE are the temporary files used in the process.  */
int
confucius_process (int mode, char *infile, char *outfile,
		   int argc, char *argv[])
{
  char **args;
  int cstderr[2];
  int master;
  int slave;
  int res;
  pid_t pid;
  pid_t wpid;
  int tries = 0;
  char cacheid[40];

  signal (SIGPIPE, SIG_IGN);

  if (!opt.program)
    {
      log_error (_("no --program option provided\n"));
      return 1;
    }

  if (mode != oDecrypt && mode != oEncrypt)
    {
      log_error (_("only --decrypt and --encrypt are supported\n"));
      return 1;
    }

  if (!opt.keyfile)
    {
      log_error (_("no --keyfile option provided\n"));
      return 1;
    }

  /* Generate a hash from the keyfile name for caching.  */
  snprintf (cacheid, sizeof (cacheid), "confucius:%lu",
	    hash_string (opt.keyfile));
  cacheid[sizeof (cacheid) - 1] = '\0';
  args = malloc (sizeof (char *) * (10 + argc));
  if (!args)
    {
      log_error (_("cannot allocate args vector\n"));
      return 1;
    }
  args[0] = opt.program;
  args[1] = (mode == oEncrypt) ? "-m1" : "-m2";
  args[2] = "-q";
  args[3] = infile;
  args[4] = "-z";
  args[5] = outfile;
  args[6] = "-s";
  args[7] = opt.keyfile;
  args[8] = (mode == oEncrypt) ? "-af" : "-f";
  args[9 + argc] = NULL;
  while (argc--)
    args[9 + argc] = argv[argc];

  if (pipe (cstderr) < 0)
    {
      log_error (_("could not create pipe: %s\n"), strerror (errno));
      free (args);
      return 1;
    }

  if (openpty (&master, &slave, NULL, NULL, NULL) == -1)
    {
      log_error (_("could not create pty: %s\n"), strerror (errno));
      close (cstderr[0]);
      close (cstderr[1]);
      free (args);
      return -1;
    }

  /* We don't want to deal with the worst case scenarios.  */
  assert (master > 2);
  assert (slave > 2);
  assert (cstderr[0] > 2);
  assert (cstderr[1] > 2);

  pid = fork ();
  if (pid < 0)
    {
      log_error (_("could not fork: %s\n"), strerror (errno));
      close (master);
      close (slave);
      close (cstderr[0]);
      close (cstderr[1]);
      free (args);
      return 1;
    }
  else if (pid == 0)
    {
      /* Child.  */

      /* Close the parent ends.  */
      close (master);
      close (cstderr[0]);

      /* Change controlling terminal.  */
      if (login_tty (slave))
	{
	  /* It's too early to output a debug message.  */
	  _exit (1);
	}

      dup2 (cstderr[1], 2);
      close (cstderr[1]);

      /* Now kick off the engine program.  */
      execv (opt.program, args);
      log_error (_("execv failed: %s\n"), strerror (errno));
      _exit (1);
    }
  else
    {
      /* Parent.  */
      char buffer[CONFUCIUS_LINESIZE];
      int buffer_len = 0;
      fd_set fds;
      int slave_closed = 0;
      int stderr_closed = 0;

      close (slave);
      close (cstderr[1]);
      free (args);

      /* Listen on the output FDs.  */
      do
	{
	  FD_ZERO (&fds);

	  if (!slave_closed)
	    FD_SET (master, &fds);
	  if (!stderr_closed)
	    FD_SET (cstderr[0], &fds);

	  res = select (FD_SETSIZE, &fds, NULL, NULL, NULL);
	  if (res < 0)
	    {
	      log_error (_("select failed: %s\n"), strerror (errno));

	      kill (pid, SIGTERM);
	      close (master);
	      close (cstderr[0]);
     	      return 1;
	    }

	  if (FD_ISSET (cstderr[0], &fds))
	    {
	      /* We got some output on stderr.  This is just passed
		 through via the logging facility.  */

	      res = read (cstderr[0], &buffer[buffer_len],
			  sizeof (buffer) - buffer_len - 1);
	      if (res < 0)
		{
		  log_error (_("read failed: %s\n"), strerror (errno));

		  kill (pid, SIGTERM);
		  close (master);
		  close (cstderr[0]);
		  return 1;
		}
	      else
		{
		  char *newline;

		  buffer_len += res;
		  for (;;)
		    {
		      buffer[buffer_len] = '\0';
		      newline = strchr (buffer, '\n');
		      if (newline)
			{
			  *newline = '\0';
			  log_error ("%s\n", buffer);
			  buffer_len -= newline + 1 - buffer;
			  memmove (buffer, newline + 1, buffer_len);
			}
		      else if (buffer_len == sizeof (buffer) - 1)
			{
			  /* Overflow.  */
			  log_error ("%s\n", buffer);
			  buffer_len = 0;
			}
		      else
			break;
		    }

		  if (res == 0)
		    stderr_closed = 1;
		}
	    }
	  else if (FD_ISSET (master, &fds))
	    {
	      char data[512];

	      res = read (master, data, sizeof (data));
	      if (res < 0)
		{
		  if (errno == EIO)
		    {
		      /* Slave-side close leads to readable fd and
			 EIO.  */
		      slave_closed = 1;
		    }
		  else
		    {
		      log_error (_("pty read failed: %s\n"), strerror (errno));

		      kill (pid, SIGTERM);
		      close (master);
		      close (cstderr[0]);
		      return 1;
		    }
		}
	      else if (res == 0)
		/* This never seems to be what happens on slave-side
		   close.  */
		slave_closed = 1;
	      else
		{
		  /* Check for password prompt.  */
		  if (data[res - 1] == ':')
		    {
		      char *pass;
		      int canceled;

		      /* If this is not the first attempt, the
			 passphrase seems to be wrong, so clear the
			 cache.  */
		      if (tries)
			simple_pwclear (cacheid);

		      pass = confucius_get_pass (cacheid,
						 tries ? 1 : 0, &canceled);
		      if (!pass)
			{
			  kill (pid, SIGTERM);
			  close (master);
			  close (cstderr[0]);
			  return canceled ? SYMC_CANCELED : 1;
			}
 		      write (master, pass, strlen (pass));
 		      write (master, "\n", 1);
		      confucius_drop_pass (pass);

		      tries++;
		    }
		}
	    }
	}
      while (!stderr_closed || !slave_closed);

      close (master);
      close (cstderr[0]);

      wpid = waitpid (pid, &res, 0);
      if (wpid < 0)
	{
	  log_error (_("waitpid failed: %s\n"), strerror (errno));

	  kill (pid, SIGTERM);
	  /* State of cached password is unclear.  Just remove it.  */
	  simple_pwclear (cacheid);
	  return 1;
	}
      else
	{
	  /* Shouldn't happen, as we don't use WNOHANG.  */
	  assert (wpid != 0);

	  if (!WIFEXITED (res))
	    {
	      log_error (_("child aborted with status %i\n"), res);

	      /* State of cached password is unclear.  Just remove it.  */
	      simple_pwclear (cacheid);

	      return 1;
	    }

	  if (WEXITSTATUS (res))
	    {
	      /* The passphrase was wrong.  Remove it from the cache.  */
	      simple_pwclear (cacheid);

	      /* We probably exceeded our number of attempts at guessing
		 the password.  */
	      if (tries >= 3)
		return SYMC_BAD_PASSPHRASE;
	      else
		return 1;
	    }

	  return 0;
	}
    }

  /* Not reached.  */
}


/* Class confucius main program.  If MODE is oEncrypt, encryption is
   requested.  If it is oDecrypt, decryption is requested.  The other
   parameters are taken from the global option data.  */
int
confucius_main (int mode, int argc, char *argv[])
{
  int res;
  char *tmpdir;
  char *infile;
  int infile_from_stdin = 0;
  char *outfile;

  tmpdir = confucius_mktmpdir ();
  if (!tmpdir)
    return 1;

  if (opt.input && !(opt.input[0] == '-' && opt.input[1] == '\0'))
    infile = xstrdup (opt.input);
  else
    {
      infile_from_stdin = 1;

      /* TMPDIR + "/" + "in" + "\0".  */
      infile = malloc (strlen (tmpdir) + 1 + 2 + 1);
      if (!infile)
	{
	  log_error (_("cannot allocate infile string: %s\n"),
		     strerror (errno));
	  rmdir (tmpdir);
	  return 1;
	}
      strcpy (infile, tmpdir);
      strcat (infile, "/in");
    }

  /* TMPDIR + "/" + "out" + "\0".  */
  outfile = malloc (strlen (tmpdir) + 1 + 3 + 1);
  if (!outfile)
    {
      log_error (_("cannot allocate outfile string: %s\n"), strerror (errno));
      free (infile);
      rmdir (tmpdir);
      return 1;
    }
  strcpy (outfile, tmpdir);
  strcat (outfile, "/out");

  if (infile_from_stdin)
    {
      /* Create INFILE and fill it with content.  */
      res = confucius_copy_file ("-", infile, mode == oEncrypt);
      if (res)
	{
	  free (outfile);
	  free (infile);
	  rmdir (tmpdir);
	  return res;
	}
    }

  /* Run the engine and thus create the output file, handling
     passphrase retrieval.  */
  res = confucius_process (mode, infile, outfile, argc, argv);
  if (res)
    {
      remove_file (outfile, mode == oDecrypt);
      if (infile_from_stdin)
	remove_file (infile, mode == oEncrypt);
      free (outfile);
      free (infile);
      rmdir (tmpdir);
      return res;
    }

  /* Dump the output file to stdout.  */
  res = confucius_copy_file (outfile, "-", mode == oDecrypt);
  if (res)
    {
      remove_file (outfile, mode == oDecrypt);
      if (infile_from_stdin)
	remove_file (infile, mode == oEncrypt);
      free (outfile);
      free (infile);
      rmdir (tmpdir);
      return res;
    }

  remove_file (outfile, mode == oDecrypt);
  if (infile_from_stdin)
    remove_file (infile, mode == oEncrypt);
  free (outfile);
  free (infile);
  rmdir (tmpdir);
  return 0;
}


/* symcryptrun's entry point.  */
int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  char **orig_argv;
  FILE *configfp = NULL;
  char *configname = NULL;
  unsigned configlineno;
  int mode = 0;
  int res;
  char *logfile = NULL;
  int default_config = 1;

  early_system_init ();
  set_strusage (my_strusage);
  log_set_prefix ("symcryptrun", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);

  /* Check whether we have a config file given on the commandline */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= 1|(1<<6);  /* do not remove the args, ignore version */
  while (arg_parse( &pargs, opts))
    {
      if (pargs.r_opt == oOptions)
        { /* Yes there is one, so we do not try the default one, but
	     read the option file when it is encountered at the
	     commandline */
          default_config = 0;
	}
      else if (pargs.r_opt == oNoOptions)
        default_config = 0; /* --no-options */
      else if (pargs.r_opt == oHomedir)
	gnupg_set_homedir (pargs.r.ret_str);
    }

  if (default_config)
    configname = make_filename (gnupg_homedir (), "symcryptrun.conf", NULL );

  argc = orig_argc;
  argv = orig_argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= 1;  /* do not remove the args */
 next_pass:
  if (configname)
    {
      configlineno = 0;
      configfp = fopen (configname, "r");
      if (!configfp)
        {
          if (!default_config)
            {
              log_error (_("option file '%s': %s\n"),
                         configname, strerror(errno) );
              exit(1);
	    }
          xfree (configname);
          configname = NULL;
	}
      default_config = 0;
    }

  /* Parse the command line. */
  while (optfile_parse (configfp, configname, &configlineno, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oDecrypt:   mode = oDecrypt; break;
        case oEncrypt:   mode = oEncrypt; break;

	case oQuiet:     opt.quiet = 1; break;
        case oVerbose:   opt.verbose++; break;
        case oNoVerbose: opt.verbose = 0; break;

	case oClass:	opt.class = pargs.r.ret_str; break;
	case oProgram:	opt.program = pargs.r.ret_str; break;
	case oKeyfile:	opt.keyfile = pargs.r.ret_str; break;
	case oInput:	opt.input = pargs.r.ret_str; break;

        case oLogFile:  logfile = pargs.r.ret_str; break;

        case oOptions:
          /* Config files may not be nested (silently ignore them) */
          if (!configfp)
            {
		xfree(configname);
		configname = xstrdup(pargs.r.ret_str);
		goto next_pass;
	    }
          break;
        case oNoOptions: break; /* no-options */
        case oHomedir: /* Ignore this option here. */; break;

        default : pargs.err = configfp? 1:2; break;
	}
    }
  if (configfp)
    {
      fclose( configfp );
      configfp = NULL;
      configname = NULL;
      goto next_pass;
    }
  xfree (configname);
  configname = NULL;

  if (!mode)
    log_error (_("either %s or %s must be given\n"),
               "--decrypt", "--encrypt");

  if (log_get_errorcount (0))
    exit (1);

  if (logfile)
    log_set_file (logfile);

  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  setup_libgcrypt_logging ();
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

  /* Tell simple-pwquery about the standard socket name.  */
  {
    char *tmp = make_filename (gnupg_socketdir (), GPG_AGENT_SOCK_NAME, NULL);
    simple_pw_set_socket (tmp);
    xfree (tmp);
  }

  if (!opt.class)
    {
      log_error (_("no class provided\n"));
      res = 1;
    }
  else if (!strcmp (opt.class, "confucius"))
    {
      res = confucius_main (mode, argc, argv);
    }
  else
    {
      log_error (_("class %s is not supported\n"), opt.class);
      res = 1;
    }

  return res;
}
