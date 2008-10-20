/* gpgparsemail.c - Standalone crypto mail parser
 *	Copyright (C) 2004, 2007 Free Software Foundation, Inc.
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


/* This utility prints an RFC8222, possible MIME structured, message
   in an annotated format with the first column having an indicator
   for the content of the line.  Several options are available to
   scrutinize the message.  S/MIME and OpenPGP support is included. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "rfc822parse.h"


#define PGM "gpgparsemail"

/* Option flags. */
static int verbose;
static int debug;
static int opt_crypto;    /* Decrypt or verify messages. */
static int opt_no_header; /* Don't output the header lines. */

/* Structure used to communicate with the parser callback. */
struct parse_info_s {
  int show_header;             /* Show the header lines. */
  int show_data;               /* Show the data lines. */
  unsigned int skip_show;      /* Temporary disable above for these
                                   number of lines. */
  int show_data_as_note;       /* The next data line should be shown
                                  as a note. */
  int show_boundary;
  int nesting_level;

  int is_pkcs7;                /* Old style S/MIME message. */

  int moss_state;              /* State of PGP/MIME or S/MIME parsing.  */
  int is_smime;                /* This is S/MIME and not PGP/MIME. */

  char *signing_protocol;
  int hashing_level;           /* The nesting level we are hashing. */
  int hashing;                 
  FILE *hash_file;

  FILE *sig_file;              /* Signature part with MIME or full
                                  pkcs7 data if IS_PCKS7 is set. */
  int  verify_now;             /* Flag set when all signature data is
                                  available. */
};


/* Print diagnostic message and exit with failure. */
static void
die (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  putc ('\n', stderr);

  exit (1);
}


/* Print diagnostic message. */
static void
err (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);

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
    die ("out of core: %s", strerror (errno));
  return p;
}

/* static void * */
/* xcalloc (size_t n, size_t m) */
/* { */
/*   void *p = calloc (n, m); */
/*   if (!p) */
/*     die ("out of core: %s", strerror (errno)); */
/*   return p; */
/* } */

/* static void * */
/* xrealloc (void *old, size_t n) */
/* { */
/*   void *p = realloc (old, n); */
/*   if (!p) */
/*     die ("out of core: %s", strerror (errno)); */
/*   return p; */
/* } */

static char *
xstrdup (const char *string)
{
  void *p = malloc (strlen (string)+1);
  if (!p)
    die ("out of core: %s", strerror (errno));
  strcpy (p, string);
  return p;
}

#ifndef HAVE_STPCPY
static char *
stpcpy (char *a,const char *b)
{
  while (*b)
    *a++ = *b++;
  *a = 0;
  
  return (char*)a;
}
#endif

static int
run_gnupg (int smime, int sig_fd, int data_fd, int *close_list)
{
  int rp[2];
  pid_t pid;
  int i, c, is_status;
  unsigned int pos;
  char status_buf[10];
  FILE *fp;

  if (pipe (rp) == -1)
    die ("error creating a pipe: %s", strerror (errno));

  pid = fork ();
  if (pid == -1)
    die ("error forking process: %s", strerror (errno));

  if (!pid)
    { /* Child. */
      char data_fd_buf[50];
      int fd;

      /* Connect our signature fd to stdin. */
      if (sig_fd != 0)
        {
          if (dup2 (sig_fd, 0) == -1)
            die ("dup2 stdin failed: %s", strerror (errno));
        }
      
      /* Keep our data fd and format it for gpg/gpgsm use. */
      if (data_fd == -1)
        *data_fd_buf = 0;
      else
        sprintf (data_fd_buf, "-&%d", data_fd);

      /* Send stdout to the bit bucket. */
      fd = open ("/dev/null", O_WRONLY);
      if (fd == -1)
        die ("can't open `/dev/null': %s", strerror (errno));
      if (fd != 1)
	{
          if (dup2 (fd, 1) == -1)
            die ("dup2 stderr failed: %s", strerror (errno));
        }
      
      /* Connect stderr to our pipe. */
      if (rp[1] != 2)
	{
	  if (dup2 (rp[1], 2) == -1)
	    die ("dup2 stderr failed: %s", strerror (errno));
	}

      /* Close other files. */
      for (i=0; (fd=close_list[i]) != -1; i++)
        if (fd > 2 && fd != data_fd)
          close (fd);
      errno = 0;

      if (smime)
        execlp ("gpgsm", "gpgsm",
                "--enable-special-filenames",
                "--status-fd", "2",
                "--assume-base64",
                "--verify",
                "--",
                "-", data_fd == -1? NULL : data_fd_buf,
                NULL);
      else
        execlp ("gpg", "gpg",
                "--enable-special-filenames",
                "--status-fd", "2",
                "--verify",
                "--debug=512",
                "--",
                "-", data_fd == -1? NULL : data_fd_buf,
                NULL);
      
      die ("failed to exec the crypto command: %s", strerror (errno));
    }

  /* Parent. */ 
  close (rp[1]);

  fp = fdopen (rp[0], "r");
  if (!fp)
    die ("can't fdopen pipe for reading: %s", strerror (errno));

  pos = 0;
  is_status = 0;
  assert (sizeof status_buf > 9);
  while ((c=getc (fp)) != EOF)
    {
      if (pos < 9)
        status_buf[pos] = c;
      else 
        {
          if (pos == 9)
            {
              is_status = !memcmp (status_buf, "[GNUPG:] ", 9);
              if (is_status)
                fputs ( "c ", stdout);
              else if (verbose)
                fputs ( "# ", stdout);
              fwrite (status_buf, 9, 1, stdout);
            }
          putchar (c);
        }
      if (c == '\n')
        {
          if (verbose && pos < 9)
            {
              fputs ( "# ", stdout);
              fwrite (status_buf, pos+1, 1, stdout);
            }
          pos = 0;
        }
      else
        pos++;
    }
  if (pos)
    {
      if (verbose && pos < 9)
        {
          fputs ( "# ", stdout);
          fwrite (status_buf, pos+1, 1, stdout);
        }
      putchar ('\n');
    }
  fclose (fp);

  while ( (i=waitpid (pid, NULL, 0)) == -1 && errno == EINTR)
    ;
  if (i == -1)
    die ("waiting for child failed: %s", strerror (errno));

  return 0;
}




/* Verify the signature in the current temp files. */
static void
verify_signature (struct parse_info_s *info)
{
  int close_list[10];

  if (info->is_pkcs7)
    {
      assert (!info->hash_file);
      assert (info->sig_file);
      rewind (info->sig_file);
    }
  else
    {
      assert (info->hash_file);
      assert (info->sig_file);
      rewind (info->hash_file);
      rewind (info->sig_file);
    }

/*   printf ("# Begin hashed data\n"); */
/*   while ( (c=getc (info->hash_file)) != EOF) */
/*     putchar (c); */
/*   printf ("# End hashed data signature\n"); */
/*   printf ("# Begin signature\n"); */
/*   while ( (c=getc (info->sig_file)) != EOF) */
/*     putchar (c); */
/*   printf ("# End signature\n"); */
/*   rewind (info->hash_file); */
/*   rewind (info->sig_file); */

  close_list[0] = -1;
  run_gnupg (info->is_smime, fileno (info->sig_file),
             info->hash_file ? fileno (info->hash_file) : -1, close_list);
}





/* Prepare for a multipart/signed. 
   FIELD_CTX is the parsed context of the content-type header.*/
static void
mime_signed_begin (struct parse_info_s *info, rfc822parse_t msg,
                   rfc822parse_field_t field_ctx)
{
  const char *s;

  (void)msg;

  s = rfc822parse_query_parameter (field_ctx, "protocol", 1);
  if (s)
    {
      printf ("h signed.protocol: %s\n", s);
      if (!strcmp (s, "application/pgp-signature"))
        {
          if (info->moss_state)
            err ("note: ignoring nested PGP/MIME or S/MIME signature");
          else
            {
              info->moss_state = 1;
              info->is_smime = 0;
              free (info->signing_protocol);
              info->signing_protocol = xstrdup (s);
            }
        }
      else if (!strcmp (s, "application/pkcs7-signature")
               || !strcmp (s, "application/x-pkcs7-signature"))
        {
          if (info->moss_state)
            err ("note: ignoring nested PGP/MIME or S/MIME signature");
          else
            {
              info->moss_state = 1;
              info->is_smime = 1;
              free (info->signing_protocol);
              info->signing_protocol = xstrdup (s);
            }
        }
      else if (verbose)
        printf ("# this protocol is not supported\n");
    }
}


/* Prepare for a multipart/encrypted. 
   FIELD_CTX is the parsed context of the content-type header.*/
static void
mime_encrypted_begin (struct parse_info_s *info, rfc822parse_t msg,
                      rfc822parse_field_t field_ctx)
{
  const char *s;

  (void)info;
  (void)msg;

  s = rfc822parse_query_parameter (field_ctx, "protocol", 0);
  if (s)
    printf ("h encrypted.protocol: %s\n", s);
}


/* Prepare for old-style pkcs7 messages. */
static void
pkcs7_begin (struct parse_info_s *info, rfc822parse_t msg,
             rfc822parse_field_t field_ctx)
{
  const char *s;
  
  (void)msg;

  s = rfc822parse_query_parameter (field_ctx, "name", 0);
  if (s)
    printf ("h pkcs7.name: %s\n", s);
  if (info->is_pkcs7)
    err ("note: ignoring nested pkcs7 data");
  else
    {
      info->is_pkcs7 = 1;
      if (opt_crypto)
        {
          assert (!info->sig_file);
          info->sig_file = tmpfile ();
          if (!info->sig_file)
            die ("error creating temp file: %s", strerror (errno));
        }
    }
}


/* Print the event received by the parser for debugging as comment
   line. */
static void
show_event (rfc822parse_event_t event)
{
  const char *s;

  switch (event)
    {
    case RFC822PARSE_OPEN: s= "Open"; break;
    case RFC822PARSE_CLOSE: s= "Close"; break;
    case RFC822PARSE_CANCEL: s= "Cancel"; break;
    case RFC822PARSE_T2BODY: s= "T2Body"; break;
    case RFC822PARSE_FINISH: s= "Finish"; break;
    case RFC822PARSE_RCVD_SEEN: s= "Rcvd_Seen"; break;
    case RFC822PARSE_LEVEL_DOWN: s= "Level_Down"; break;
    case RFC822PARSE_LEVEL_UP: s= "Level_Up"; break;
    case RFC822PARSE_BOUNDARY: s= "Boundary"; break;
    case RFC822PARSE_LAST_BOUNDARY: s= "Last_Boundary"; break;
    case RFC822PARSE_BEGIN_HEADER: s= "Begin_Header"; break;
    case RFC822PARSE_PREAMBLE: s= "Preamble"; break;
    case RFC822PARSE_EPILOGUE: s= "Epilogue"; break;
    default: s= "[unknown event]"; break;
    }
  printf ("# *** got RFC822 event %s\n", s);
}

/* This function is called by the parser to communicate events.  This
   callback comminucates with the main program using a structure
   passed in OPAQUE. Should retrun 0 or set errno and return -1. */
static int
message_cb (void *opaque, rfc822parse_event_t event, rfc822parse_t msg)
{
  struct parse_info_s *info = opaque;

  if (debug)
    show_event (event);

  if (event == RFC822PARSE_BEGIN_HEADER || event == RFC822PARSE_T2BODY)
    {
      /* We need to check here whether to start collecting signed data
         because attachments might come without header lines and thus
         we won't see the BEGIN_HEADER event.  */
      if (info->moss_state == 1)
        {
          printf ("c begin_hash\n");
          info->hashing = 1;
          info->hashing_level = info->nesting_level;
          info->moss_state++;

          if (opt_crypto)
            {
              assert (!info->hash_file);
              info->hash_file = tmpfile ();
              if (!info->hash_file)
                die ("failed to create temporary file: %s", strerror (errno));
            }
        }
    }


  if (event == RFC822PARSE_OPEN)
    {
      /* Initialize for a new message. */
      info->show_header = 1;
    }
  else if (event == RFC822PARSE_T2BODY)
    {
      rfc822parse_field_t ctx;

      ctx = rfc822parse_parse_field (msg, "Content-Type", -1);
      if (ctx)
        {
          const char *s1, *s2;
          s1 = rfc822parse_query_media_type (ctx, &s2);
          if (s1)
            {
              printf ("h media: %*s%s %s\n", 
                      info->nesting_level*2, "", s1, s2);
              if (info->moss_state == 3)
                {
                  char *buf = xmalloc (strlen (s1) + strlen (s2) + 2);
                  strcpy (stpcpy (stpcpy (buf, s1), "/"), s2);
                  assert (info->signing_protocol);
                  if (strcmp (buf, info->signing_protocol))
                    err ("invalid %s structure; expected `%s', found `%s'",
                         info->is_smime? "S/MIME":"PGP/MIME",
                         info->signing_protocol, buf);
                  else
                    {
                      printf ("c begin_signature\n");
                      info->moss_state++;
                      if (opt_crypto)
                        {
                          assert (!info->sig_file);
                          info->sig_file = tmpfile ();
                          if (!info->sig_file)
                            die ("error creating temp file: %s",
                                 strerror (errno));
                        }
                    }
                  free (buf);
                }
              else if (!strcmp (s1, "multipart"))
                {
                  if (!strcmp (s2, "signed"))
                    mime_signed_begin (info, msg, ctx);
                  else if (!strcmp (s2, "encrypted"))
                    mime_encrypted_begin (info, msg, ctx);
                }
              else if (!strcmp (s1, "application")
                       && (!strcmp (s2, "pkcs7-mime")
                           || !strcmp (s2, "x-pkcs7-mime")))
                pkcs7_begin (info, msg, ctx);
            }
          else
            printf ("h media: %*s none\n", info->nesting_level*2, "");
              
          rfc822parse_release_field (ctx);
        }
      else
        printf ("h media: %*stext plain [assumed]\n",
                info->nesting_level*2, "");


      info->show_header = 0;
      info->show_data = 1;
      info->skip_show = 1;
    }
  else if (event == RFC822PARSE_PREAMBLE)
    info->show_data_as_note = 1;
  else if (event == RFC822PARSE_LEVEL_DOWN)
    {
      printf ("b down\n");
      info->nesting_level++;
    }
  else if (event == RFC822PARSE_LEVEL_UP)
    {
      printf ("b up\n");
      if (info->nesting_level)
        info->nesting_level--;
      else 
        err ("invalid structure (bad nesting level)");
    }
  else if (event == RFC822PARSE_BOUNDARY || event == RFC822PARSE_LAST_BOUNDARY)
    {
      info->show_data = 0;
      info->show_boundary = 1;
      if (event == RFC822PARSE_BOUNDARY)
        {
          info->show_header = 1;
          info->skip_show = 1;
          printf ("b part\n");
        }
      else 
        printf ("b last\n");

      if (info->moss_state == 2 && info->nesting_level == info->hashing_level)
        {
          printf ("c end_hash\n");
          info->moss_state++;
          info->hashing = 0;
        }
      else if (info->moss_state == 4)
        {
          printf ("c end_signature\n");
          info->verify_now = 1;
        }
    }

  return 0;
}


/* Read a message from FP and process it according to the global
   options. */
static void
parse_message (FILE *fp)
{
  char line[5000];
  size_t length;
  rfc822parse_t msg;
  unsigned int lineno = 0;
  int no_cr_reported = 0;
  struct parse_info_s info;

  memset (&info, 0, sizeof info);

  msg = rfc822parse_open (message_cb, &info);
  if (!msg)
    die ("can't open parser: %s", strerror (errno));

  /* Fixme: We should not use fgets becuase it can't cope with
     embedded nul characters. */
  while (fgets (line, sizeof (line), fp))
    {
      lineno++;
      if (lineno == 1 && !strncmp (line, "From ", 5))
        continue;  /* We better ignore a leading From line. */

      length = strlen (line);
      if (length && line[length - 1] == '\n')
	line[--length] = 0;
      else
        err ("line number %u too long or last line not terminated", lineno);
      if (length && line[length - 1] == '\r')
	line[--length] = 0;
      else if (verbose && !no_cr_reported)
        {
          err ("non canonical ended line detected (line %u)", lineno);
          no_cr_reported = 1;
        }


      if (rfc822parse_insert (msg, line, length))
	die ("parser failed: %s", strerror (errno));
      
      if (info.hashing)
        {
          /* Delay hashing of the CR/LF because the last line ending
             belongs to the next boundary. */
          if (debug)
            printf ("# hashing %s`%s'\n", info.hashing==2?"CR,LF+":"", line);
          if (opt_crypto)
            {
              if (info.hashing == 2)
                fputs ("\r\n", info.hash_file);
              fputs (line, info.hash_file);
              if (ferror (info.hash_file))
                die ("error writing to temporary file: %s", strerror (errno));
            }

          info.hashing = 2;
        }

      if (info.sig_file && opt_crypto)
        {
          if (info.verify_now)
            {
              verify_signature (&info);
              if (info.hash_file)
                fclose (info.hash_file);
              info.hash_file = NULL;
              fclose (info.sig_file);
              info.sig_file = NULL;
              info.moss_state = 0;
              info.is_smime = 0;
              info.is_pkcs7 = 0;
            }
          else
            {
              fputs (line, info.sig_file);
              fputs ("\r\n", info.sig_file);
              if (ferror (info.sig_file))
                die ("error writing to temporary file: %s", strerror (errno));
            }
        }
      
      if (info.show_boundary)
        {
          if (!opt_no_header)
            printf (":%s\n", line);
          info.show_boundary = 0;
        }

      if (info.skip_show)
        info.skip_show--;
      else if (info.show_data)
        {
          if (info.show_data_as_note)
            {
              if (verbose)
                printf ("# DATA: %s\n", line);
              info.show_data_as_note = 0;
            }
          else
            printf (" %s\n", line);
        }
      else if (info.show_header && !opt_no_header)
        printf (".%s\n", line);

    }

  if (info.sig_file && opt_crypto && info.is_pkcs7)
    {
      verify_signature (&info);
      fclose (info.sig_file);
      info.sig_file = NULL;
      info.is_pkcs7 = 0;
    }

  rfc822parse_close (msg);
}


int 
main (int argc, char **argv)
{
  int last_argc = -1;
 
  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          puts (
                "Usage: " PGM " [OPTION] [FILE]\n"
                "Parse a mail message into an annotated format.\n\n"
                "  --crypto    decrypt or verify messages\n"
                "  --no-header don't output the header lines\n"
                "  --verbose   enable extra informational output\n"
                "  --debug     enable additional debug output\n"
                "  --help      display this help and exit\n\n"
                "With no FILE, or when FILE is -, read standard input.\n\n"
                "WARNING: This tool is under development.\n"
                "         The semantics may change without notice\n\n"
                "Report bugs to <bug-gnupg@gnu.org>.");
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--crypto"))
        {
          opt_crypto = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--no-header"))
        {
          opt_no_header = 1;
          argc--; argv++;
        }
    }          
 
  if (argc > 1)
    die ("usage: " PGM " [OPTION] [FILE] (try --help for more information)\n");

  signal (SIGPIPE, SIG_IGN);

  if (argc && strcmp (*argv, "-"))
    {
      FILE *fp = fopen (*argv, "rb");
      if (!fp)
        die ("can't open `%s': %s", *argv, strerror (errno));
      parse_message (fp);
      fclose (fp);
    }
  else
    parse_message (stdin);

  return 0;
}


/*
Local Variables:
compile-command: "gcc -Wall -Wno-pointer-sign -g -o gpgparsemail rfc822parse.c gpgparsemail.c"
End:
*/
