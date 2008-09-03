/* gpgkeys_kdns.c - Fetch a key via the GnuPG specific KDNS scheme.
 * Copyright (C) 2008 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif
#include <assert.h>
#ifdef HAVE_ADNS_H
# include <adns.h>
# ifndef HAVE_ADNS_FREE
#  define adns_free free
# endif
#endif

#define INCLUDED_BY_MAIN_MODULE 1
#include "util.h"
#include "keyserver.h"
#include "ksutil.h"

/* Our own name.  */
#define PGM "gpgkeys_kdns"

/* getopt(3) requires declarion of some global variables.  */
extern char *optarg;
extern int optind;

/* Convenience variables usually intialized withn std{in,out,err}.  */
static FILE *input, *output, *console;

/* Standard keyserver module options.  */
static struct ks_options *opt;

/* The flags we pass to adns_init: Do not allow any environment
   variables and for now enable debugging.  */
#define MY_ADNS_INITFLAGS  (adns_if_noenv)


/* ADNS has no support for CERT yes. */
#define my_adns_r_cert 37

/* The root of the KDNS tree. */
static const char *kdns_root;

/* The replacement string for the at sign.  */
static const char *kdns_at_repl;

/* Flag indicating that a TCP conenction should be used.  */
static int kdns_usevc;



/* Retrieve one key.  ADDRESS should be an RFC-2822 addr-spec. */
static int
get_key (adns_state adns_ctx, char *address)
{
  int ret = KEYSERVER_INTERNAL_ERROR;
  const char *domain;
  char *name = NULL;
  adns_answer *answer = NULL;
  const unsigned char *data;
  int datalen;
  struct b64state b64state;
  char *p;

  domain = strrchr (address, '@');
  if (!domain || domain == address || !domain[1])
    {
      fprintf (console, PGM": invalid mail address `%s'\n", address);
      ret = KEYSERVER_GENERAL_ERROR;
      goto leave;
    }
  name = xtrymalloc (strlen (address) + strlen (kdns_at_repl)
                     + 1 + strlen (kdns_root) + 1);
  if (!name)
    goto leave;
  memcpy (name, address, domain - address);
  p = stpcpy (name + (domain-address), ".");
  if (*kdns_at_repl)
    p = stpcpy (stpcpy (p, kdns_at_repl), ".");
  p = stpcpy (p, domain+1);
  if (*kdns_root)
    strcpy (stpcpy (p, "."), kdns_root);

  fprintf (output,"NAME %s BEGIN\n", address);
  if (opt->verbose > 2)
    fprintf(console, PGM": looking up `%s'\n", name);

  if ( adns_synchronous (adns_ctx, name, (adns_r_unknown | my_adns_r_cert),
                         adns_qf_quoteok_query|(kdns_usevc?adns_qf_usevc:0),
                         &answer) )
    {
      fprintf (console, PGM": DNS query failed: %s\n", strerror (errno));
      ret = KEYSERVER_KEY_NOT_FOUND;
      goto leave;
    }
  if (answer->status != adns_s_ok) 
    {
      fprintf (console, PGM": DNS query returned: %s (%s)\n", 
               adns_strerror (answer->status),
               adns_errabbrev (answer->status));
      ret = KEYSERVER_KEY_NOT_FOUND;
      goto leave;
    }
  datalen = answer->rrs.byteblock->len;
  data = answer->rrs.byteblock->data;

  if ( opt->debug > 1 )
    {
      int i;

      fprintf (console, "got %d  bytes of data:", datalen);
      for (i=0; i < datalen; i++)
        {
          if (!(i % 32))
            fprintf (console, "\n%08x  ", i);
          fprintf (console, "%02x", data[i]);
        }
      putc ('\n', console);
    }
  if ( datalen < 5 )
    {
      fprintf (console, PGM": error: truncated CERT record\n"); 
      ret = KEYSERVER_KEY_NOT_FOUND;
      goto leave;
    }

  switch ( ((data[0]<<8)|data[1]) )
    {
    case 3: /* CERT type is PGP.  */
      /* (key tag and algorithm fields are ignored for this CERT type). */
      data += 5;
      datalen -= 5;
      if ( datalen < 11 )
        {
          /* Gpg checks for a minium length of 11, thus we do the same.  */
          fprintf (console, PGM": error: OpenPGP data to short\n"); 
          ret = KEYSERVER_KEY_NOT_FOUND;
          goto leave;
        }
      if (b64enc_start (&b64state, output, "PGP PUBLIC KEY BLOCK")
          || b64enc_write (&b64state, data, datalen)
          || b64enc_finish (&b64state))
        goto leave; /* Oops, base64 encoder failed.  */
      break;

    default:
      fprintf (console, PGM": CERT type %d ignored\n", (data[0] <<8|data[1])); 
      ret = KEYSERVER_KEY_NOT_FOUND;
      goto leave;
    }
  
  ret = 0; /* All fine.  */

 leave:
  if (ret)
    fprintf (output, "\nNAME %s FAILED %d\n", address, ret);
  else
    fprintf (output, "\nNAME %s END\n", address);
  adns_free (answer); 
  xfree (name);
  return ret;
}


/* Print some help.  */
static void 
show_help (FILE *fp)
{
  fputs (PGM" (GnuPG) " VERSION"\n\n", fp);
  fputs (" -h\thelp\n"
         " -V\tversion\n"
         " -o\toutput to this file\n"
         "\n", fp);
  fputs ("This keyserver helper accepts URLs of the form:\n"
         "  kdns://[NAMESERVER]/[ROOT][?at=STRING]\n"
         "with\n"
         "  NAMESERVER  used for queries (default: system standard)\n"
         "  ROOT        a DNS name appended to the query (default: none)\n"
         "  STRING      a string to replace the '@' (default: \".\")\n"
         "If a long answer is expected add the parameter \"usevc=1\".\n"
         "\n", fp);
  fputs ("Example:  A query for \"hacker@gnupg.org\" with\n"
         "  kdns://10.0.0.1/example.net?at=_key&usevc=1\n"
         "setup as --auto-key-lookup does a CERT record query\n"
         "with type PGP on the nameserver 10.0.0.1 for\n"
         "  hacker._key_.gnupg.org.example.net\n"
         "\n", fp);
}


int
main (int argc, char *argv[])
{
  int arg;
  int ret = KEYSERVER_INTERNAL_ERROR;
  char line[MAX_LINE];
  struct keylist *keylist = NULL;
  struct keylist **keylist_tail = &keylist;
  struct keylist *akey;
  int failed = 0;
  adns_state adns_ctx = NULL;
  adns_initflags my_adns_initflags = MY_ADNS_INITFLAGS;
  int tmprc;

  /* The defaults for the KDNS name mangling.  */
  kdns_root = "";
  kdns_at_repl = "";

  console = stderr;

  /* Kludge to implement standard GNU options.  */
  if (argc > 1 && !strcmp (argv[1], "--version"))
    {
      fputs (PGM" (GnuPG) " VERSION"\n", stdout);
      return 0;
    }
  else if (argc > 1 && !strcmp (argv[1], "--help"))
    {
      show_help (stdout);
      return 0;
    }

  while ( (arg = getopt (argc, argv, "hVo:")) != -1 )
    {
      switch(arg)
        {
        case 'V':
          printf ("%d\n%s\n", KEYSERVER_PROTO_VERSION, VERSION);
          return KEYSERVER_OK;

        case 'o':
          output = fopen (optarg,"w");
          if (!output)
            {
              fprintf (console, PGM": cannot open output file `%s': %s\n",
                       optarg, strerror(errno) );
              return KEYSERVER_INTERNAL_ERROR;
            }
          break;

        case 'h':
        default:
          show_help (console);
          return KEYSERVER_OK;
        }
    }

  if (argc > optind)
    {
      input = fopen (argv[optind], "r");
      if (!input)
	{
	  fprintf (console, PGM": cannot open input file `%s': %s\n",
                   argv[optind], strerror(errno) );
	  return KEYSERVER_INTERNAL_ERROR;
	}
    }

  if (!input)
    input = stdin;

  if (!output)
    output = stdout;
  
  opt = init_ks_options();
  if(!opt)
    return KEYSERVER_NO_MEMORY;

  /* Get the command and info block */
  while ( fgets(line,MAX_LINE,input) )
    {
      int err;
      
      if(line[0]=='\n')
	break;
      
      err = parse_ks_options (line, opt);
      if (err > 0)
	{
	  ret = err;
	  goto leave;
	}
      else if (!err)
	continue;
    }

  if (opt->timeout && register_timeout() == -1 )
    {
      fprintf (console, PGM": unable to register timeout handler\n");
      return KEYSERVER_INTERNAL_ERROR;
    }

  if (opt->verbose)
    {
      fprintf (console, PGM": HOST=%s\n", opt->host? opt->host:"(none)");
      fprintf (console, PGM": PATH=%s\n", opt->path? opt->path:"(none)");
    }
  if (opt->path && *opt->path == '/')
    {
      char *p, *pend;

      kdns_root = opt->path+1;
      p = strchr (opt->path+1, '?');
      if (p)
        {
          *p++ = 0;
          do 
            {
              pend = strchr (p, '&');
              if (pend)
                *pend++ = 0;
              if (!strncmp (p, "at=", 3))
                kdns_at_repl = p+3;
              else if (!strncmp (p, "usevc=", 6))
                kdns_usevc = !!atoi (p+6);
            }
          while ((p = pend));
        }
    }
  if (strchr (kdns_root, '/'))
    {
      fprintf (console, PGM": invalid character in KDNS root\n");
      return KEYSERVER_GENERAL_ERROR;
    }
  if (!strcmp (kdns_at_repl, "."))
    kdns_at_repl = "";

  if (opt->verbose)
    {
      fprintf (console, PGM": kdns_root=%s\n", kdns_root);
      fprintf (console, PGM": kdns_at=%s\n", kdns_at_repl);
      fprintf (console, PGM": kdns_usevc=%d\n", kdns_usevc);
    }

  if (opt->debug)
    my_adns_initflags |= adns_if_debug;
  if (opt->host)
    {
      char cfgtext[200];

      snprintf (cfgtext, sizeof cfgtext, "nameserver %s\n", opt->host);
      tmprc = adns_init_strcfg (&adns_ctx, my_adns_initflags, console,cfgtext);
    }
  else
    tmprc = adns_init (&adns_ctx, my_adns_initflags, console);
  if (tmprc)
    {
      fprintf (console, PGM": error initializing ADNS: %s\n",
               strerror (errno));
      goto leave;
    }
  
  if (opt->action == KS_GETNAME)
    {
      while ( fgets (line,MAX_LINE,input) )
        {
          if (line[0]=='\n' || !line[0] )
            break;
          line[strlen(line)-1] = 0;  /* Trim the trailing LF. */
          
          akey = xtrymalloc (sizeof *akey);
          if (!akey)
            {
              fprintf (console, 
                       PGM": out of memory while building key list\n");
              ret = KEYSERVER_NO_MEMORY;
              goto leave;
            }
          assert (sizeof (akey->str) > strlen(line));
          strcpy (akey->str, line);
          akey->next = NULL;
          *keylist_tail = akey;
          keylist_tail = &akey->next;
	}
    }
  else
    {
      fprintf (console,
               PGM": this keyserver type only supports "
               "key retrieval by name\n");
      goto leave;
    }
  
  /* Send the response */
  fprintf (output, "VERSION %d\n", KEYSERVER_PROTO_VERSION);
  fprintf (output, "PROGRAM %s\n\n", VERSION);

  if (opt->verbose > 1)
    {
      if (opt->opaque)
        fprintf (console, "User:\t\t%s\n", opt->opaque);
      fprintf (console, "Command:\tGET\n");
    }
  
  for (akey = keylist; akey; akey = akey->next)
    {
      set_timeout (opt->timeout);
      if ( get_key (adns_ctx, akey->str) )
        failed++;
    }      
  if (!failed)
    ret = KEYSERVER_OK;


 leave:
  if (adns_ctx)
    adns_finish (adns_ctx);
  while (keylist)
    {
      akey = keylist->next;
      xfree (keylist);
      keylist = akey;
    }
  if (input != stdin)
    fclose (input);
  if (output != stdout)
    fclose (output);
  kdns_root = "";
  kdns_at_repl = ".";
  free_ks_options (opt);
  return ret;
}
