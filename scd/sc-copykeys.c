/* sc-copykeys.c - A tool to store keys on a smartcard.
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define JNLIB_NEED_LOG_LOGV
#include "scdaemon.h"
#include <gcrypt.h>

#include "../common/ttyio.h"
#include "../common/simple-pwquery.h"
#include "iso7816.h"
#include "apdu.h" /* for open_reader */
#include "atr.h"
#include "app-common.h"

#define _(a) (a)


enum cmd_and_opt_values 
{ oVerbose	  = 'v',
  oReaderPort     = 500,
  octapiDriver,
  oDebug,
  oDebugAll,

aTest };


static ARGPARSE_OPTS opts[] = {
  
  { 301, NULL, 0, "@Options:\n " },

  { oVerbose, "verbose",   0, "verbose" },
  { oReaderPort, "reader-port", 2, "|N|connect to reader at port N"},
  { octapiDriver, "ctapi-driver", 2, "NAME|use NAME as ctAPI driver"},
  { oDebug,	"debug"     ,4|16, "set debugging flags"},
  { oDebugAll, "debug-all" ,0, "enable full debugging"},
  {0}
};


static void copykeys (APP app, const char *fname);


static const char *
my_strusage (int level)
{
  const char *p;
  switch (level)
    {
    case 11: p = "sc-copykeys (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p =  _("Usage: sc-copykeys [options] (-h for help)\n");
      break;
    case 41: p = _("Syntax: sc-copykeys [options] "
                   "file-with-key\n"
                    "Copy keys to a smartcards\n");
    break;
    
    default: p = NULL;
    }
  return p;
}


int
main (int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int slot, rc;
  const char *reader_port = NULL;
  struct app_ctx_s appbuf;

  memset (&appbuf, 0, sizeof appbuf);

  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  log_set_prefix ("sc-copykeys", 1); 

  /* check that the libraries are suitable.  Do it here because
     the option parsing may need services of the library */
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal (_("%s is too old (need %s, have %s)\n"), "libgcrypt",
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }

  setup_libgcrypt_logging ();
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0); /* FIXME - we want to use it */
  /* FIXME? gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);*/

  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* do not remove the args */
  while (arg_parse (&pargs, opts) )
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt.verbose++; break;
        case oDebug: opt.debug |= pargs.r.ret_ulong; break;
        case oDebugAll: opt.debug = ~0; break;
        case oReaderPort: reader_port = pargs.r.ret_str; break;
        case octapiDriver: opt.ctapi_driver = pargs.r.ret_str; break;
        default : pargs.err = 2; break;
	}
    }
  if (log_get_errorcount(0))
    exit(2);

  if (argc != 1)
    usage (1);

  slot = apdu_open_reader (reader_port);
  if (slot == -1)
    exit (1);
  if (apdu_connect (slot))
    exit (1);

  /* FIXME: Use select_application. */
  appbuf.slot = slot;
  rc = app_select_openpgp (&appbuf);
  if (rc)
    {
      log_error ("selecting openpgp failed: %s\n", gpg_strerror (rc));
      exit (1);
    }
  appbuf.initialized = 1;
  log_info ("openpgp application selected\n");

  copykeys (&appbuf, *argv);


  return 0;
}



void
send_status_info (CTRL ctrl, const char *keyword, ...)
{
  /* DUMMY */
}



static char *
read_file (const char *fname, size_t *r_length)
{
  FILE *fp;
  struct stat st;
  char *buf;
  size_t buflen;
  
  fp = fname? fopen (fname, "rb") : stdin;
  if (!fp)
    {
      log_error ("can't open `%s': %s\n",
                 fname? fname: "[stdin]", strerror (errno));
      return NULL;
    }
  
  if (fstat (fileno(fp), &st))
    {
      log_error ("can't stat `%s': %s\n", 
                 fname? fname: "[stdin]", strerror (errno));
      if (fname)
        fclose (fp);
      return NULL;
    }

  buflen = st.st_size;
  buf = xmalloc (buflen+1);
  if (fread (buf, buflen, 1, fp) != 1)
    {
      log_error ("error reading `%s': %s\n", 
                 fname? fname: "[stdin]", strerror (errno));
      if (fname)
        fclose (fp);
      xfree (buf);
      return NULL;
    }
  if (fname)
    fclose (fp);

  *r_length = buflen;
  return buf;
}


static gcry_sexp_t
read_key (const char *fname)
{
  char *buf;
  size_t buflen;
  gcry_sexp_t private;
  int rc;
  
  buf = read_file (fname, &buflen);
  if (!buf)
    return NULL;

  rc = gcry_sexp_new (&private, buf, buflen, 1);
  if (rc)
    {
      log_error ("gcry_sexp_new failed: %s\n", gpg_strerror (rc));
      return NULL;
    } 
  xfree (buf);

  return private;
}



static gcry_mpi_t *
sexp_to_kparms (gcry_sexp_t sexp, unsigned long *created)
{
  gcry_sexp_t list, l2;
  const char *name;
  const char *s;
  size_t n;
  int i, idx;
  const char *elems;
  gcry_mpi_t *array;

  *created = 0;
  list = gcry_sexp_find_token (sexp, "private-key", 0 );
  if(!list)
    return NULL; 

  /* quick hack to get the creation time. */
  l2 = gcry_sexp_find_token (list, "created", 0);
  if (l2 && (name = gcry_sexp_nth_data (l2, 1, &n)))
    {
      char *tmp = xmalloc (n+1);
      memcpy (tmp, name, n);
      tmp[n] = 0;
      *created = strtoul (tmp, NULL, 10);
      xfree (tmp);
    }
  gcry_sexp_release (l2);
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  name = gcry_sexp_nth_data (list, 0, &n);
  if(!name || n != 3 || memcmp (name, "rsa", 3))
    {
      gcry_sexp_release (list);
      return NULL;
    }

  /* Parameter names used with RSA. */
  elems = "nedpqu";
  array = xcalloc (strlen(elems) + 1, sizeof *array);
  for (idx=0, s=elems; *s; s++, idx++ ) 
    {
      l2 = gcry_sexp_find_token (list, s, 1);
      if (!l2)
        {
          for (i=0; i<idx; i++)
            gcry_mpi_release (array[i]);
          xfree (array);
          gcry_sexp_release (list);
          return NULL; /* required parameter not found */
	}
      array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release (l2);
      if (!array[idx])
        {
          for (i=0; i<idx; i++)
            gcry_mpi_release (array[i]);
          xfree (array);
          gcry_sexp_release (list);
          return NULL; /* required parameter is invalid */
	}
    }
  
  gcry_sexp_release (list);
  return array;
}


/* Return true if the SHA1 fingerprint FPR consists only of zeroes. */
static int
fpr_is_zero (const char *fpr)
{
  int i;

  for (i=0; i < 20 && !fpr[i]; i++)
    ;
  return (i == 20);
}


static void
show_sha1_fpr (const unsigned char *fpr)
{
  int i;

  if (fpr)
    {
      for (i=0; i < 20 ; i+=2, fpr += 2 )
        {
          if (i == 10 )
            tty_printf (" ");
          tty_printf (" %02X%02X", *fpr, fpr[1]);
        }
    }
  else
    tty_printf (" [none]");
  tty_printf ("\n");
}

/* Query the card, show a list of already stored keys and ask the user
   where to store the key.  Returns the key number or 0 for cancel
   operation. */
static int
query_card (APP app)
{
  int keyno = 0;
  char *serialno, *disp_name, *pubkey_url;
  unsigned char *fpr1, *fpr2, *fpr3;


  if (app_openpgp_cardinfo (app,
                            &serialno,
                            &disp_name,
                            &pubkey_url,
                            &fpr1, &fpr2, &fpr3))
    return 0;


  for (;;)
    {
      char *answer;

      tty_printf ("\n");

      tty_printf ("Serial number ....: %s\n",
                  serialno? serialno : "[none]");
      tty_printf ("Name of cardholder: %s\n",
                  disp_name && *disp_name? disp_name : "[not set]");
      tty_printf ("URL of public key : %s\n",
                  pubkey_url && *pubkey_url? pubkey_url : "[not set]");
      tty_printf ("Signature key ....:");
      show_sha1_fpr (fpr1);
      tty_printf ("Encryption key....:");
      show_sha1_fpr (fpr2);
      tty_printf ("Authentication key:");
      show_sha1_fpr (fpr3);

      tty_printf ("\n"
                  "1 - store as signature key and reset usage counter\n"
                  "2 - store as encryption key\n"
                  "3 - store as authentication key\n"
                  "Q - quit\n"
                  "\n");

      answer = tty_get("Your selection? ");
      tty_kill_prompt();
      if (strlen (answer) != 1)
        ;
      else if ( *answer == '1' )
        {
          if ( (fpr1 && !fpr_is_zero (fpr1)) )
            {
              tty_printf ("\n");
              log_error ("WARNING: signature key does already exists!\n");
              tty_printf ("\n");
              if ( tty_get_answer_is_yes ("Replace existing key? ") )
                {
                  keyno = 1;
                  break;
                }
            }
          else
            {
              keyno = 1;
              break;
            }
        }
      else if ( *answer == '2' )
        {
          if ( (fpr2 && !fpr_is_zero (fpr2)) )
            {
              tty_printf ("\n");
              log_error ("WARNING: encryption key does already exists!\n");
              tty_printf ("\n");
              if ( tty_get_answer_is_yes ("Replace existing key? ") )
                {
                  keyno = 2;
                  break;
                }
            }
          else
            {
              keyno = 2;
              break;
            }
        }
      else if ( *answer == '3' )
        {
          if ( (fpr3 && !fpr_is_zero (fpr3)) )
            {
              tty_printf ("\n");
              log_error ("WARNING: authentication key does already exists!\n");
              tty_printf ("\n");
              if ( tty_get_answer_is_yes ("Replace existing key? ") )
                {
                  keyno = 3;
                  break;
                }
            }
          else
            {
              keyno = 3;
              break;
            }
        }
      else if ( *answer == 'q' || *answer == 'Q')
        {
          keyno = 0;
          break;
        }
    }

  xfree (serialno); 
  xfree (disp_name); 
  xfree (pubkey_url);
  xfree (fpr1);
  xfree (fpr2);
  xfree (fpr3);

  return keyno;
}


/* Callback function to ask for a PIN. */
static gpg_error_t
pincb (void *arg, const char *prompt, char **pinvalue)
{
  char *pin = xstrdup ("12345678");

/*    pin = simple_pwquery (NULL, NULL, prompt, */
/*                          "We need the admin's PIN to store the key on the card", */
/*                          0, NULL); */
/*    if (!pin) */
/*      return gpg_error (GPG_ERR_CANCELED); */



  *pinvalue = pin;
  return 0;
}


/* This function expects a file (or NULL for stdin) with the secret
   and public key parameters.  This file should consist of an
   S-expression as used by gpg-agent. Only the unprotected format is
   supported.  Example:

   (private-key
    (rsa
     (n #00e0ce9..[some bytes not shown]..51#)
     (e #010001#)
     (d #046129F..[some bytes not shown]..81#)
     (p #00e861b..[some bytes not shown]..f1#)
     (q #00f7a7c..[some bytes not shown]..61#)
     (u #304559a..[some bytes not shown]..9b#))
    (uri http://foo.bar x-foo:whatever_you_want))
   
*/
static void
copykeys (APP app, const char *fname)
{
  int rc;
  gcry_sexp_t private;
  gcry_mpi_t *mpis, rsa_n, rsa_e, rsa_p, rsa_q;
  unsigned int nbits;
  size_t n;
  unsigned char *template, *tp;
  unsigned char m[128], e[4];
  size_t mlen, elen;
  unsigned long creation_date;
  time_t created_at;
  int keyno;

  if (!strcmp (fname, "-"))
    fname = NULL;

  private = read_key (fname);
  if (!private)
    exit (1);
  
  mpis = sexp_to_kparms (private, &creation_date);
  if (!creation_date)
    {
      log_info ("no creation date found - assuming current date\n");
      created_at = time (NULL);
    }
  else
    created_at = creation_date;
  gcry_sexp_release (private);
  if (!mpis)
    {
      log_error ("invalid structure of key file or not RSA\n");
      exit (1);
    }
  /* MPIS is now an array with the key parameters as defined by OpenPGP. */
  rsa_n = mpis[0];
  rsa_e = mpis[1];
  gcry_mpi_release (mpis[2]);
  rsa_p = mpis[3];
  rsa_q = mpis[4];
  gcry_mpi_release (mpis[5]);
  xfree (mpis);

  nbits = gcry_mpi_get_nbits (rsa_e);
  if (nbits < 2 || nbits > 32)
    {
      log_error ("public exponent too large (more than 32 bits)\n");
      goto failure;
    }
  nbits = gcry_mpi_get_nbits (rsa_p);
  if (nbits != 512)
    {
      log_error ("length of first RSA prime is not 512\n");
      goto failure;
    }
  nbits = gcry_mpi_get_nbits (rsa_q);
  if (nbits != 512)
    {
      log_error ("length of second RSA prime is not 512\n");
      goto failure;
    }

  nbits = gcry_mpi_get_nbits (rsa_n);
  if (nbits != 1024)
    {
      log_error ("length of RSA modulus is not 1024\n");
      goto failure;
    }

  keyno = query_card (app);
  if (!keyno)
    goto failure;

  /* Build the private key template as described in section 4.3.3.6 of
     the specs.
                   0xC0   <length> public exponent
                   0xC1   <length> prime p 
                   0xC2   <length> prime q  */
  template = tp = xmalloc (1+2 + 1+1+4 + 1+1+64 + 1+1+64);
  *tp++ = 0xC0;
  *tp++ = 4;
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, tp, 4, &n, rsa_e);
  if (rc)
    {
      log_error ("mpi_print failed: %s\n", gpg_strerror (rc));
      goto failure;
    }
  assert (n <= 4);
  memcpy (e, tp, n);
  elen = n;
  if (n != 4)
    {
      memmove (tp+4-n, tp, 4-n);
      memset (tp, 0, 4-n);
    }                 
  tp += 4;

  *tp++ = 0xC1;
  *tp++ = 64;
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, tp, 64, &n, rsa_p);
  if (rc)
    {
      log_error ("mpi_print failed: %s\n", gpg_strerror (rc));
      goto failure;
    }
  assert (n == 64);
  tp += 64;

  *tp++ = 0xC2;
  *tp++ = 64;
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, tp, 64, &n, rsa_q);
  if (rc)
    {
      log_error ("mpi_print failed: %s\n", gpg_strerror (rc));
      goto failure;
    }
  assert (n == 64);
  tp += 64;
  assert (tp - template == 138);

  /* (we need the modulus to calculate the fingerprint) */
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, m, 128, &n, rsa_n);
  if (rc)
    {
      log_error ("mpi_print failed: %s\n", gpg_strerror (rc));
      goto failure;
    }
  assert (n == 128);
  mlen = 128;


  rc = app_openpgp_storekey (app, keyno,
                             template, tp - template,
                             created_at,
                             m, mlen,
                             e, elen,
                             pincb, NULL);

  if (rc)
    {
      log_error ("error storing key: %s\n", gpg_strerror (rc));
      goto failure;
    }
  log_info ("key successfully stored\n");
  {
    unsigned char *mm, *ee;
    size_t mmlen, eelen;
    int i;

    rc = app_openpgp_readkey (app, keyno, &mm, &mmlen, &ee, &eelen);
    if (rc)
      {
        log_error ("error reading key back: %s\n", gpg_strerror (rc));
        goto failure;
      }

    /* Strip leading zeroes. */
    for (i=0; i < mmlen && !mm[i]; i++)
      ;
    mmlen -= i;
    memmove (mm, mm+i, mmlen);
    for (i=0; i < eelen && !ee[i]; i++)
      ;
    eelen -= i;
    memmove (ee, ee+i, eelen);

    if (eelen != elen || mmlen != mlen)
      {
        log_error ("key parameter length mismatch (n=%u/%u, e=%u/%u)\n",
                   (unsigned int)mlen, (unsigned int)mmlen,
                   (unsigned int)elen, (unsigned int)eelen);
        xfree (mm);
        xfree (ee);
        goto failure;
      }

    if (memcmp (m, mm, mlen))
      {
        log_error ("key parameter n mismatch\n");
        log_printhex ("original n: ", m, mlen);
        log_printhex ("  copied n: ", mm, mlen);
        xfree (mm);
        xfree (ee);
        goto failure;
      }
    if (memcmp (e, ee, elen))
      {
        log_error ("key parameter e mismatch\n");
        log_printhex ("original e: ", e, elen);
        log_printhex ("  copied e: ", ee, elen);
        xfree (mm);
        xfree (ee);
        goto failure;
      }
    xfree (mm);
    xfree (ee);
  }


  gcry_mpi_release (rsa_e);
  gcry_mpi_release (rsa_p);
  gcry_mpi_release (rsa_q);
  gcry_mpi_release (rsa_n);
  return;

 failure:
  gcry_mpi_release (rsa_e);
  gcry_mpi_release (rsa_p);
  gcry_mpi_release (rsa_q);
  gcry_mpi_release (rsa_n);
  exit (1);
}


