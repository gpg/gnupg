/* protect-tool.c - A tool to test the secret key protection
 * Copyright (C) 2002, 2003, 2004, 2006 Free Software Foundation, Inc.
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
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif
#ifdef HAVE_DOSISH_SYSTEM
#include <fcntl.h> /* for setmode() */
#endif

#define JNLIB_NEED_LOG_LOGV
#include "agent.h"
#include "minip12.h"
#include "i18n.h"
#include "get-passphrase.h"
#include "sysutils.h"
#include "estream.h"


enum cmd_and_opt_values 
{ 
  aNull = 0,
  oVerbose	  = 'v',
  oArmor          = 'a',
  oPassphrase     = 'P',

  oProtect        = 'p',
  oUnprotect      = 'u',
  
  oNoVerbose = 500,
  oShadow,
  oShowShadowInfo,
  oShowKeygrip,
  oS2Kcalibration,
  oCanonical,

  oP12Import,
  oP12Export,
  oP12Charset,
  oStore,
  oForce,
  oHaveCert,
  oNoFailOnExist,
  oHomedir,
  oPrompt,
  oStatusMsg, 

  oAgentProgram
};


struct rsa_secret_key_s 
{
  gcry_mpi_t n;	    /* public modulus */
  gcry_mpi_t e;	    /* public exponent */
  gcry_mpi_t d;	    /* exponent */
  gcry_mpi_t p;	    /* prime  p. */
  gcry_mpi_t q;	    /* prime  q. */
  gcry_mpi_t u;	    /* inverse of p mod q. */
};


static const char *opt_homedir;
static int opt_armor;
static int opt_canonical;
static int opt_store;
static int opt_force;
static int opt_no_fail_on_exist;
static int opt_have_cert;
static const char *opt_passphrase;
static char *opt_prompt;
static int opt_status_msg;
static const char *opt_p12_charset;
static const char *opt_agent_program; 

static char *get_passphrase (int promptno);
static void release_passphrase (char *pw);
static int store_private_key (const unsigned char *grip,
                              const void *buffer, size_t length, int force);


static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (oProtect,   "protect",   "protect a private key"),
  ARGPARSE_c (oUnprotect, "unprotect", "unprotect a private key"),
  ARGPARSE_c (oShadow,    "shadow", "create a shadow entry for a public key"),
  ARGPARSE_c (oShowShadowInfo,  "show-shadow-info", "return the shadow info"),
  ARGPARSE_c (oShowKeygrip, "show-keygrip", "show the \"keygrip\""),
  ARGPARSE_c (oP12Import, "p12-import", 
              "import a pkcs#12 encoded private key"),
  ARGPARSE_c (oP12Export, "p12-export",
              "export a private key pkcs#12 encoded"),

  ARGPARSE_c (oS2Kcalibration, "s2k-calibration", "@"),
  
  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", "verbose"),
  ARGPARSE_s_n (oArmor, "armor", "write output in advanced format"),
  ARGPARSE_s_n (oCanonical, "canonical", "write output in canonical format"),

  ARGPARSE_s_s (oPassphrase, "passphrase", "|STRING|use passphrase STRING"),
  ARGPARSE_s_s (oP12Charset,"p12-charset",
                "|NAME|set charset for a new PKCS#12 passphrase to NAME"),
  ARGPARSE_s_n (oHaveCert, "have-cert",
                "certificate to export provided on STDIN"),
  ARGPARSE_s_n (oStore,    "store", 
                "store the created key in the appropriate place"),
  ARGPARSE_s_n (oForce,    "force", 
                "force overwriting"),
  ARGPARSE_s_n (oNoFailOnExist, "no-fail-on-exist", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@"), 
  ARGPARSE_s_s (oPrompt,  "prompt", 
                "|ESCSTRING|use ESCSTRING as prompt in pinentry"), 
  ARGPARSE_s_n (oStatusMsg, "enable-status-msg", "@"),

  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),

  ARGPARSE_end ()
};

static const char *
my_strusage (int level)
{
  const char *p;
  switch (level)
    {
    case 11: p = "gpg-protect-tool (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p =  _("Usage: gpg-protect-tool [options] (-h for help)\n");
      break;
    case 41: p =  _("Syntax: gpg-protect-tool [options] [args]\n"
                    "Secret key maintenance tool\n");
    break;
    
    default: p = NULL;
    }
  return p;
}


/*  static void */
/*  print_mpi (const char *text, gcry_mpi_t a) */
/*  { */
/*    char *buf; */
/*    void *bufaddr = &buf; */
/*    int rc; */

/*    rc = gcry_mpi_aprint (GCRYMPI_FMT_HEX, bufaddr, NULL, a); */
/*    if (rc) */
/*      log_info ("%s: [error printing number: %s]\n", text, gpg_strerror (rc)); */
/*    else */
/*      { */
/*        log_info ("%s: %s\n", text, buf); */
/*        gcry_free (buf); */
/*      } */
/*  } */



static unsigned char *
make_canonical (const char *fname, const char *buf, size_t buflen)
{
  int rc;
  size_t erroff, len;
  gcry_sexp_t sexp;
  unsigned char *result;

  rc = gcry_sexp_sscan (&sexp, &erroff, buf, buflen);
  if (rc)
    {
      log_error ("invalid S-Expression in `%s' (off=%u): %s\n",
                 fname, (unsigned int)erroff, gpg_strerror (rc));
      return NULL;
    }
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  result = xmalloc (len);
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, result, len);
  assert (len);
  gcry_sexp_release (sexp);
  return result;
}

static char *
make_advanced (const unsigned char *buf, size_t buflen)
{
  int rc;
  size_t erroff, len;
  gcry_sexp_t sexp;
  char *result;

  rc = gcry_sexp_sscan (&sexp, &erroff, (const char*)buf, buflen);
  if (rc)
    {
      log_error ("invalid canonical S-Expression (off=%u): %s\n",
                 (unsigned int)erroff, gpg_strerror (rc));
      return NULL;
    }
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  assert (len);
  result = xmalloc (len);
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, result, len);
  assert (len);
  gcry_sexp_release (sexp);
  return result;
}


static char *
read_file (const char *fname, size_t *r_length)
{
  FILE *fp;
  char *buf;
  size_t buflen;
  
  if (!strcmp (fname, "-"))
    {
      size_t nread, bufsize = 0;

      fp = stdin;
#ifdef HAVE_DOSISH_SYSTEM
      setmode ( fileno(fp) , O_BINARY );
#endif
      buf = NULL;
      buflen = 0;
#define NCHUNK 8192
      do 
        {
          bufsize += NCHUNK;
          if (!buf)
            buf = xmalloc (bufsize);
          else
            buf = xrealloc (buf, bufsize);

          nread = fread (buf+buflen, 1, NCHUNK, fp);
          if (nread < NCHUNK && ferror (fp))
            {
              log_error ("error reading `[stdin]': %s\n", strerror (errno));
              xfree (buf);
              return NULL;
            }
          buflen += nread;
        }
      while (nread == NCHUNK);
#undef NCHUNK

    }
  else
    {
      struct stat st;

      fp = fopen (fname, "rb");
      if (!fp)
        {
          log_error ("can't open `%s': %s\n", fname, strerror (errno));
          return NULL;
        }
  
      if (fstat (fileno(fp), &st))
        {
          log_error ("can't stat `%s': %s\n", fname, strerror (errno));
          fclose (fp);
          return NULL;
        }
      
      buflen = st.st_size;
      buf = xmalloc (buflen+1);
      if (fread (buf, buflen, 1, fp) != 1)
        {
          log_error ("error reading `%s': %s\n", fname, strerror (errno));
          fclose (fp);
          xfree (buf);
          return NULL;
        }
      fclose (fp);
    }

  *r_length = buflen;
  return buf;
}


static unsigned char *
read_key (const char *fname)
{
  char *buf;
  size_t buflen;
  unsigned char *key;
  
  buf = read_file (fname, &buflen);
  if (!buf)
    return NULL;
  key = make_canonical (fname, buf, buflen);
  xfree (buf);
  return key;
}



static void
read_and_protect (const char *fname)
{
  int  rc;
  unsigned char *key;
  unsigned char *result;
  size_t resultlen;
  char *pw;
  
  key = read_key (fname);
  if (!key)
    return;

  pw = get_passphrase (1);
  rc = agent_protect (key, pw, &result, &resultlen);
  release_passphrase (pw);
  xfree (key);
  if (rc)
    {
      log_error ("protecting the key failed: %s\n", gpg_strerror (rc));
      return;
    }
  
  if (opt_armor)
    {
      char *p = make_advanced (result, resultlen);
      xfree (result);
      if (!p)
        return;
      result = (unsigned char*)p;
      resultlen = strlen (p);
    }

  fwrite (result, resultlen, 1, stdout);
  xfree (result);
}


static void
read_and_unprotect (const char *fname)
{
  int  rc;
  unsigned char *key;
  unsigned char *result;
  size_t resultlen;
  char *pw;
  gnupg_isotime_t protected_at;

  key = read_key (fname);
  if (!key)
    return;

  rc = agent_unprotect (key, (pw=get_passphrase (1)), 
                        protected_at, &result, &resultlen);
  release_passphrase (pw);
  xfree (key);
  if (rc)
    {
      if (opt_status_msg)
        log_info ("[PROTECT-TOOL:] bad-passphrase\n");
      log_error ("unprotecting the key failed: %s\n", gpg_strerror (rc));
      return;
    }
  if (opt.verbose)
    log_info ("key protection done at %.4s-%.2s-%.2s %.2s:%.2s:%s\n",
              protected_at, protected_at+4, protected_at+6,
              protected_at+9, protected_at+11, protected_at+13);


  if (opt_armor)
    {
      char *p = make_advanced (result, resultlen);
      xfree (result);
      if (!p)
        return;
      result = (unsigned char*)p;
      resultlen = strlen (p);
    }

  fwrite (result, resultlen, 1, stdout);
  xfree (result);
}



static void
read_and_shadow (const char *fname)
{
  int  rc;
  unsigned char *key;
  unsigned char *result;
  size_t resultlen;
  unsigned char dummy_info[] = "(8:313233342:43)";
  
  key = read_key (fname);
  if (!key)
    return;

  rc = agent_shadow_key (key, dummy_info, &result);
  xfree (key);
  if (rc)
    {
      log_error ("shadowing the key failed: %s\n", gpg_strerror (rc));
      return;
    }
  resultlen = gcry_sexp_canon_len (result, 0, NULL,NULL);
  assert (resultlen);
  
  if (opt_armor)
    {
      char *p = make_advanced (result, resultlen);
      xfree (result);
      if (!p)
        return;
      result = (unsigned char*)p;
      resultlen = strlen (p);
    }

  fwrite (result, resultlen, 1, stdout);
  xfree (result);
}

static void
show_shadow_info (const char *fname)
{
  int  rc;
  unsigned char *key;
  const unsigned char *info;
  size_t infolen;
  
  key = read_key (fname);
  if (!key)
    return;

  rc = agent_get_shadow_info (key, &info);
  xfree (key);
  if (rc)
    {
      log_error ("get_shadow_info failed: %s\n", gpg_strerror (rc));
      return;
    }
  infolen = gcry_sexp_canon_len (info, 0, NULL,NULL);
  assert (infolen);
  
  if (opt_armor)
    {
      char *p = make_advanced (info, infolen);
      if (!p)
        return;
      fwrite (p, strlen (p), 1, stdout);
      xfree (p);
    }
  else
    fwrite (info, infolen, 1, stdout);
}


static void
show_file (const char *fname)
{
  unsigned char *key;
  size_t keylen;
  char *p;
  
  key = read_key (fname);
  if (!key)
    return;

  keylen = gcry_sexp_canon_len (key, 0, NULL,NULL);
  assert (keylen);
  
  if (opt_canonical)
    {
      fwrite (key, keylen, 1, stdout);
    }
  else
    {
      p = make_advanced (key, keylen);
      if (p)
        {
          fwrite (p, strlen (p), 1, stdout);
          xfree (p);
        }
    }
  xfree (key);
}

static void
show_keygrip (const char *fname)
{
  unsigned char *key;
  gcry_sexp_t private;
  unsigned char grip[20];
  int i;
  
  key = read_key (fname);
  if (!key)
    return;

  if (gcry_sexp_new (&private, key, 0, 0))
    {
      log_error ("gcry_sexp_new failed\n");
      return;
    } 
  xfree (key);

  if (!gcry_pk_get_keygrip (private, grip))
    {
      log_error ("can't calculate keygrip\n");
      return;
    }
  gcry_sexp_release (private);

  for (i=0; i < 20; i++)
    printf ("%02X", grip[i]);
  putchar ('\n');
}


static int
rsa_key_check (struct rsa_secret_key_s *skey)
{
  int err = 0;
  gcry_mpi_t t = gcry_mpi_snew (0);
  gcry_mpi_t t1 = gcry_mpi_snew (0);
  gcry_mpi_t t2 = gcry_mpi_snew (0);
  gcry_mpi_t phi = gcry_mpi_snew (0);

  /* check that n == p * q */
  gcry_mpi_mul (t, skey->p, skey->q);
  if (gcry_mpi_cmp( t, skey->n) )
    {
      log_error ("RSA oops: n != p * q\n");
      err++;
    }

  /* check that p is less than q */
  if (gcry_mpi_cmp (skey->p, skey->q) > 0)
    {
      gcry_mpi_t tmp;

      log_info ("swapping secret primes\n");
      tmp = gcry_mpi_copy (skey->p);
      gcry_mpi_set (skey->p, skey->q);
      gcry_mpi_set (skey->q, tmp);
      gcry_mpi_release (tmp);
      /* and must recompute u of course */
      gcry_mpi_invm (skey->u, skey->p, skey->q);
    }

  /* check that e divides neither p-1 nor q-1 */
  gcry_mpi_sub_ui (t, skey->p, 1 );
  gcry_mpi_div (NULL, t, t, skey->e, 0);
  if (!gcry_mpi_cmp_ui( t, 0) )
    {
      log_error ("RSA oops: e divides p-1\n");
      err++;
    }
  gcry_mpi_sub_ui (t, skey->q, 1);
  gcry_mpi_div (NULL, t, t, skey->e, 0);
  if (!gcry_mpi_cmp_ui( t, 0))
    {
      log_info ( "RSA oops: e divides q-1\n" );
      err++;
    }

  /* check that d is correct. */
  gcry_mpi_sub_ui (t1, skey->p, 1);
  gcry_mpi_sub_ui (t2, skey->q, 1);
  gcry_mpi_mul (phi, t1, t2);
  gcry_mpi_invm (t, skey->e, phi);
  if (gcry_mpi_cmp (t, skey->d))
    { /* no: try universal exponent. */
      gcry_mpi_gcd (t, t1, t2);
      gcry_mpi_div (t, NULL, phi, t, 0);
      gcry_mpi_invm (t, skey->e, t);
      if (gcry_mpi_cmp (t, skey->d))
        {
          log_error ("RSA oops: bad secret exponent\n");
          err++;
        }
    }

  /* check for correctness of u */
  gcry_mpi_invm (t, skey->p, skey->q);
  if (gcry_mpi_cmp (t, skey->u))
    {
      log_info ( "RSA oops: bad u parameter\n");
      err++;
    }

  if (err)
    log_info ("RSA secret key check failed\n");

  gcry_mpi_release (t);
  gcry_mpi_release (t1);
  gcry_mpi_release (t2);
  gcry_mpi_release (phi);

  return err? -1:0;
}


/* A callback used by p12_parse to return a certificate.  */
static void
import_p12_cert_cb (void *opaque, const unsigned char *cert, size_t certlen)
{
  struct b64state state;
  gpg_error_t err, err2;

  (void)opaque;

  err = b64enc_start (&state, stdout, "CERTIFICATE");
  if (!err)
    err = b64enc_write (&state, cert, certlen);
  err2 = b64enc_finish (&state);
  if (!err)
    err = err2;
  if (err)
    log_error ("error writing armored certificate: %s\n", gpg_strerror (err));
}

static void
import_p12_file (const char *fname)
{
  char *buf;
  unsigned char *result;
  size_t buflen, resultlen, buf_off;
  int i;
  int rc;
  gcry_mpi_t *kparms;
  struct rsa_secret_key_s sk;
  gcry_sexp_t s_key;
  unsigned char *key;
  unsigned char grip[20];
  char *pw;

  /* fixme: we should release some stuff on error */
  
  buf = read_file (fname, &buflen);
  if (!buf)
    return;

  /* GnuPG 2.0.4 accidently created binary P12 files with the string
     "The passphrase is %s encoded.\n\n" prepended to the ASN.1 data.
     We fix that here.  */
  if (buflen > 29 && !memcmp (buf, "The passphrase is ", 18))
    {
      for (buf_off=18; buf_off < buflen && buf[buf_off] != '\n'; buf_off++)
        ;
      buf_off++;
      if (buf_off < buflen && buf[buf_off] == '\n')
        buf_off++;
    }
  else
    buf_off = 0;

  kparms = p12_parse ((unsigned char*)buf+buf_off, buflen-buf_off,
                      (pw=get_passphrase (2)),
                      import_p12_cert_cb, NULL);
  release_passphrase (pw);
  xfree (buf);
  if (!kparms)
    {
      log_error ("error parsing or decrypting the PKCS-12 file\n");
      return;
    }
  for (i=0; kparms[i]; i++)
    ;
  if (i != 8)
    {
      log_error ("invalid structure of private key\n");
      return;
    }


/*    print_mpi ("   n", kparms[0]); */
/*    print_mpi ("   e", kparms[1]); */
/*    print_mpi ("   d", kparms[2]); */
/*    print_mpi ("   p", kparms[3]); */
/*    print_mpi ("   q", kparms[4]); */
/*    print_mpi ("dmp1", kparms[5]); */
/*    print_mpi ("dmq1", kparms[6]); */
/*    print_mpi ("   u", kparms[7]); */

  sk.n = kparms[0];
  sk.e = kparms[1];
  sk.d = kparms[2];
  sk.q = kparms[3];
  sk.p = kparms[4];
  sk.u = kparms[7];
  if (rsa_key_check (&sk))
    return;
/*    print_mpi ("   n", sk.n); */
/*    print_mpi ("   e", sk.e); */
/*    print_mpi ("   d", sk.d); */
/*    print_mpi ("   p", sk.p); */
/*    print_mpi ("   q", sk.q); */
/*    print_mpi ("   u", sk.u); */

  /* Create an S-expresion from the parameters. */
  rc = gcry_sexp_build (&s_key, NULL,
                        "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
                        sk.n, sk.e, sk.d, sk.p, sk.q, sk.u, NULL);
  for (i=0; i < 8; i++)
    gcry_mpi_release (kparms[i]);
  gcry_free (kparms);
  if (rc)
    {
      log_error ("failed to created S-expression from key: %s\n",
                 gpg_strerror (rc));
      return;
    }

  /* Compute the keygrip. */
  if (!gcry_pk_get_keygrip (s_key, grip))
    {
      log_error ("can't calculate keygrip\n");
      return;
    }
  log_info ("keygrip: ");
  for (i=0; i < 20; i++)
    log_printf ("%02X", grip[i]);
  log_printf ("\n");

  /* Convert to canonical encoding. */
  buflen = gcry_sexp_sprint (s_key, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (buflen);
  key = gcry_xmalloc_secure (buflen);
  buflen = gcry_sexp_sprint (s_key, GCRYSEXP_FMT_CANON, key, buflen);
  assert (buflen);
  gcry_sexp_release (s_key);

  pw = get_passphrase (4);
  rc = agent_protect (key, pw, &result, &resultlen);
  release_passphrase (pw);
  xfree (key);
  if (rc)
    {
      log_error ("protecting the key failed: %s\n", gpg_strerror (rc));
      return;
    }
  
  if (opt_armor)
    {
      char *p = make_advanced (result, resultlen);
      xfree (result);
      if (!p)
        return;
      result = (unsigned char*)p;
      resultlen = strlen (p);
    }

  if (opt_store)
    store_private_key (grip, result, resultlen, opt_force);
  else
    fwrite (result, resultlen, 1, stdout);

  xfree (result);
}



static gcry_mpi_t *
sexp_to_kparms (gcry_sexp_t sexp)
{
  gcry_sexp_t list, l2;
  const char *name;
  const char *s;
  size_t n;
  int i, idx;
  const char *elems;
  gcry_mpi_t *array;

  list = gcry_sexp_find_token (sexp, "private-key", 0 );
  if(!list)
    return NULL; 
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


/* Check whether STRING is a KEYGRIP, i.e has the correct length and
   does only consist of uppercase hex characters. */
static int
is_keygrip (const char *string)
{
  int i;

  for(i=0; string[i] && i < 41; i++) 
    if (!strchr("01234567890ABCDEF", string[i]))
      return 0; 
  return i == 40;
}


static void
export_p12_file (const char *fname)
{
  int rc;
  gcry_mpi_t kparms[9], *kp;
  unsigned char *key;
  size_t keylen;
  gcry_sexp_t private;
  struct rsa_secret_key_s sk;
  int i;
  unsigned char *cert = NULL;
  size_t certlen = 0;
  int keytype;
  size_t keylen_for_wipe = 0;
  char *pw;

  if ( is_keygrip (fname) )
    {
      char hexgrip[40+4+1];
      char *p;
  
      assert (strlen(fname) == 40);
      strcpy (stpcpy (hexgrip, fname), ".key");

      p = make_filename (opt_homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);
      key = read_key (p);
      xfree (p);
    }
  else
    key = read_key (fname);

  if (!key)
    return;

  keytype = agent_private_key_type (key);
  if (keytype == PRIVATE_KEY_PROTECTED)
    {
      unsigned char *tmpkey;
      size_t tmplen;

      rc = agent_unprotect (key, (pw=get_passphrase (1)),
                            NULL, &tmpkey, &tmplen);
      release_passphrase (pw);
      if (rc)
        {
          if (opt_status_msg && gpg_err_code (rc) == GPG_ERR_BAD_PASSPHRASE )
            log_info ("[PROTECT-TOOL:] bad-passphrase\n");
          log_error ("unprotecting key `%s' failed: %s\n",
                     fname, gpg_strerror (rc));
          xfree (key);
          return;
        }
      xfree (key);
      key = tmpkey;
      keylen_for_wipe = tmplen;

      keytype = agent_private_key_type (key);
    }

  if (keytype == PRIVATE_KEY_SHADOWED)
    {
      log_error ("`%s' is a shadowed private key - can't export it\n", fname);
      wipememory (key, keylen_for_wipe);
      xfree (key);
      return;
    }
  else if (keytype != PRIVATE_KEY_CLEAR)
    {
      log_error ("\%s' is not a private key\n", fname);
      wipememory (key, keylen_for_wipe);
      xfree (key);
      return;
    }


  if (opt_have_cert)
    {
      cert = (unsigned char*)read_file ("-", &certlen);
      if (!cert)
        {
          wipememory (key, keylen_for_wipe);
          xfree (key);
          return;
        }
    }


  if (gcry_sexp_new (&private, key, 0, 0))
    {
      log_error ("gcry_sexp_new failed\n");
      wipememory (key, keylen_for_wipe);
      xfree (key);
      xfree (cert);
      return;
    } 
  wipememory (key, keylen_for_wipe);
  xfree (key);

  kp = sexp_to_kparms (private);
  gcry_sexp_release (private);
  if (!kp)
    {
      log_error ("error converting key parameters\n");
      xfree (cert);
      return;
    } 
  sk.n = kp[0];
  sk.e = kp[1];
  sk.d = kp[2];
  sk.p = kp[3];
  sk.q = kp[4];
  sk.u = kp[5];
  xfree (kp);

 
  kparms[0] = sk.n;
  kparms[1] = sk.e;
  kparms[2] = sk.d;
  kparms[3] = sk.q;
  kparms[4] = sk.p;
  kparms[5] = gcry_mpi_snew (0);  /* compute d mod (p-1) */
  gcry_mpi_sub_ui (kparms[5], kparms[3], 1);
  gcry_mpi_mod (kparms[5], sk.d, kparms[5]);   
  kparms[6] = gcry_mpi_snew (0);  /* compute d mod (q-1) */
  gcry_mpi_sub_ui (kparms[6], kparms[4], 1);
  gcry_mpi_mod (kparms[6], sk.d, kparms[6]);   
  kparms[7] = sk.u;
  kparms[8] = NULL;

  pw = get_passphrase (3);
  key = p12_build (kparms, cert, certlen, pw, opt_p12_charset, &keylen);
  release_passphrase (pw);
  xfree (cert);
  for (i=0; i < 8; i++)
    gcry_mpi_release (kparms[i]);
  if (!key)
    return;
  
#ifdef HAVE_DOSISH_SYSTEM
  setmode ( fileno (stdout) , O_BINARY );
#endif
  fwrite (key, keylen, 1, stdout);
  xfree (key);
}



int
main (int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int cmd = 0;
  const char *fname;

  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  log_set_prefix ("gpg-protect-tool", 1); 

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems ();

  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal( _("%s is too old (need %s, have %s)\n"), "libgcrypt",
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }

  setup_libgcrypt_logging ();
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);


  opt_homedir = default_homedir ();


  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* (do not remove the args) */
  while (arg_parse (&pargs, opts) )
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt.verbose++; break;
        case oArmor:   opt_armor=1; break;
        case oCanonical: opt_canonical=1; break;
        case oHomedir: opt_homedir = pargs.r.ret_str; break;

        case oAgentProgram: opt_agent_program = pargs.r.ret_str; break;

        case oProtect: cmd = oProtect; break;
        case oUnprotect: cmd = oUnprotect; break;
        case oShadow: cmd = oShadow; break;
        case oShowShadowInfo: cmd = oShowShadowInfo; break;
        case oShowKeygrip: cmd = oShowKeygrip; break;
        case oP12Import: cmd = oP12Import; break;
        case oP12Export: cmd = oP12Export; break;
        case oP12Charset: opt_p12_charset = pargs.r.ret_str; break;

        case oS2Kcalibration: cmd = oS2Kcalibration; break;

        case oPassphrase: opt_passphrase = pargs.r.ret_str; break;
        case oStore: opt_store = 1; break;
        case oForce: opt_force = 1; break;
        case oNoFailOnExist: opt_no_fail_on_exist = 1; break;
        case oHaveCert: opt_have_cert = 1; break;
        case oPrompt: opt_prompt = pargs.r.ret_str; break;
        case oStatusMsg: opt_status_msg = 1; break;
          
        default: pargs.err = ARGPARSE_PRINT_ERROR; break;
	}
    }
  if (log_get_errorcount (0))
    exit (2);

  fname = "-";
  if (argc == 1)
    fname = *argv;
  else if (argc > 1)
    usage (1);

  /* Set the information which can't be taken from envvars.  */
  gnupg_prepare_get_passphrase (GPG_ERR_SOURCE_DEFAULT,
                                opt.verbose,
                                opt_homedir,
                                opt_agent_program,
                                NULL, NULL, NULL);

  if (opt_prompt)
    opt_prompt = percent_plus_unescape (opt_prompt, 0);

  if (cmd == oProtect)
    read_and_protect (fname);
  else if (cmd == oUnprotect)
    read_and_unprotect (fname);
  else if (cmd == oShadow)
    read_and_shadow (fname);
  else if (cmd == oShowShadowInfo)
    show_shadow_info (fname);
  else if (cmd == oShowKeygrip)
    show_keygrip (fname);
  else if (cmd == oP12Import)
    import_p12_file (fname);
  else if (cmd == oP12Export)
    export_p12_file (fname);
  else if (cmd == oS2Kcalibration)
    {
      if (!opt.verbose)
        opt.verbose++; /* We need to see something.  */
      get_standard_s2k_count ();
    }
  else
    show_file (fname);

  agent_exit (0);
  return 8; /*NOTREACHED*/
}

void
agent_exit (int rc)
{
  rc = rc? rc : log_get_errorcount(0)? 2 : 0;
  exit (rc);
}


/* Return the passphrase string and ask the agent if it has not been
   set from the command line  PROMPTNO select the prompt to display:
     0 = default
     1 = taken from the option --prompt
     2 = for unprotecting a pkcs#12 object
     3 = for protecting a new pkcs#12 object
     4 = for protecting an imported pkcs#12 in our system
*/
static char *
get_passphrase (int promptno)
{
  char *pw;
  int err;
  const char *desc;
  char *orig_codeset;
  int repeat = 0;
  
  if (opt_passphrase)
    return xstrdup (opt_passphrase);

  orig_codeset = i18n_switchto_utf8 ();

  if (promptno == 1 && opt_prompt)
    {
      desc = opt_prompt;
    }
  else if (promptno == 2)
    {
      desc = _("Please enter the passphrase to unprotect the "
               "PKCS#12 object.");
    }
  else if (promptno == 3)
    {
      desc = _("Please enter the passphrase to protect the "
               "new PKCS#12 object.");
      repeat = 1;
    }
  else if (promptno == 4)
    {
      desc = _("Please enter the passphrase to protect the "
               "imported object within the GnuPG system.");
      repeat = 1;
    }
  else
    desc = _("Please enter the passphrase or the PIN\n"
             "needed to complete this operation.");

  i18n_switchback (orig_codeset);

  err = gnupg_get_passphrase (NULL, NULL, _("Passphrase:"), desc,
                              repeat, repeat, 1, &pw);
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_CANCELED)
        log_info (_("cancelled\n"));
      else
        log_error (_("error while asking for the passphrase: %s\n"),
                   gpg_strerror (err));
      agent_exit (0);
    }
  assert (pw);

  return pw;
}


static void
release_passphrase (char *pw)
{
  if (pw)
    {
      wipememory (pw, strlen (pw));
      xfree (pw);
    }
}

static int
store_private_key (const unsigned char *grip,
                   const void *buffer, size_t length, int force)
{
  char *fname;
  estream_t fp;
  char hexgrip[40+4+1];
  
  bin2hex (grip, 20, hexgrip);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt_homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);
  if (force)
    fp = es_fopen (fname, "wb");
  else
    {
      if (!access (fname, F_OK))
      {
        if (opt_status_msg)
          log_info ("[PROTECT-TOOL:] secretkey-exists\n");
        if (opt_no_fail_on_exist)
          log_info ("secret key file `%s' already exists\n", fname);
        else
          log_error ("secret key file `%s' already exists\n", fname);
        xfree (fname);
        return opt_no_fail_on_exist? 0 : -1;
      }
      /* FWIW: Under Windows Vista the standard fopen in the msvcrt
         fails if the "x" GNU extension is used.  */
      fp = es_fopen (fname, "wbx"); 
    }

  if (!fp) 
    { 
      log_error ("can't create `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return -1;
    }

  if (es_fwrite (buffer, length, 1, fp) != 1)
    {
      log_error ("error writing `%s': %s\n", fname, strerror (errno));
      es_fclose (fp);
      remove (fname);
      xfree (fname);
      return -1;
    }
  if (es_fclose (fp))
    {
      log_error ("error closing `%s': %s\n", fname, strerror (errno));
      remove (fname);
      xfree (fname);
      return -1;
    }
  log_info ("secret key stored as `%s'\n", fname);

  if (opt_status_msg)
    log_info ("[PROTECT-TOOL:] secretkey-stored\n");

  xfree (fname);
  return 0;
}
