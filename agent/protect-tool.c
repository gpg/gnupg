/* protect-tool.c - A tool to test the secret key protection
 *	Copyright (C) 2002, 2003, 2004 Free Software Foundation, Inc.
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
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>

#define JNLIB_NEED_LOG_LOGV
#include "agent.h"
#include "minip12.h"
#include "simple-pwquery.h"
#include "i18n.h"

enum cmd_and_opt_values 
{ aNull = 0,
  oVerbose	  = 'v',
  oArmor          = 'a',
  oPassphrase     = 'P',

  oProtect        = 'p',
  oUnprotect      = 'u',
  
  oNoVerbose = 500,
  oShadow,
  oShowShadowInfo,
  oShowKeygrip,

  oP12Import,
  oP12Export,
  oStore,
  oForce,
  oHaveCert,
  oNoFailOnExist,
  oHomedir,
  oPrompt,

aTest };

struct rsa_secret_key_s 
  {
    gcry_mpi_t n;	    /* public modulus */
    gcry_mpi_t e;	    /* public exponent */
    gcry_mpi_t d;	    /* exponent */
    gcry_mpi_t p;	    /* prime  p. */
    gcry_mpi_t q;	    /* prime  q. */
    gcry_mpi_t u;	    /* inverse of p mod q. */
  };


static char *opt_homedir;
static int opt_armor;
static int opt_store;
static int opt_force;
static int opt_no_fail_on_exist;
static int opt_have_cert;
static const char *opt_passphrase;
static char *opt_prompt;

static char *get_passphrase (int promptno);
static void release_passphrase (char *pw);
static int store_private_key (const unsigned char *grip,
                              const void *buffer, size_t length, int force);


static ARGPARSE_OPTS opts[] = {
  
  { 301, NULL, 0, N_("@Options:\n ") },

  { oVerbose, "verbose",   0, "verbose" },
  { oArmor,   "armor",     0, "write output in advanced format" },
  { oPassphrase, "passphrase", 2, "|STRING|use passphrase STRING" },
  { oProtect, "protect",     256, "protect a private key"},
  { oUnprotect, "unprotect", 256, "unprotect a private key"},
  { oShadow,  "shadow", 256, "create a shadow entry for a priblic key"},
  { oShowShadowInfo,  "show-shadow-info", 256, "return the shadow info"},
  { oShowKeygrip, "show-keygrip", 256, "show the \"keygrip\""},

  { oP12Import, "p12-import", 256, "import a PKCS-12 encoded private key"},
  { oP12Export, "p12-export", 256, "export a private key PKCS-12 encoded"},
  { oHaveCert, "have-cert", 0,  "certificate to export provided on STDIN"},
  { oStore,     "store", 0, "store the created key in the appropriate place"},
  { oForce,     "force", 0, "force overwriting"},
  { oNoFailOnExist, "no-fail-on-exist", 0, "@" },
  { oHomedir, "homedir", 2, "@" }, 
  { oPrompt,  "prompt", 2, "|ESCSTRING|use ESCSTRING as prompt in pinentry"}, 
  {0}
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
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
      break;
    case 1:
    case 40: p =  _("Usage: gpg-protect-tool [options] (-h for help)\n");
      break;
    case 41: p =  _("Syntax: gpg-protect-tool [options] [args]]\n"
                    "Secret key maintenance tool\n");
    break;
    
    default: p = NULL;
    }
  return p;
}



static void
i18n_init (void)
{
#ifdef USE_SIMPLE_GETTEXT
    set_gettext_file( PACKAGE_GT );
#else
#ifdef ENABLE_NLS
    setlocale (LC_ALL, "");
    bindtextdomain (PACKAGE_GT, LOCALEDIR);
    textdomain (PACKAGE_GT);
#endif
#endif
}



/* Used by gcry for logging */
static void
my_gcry_logger (void *dummy, int level, const char *fmt, va_list arg_ptr)
{
  /* translate the log levels */
  switch (level)
    {
    case GCRY_LOG_CONT: level = JNLIB_LOG_CONT; break;
    case GCRY_LOG_INFO: level = JNLIB_LOG_INFO; break;
    case GCRY_LOG_WARN: level = JNLIB_LOG_WARN; break;
    case GCRY_LOG_ERROR:level = JNLIB_LOG_ERROR; break;
    case GCRY_LOG_FATAL:level = JNLIB_LOG_FATAL; break;
    case GCRY_LOG_BUG:  level = JNLIB_LOG_BUG; break;
    case GCRY_LOG_DEBUG:level = JNLIB_LOG_DEBUG; break;
    default:            level = JNLIB_LOG_ERROR; break;      }
  log_logv (level, fmt, arg_ptr);
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
  unsigned char *result;

  rc = gcry_sexp_sscan (&sexp, &erroff, buf, buflen);
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
      result = p;
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
  
  key = read_key (fname);
  if (!key)
    return;

  rc = agent_unprotect (key, (pw=get_passphrase (1)), &result, &resultlen);
  release_passphrase (pw);
  xfree (key);
  if (rc)
    {
      log_error ("unprotecting the key failed: %s\n", gpg_strerror (rc));
      return;
    }
  
  if (opt_armor)
    {
      char *p = make_advanced (result, resultlen);
      xfree (result);
      if (!p)
        return;
      result = p;
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
  
  key = read_key (fname);
  if (!key)
    return;

  rc = agent_shadow_key (key, "(8:313233342:43)", &result);
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
      result = p;
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

  p = make_advanced (key, keylen);
  xfree (key);
  if (p)
    {
      fwrite (p, strlen (p), 1, stdout);
      xfree (p);
    }
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
  size_t buflen, resultlen;
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

  kparms = p12_parse (buf, buflen, (pw=get_passphrase (0)),
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


  rc = agent_protect (key, (pw=get_passphrase (0)), &result, &resultlen);
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
      result = p;
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

      rc = agent_unprotect (key, (pw=get_passphrase (1)), &tmpkey, &tmplen);
      release_passphrase (pw);
      if (rc)
        {
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
      cert = read_file ("-", &certlen);
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

  key = p12_build (kparms, cert, certlen, (pw=get_passphrase (0)), &keylen);
  release_passphrase (pw);
  xfree (cert);
  for (i=0; i < 8; i++)
    gcry_mpi_release (kparms[i]);
  if (!key)
    return;
  
  fwrite (key, keylen, 1, stdout);
  xfree (key);
}



/* Do the percent and plus/space unescaping in place and return the
   length of the valid buffer. */
static size_t
percent_plus_unescape (unsigned char *string)
{
  unsigned char *p = string;
  size_t n = 0;

  while (*string)
    {
      if (*string == '%' && string[1] && string[2])
        { 
          string++;
          *p++ = xtoi_2 (string);
          n++;
          string+= 2;
        }
      else if (*string == '+')
        {
          *p++ = ' ';
          n++;
          string++;
        }
      else
        {
          *p++ = *string++;
          n++;
        }
    }

  return n;
}

/* Remove percent and plus escaping and make sure that the reuslt is a
   string.  This is done in place. Returns STRING. */
static char *
percent_plus_unescape_string (char *string) 
{
  unsigned char *p = string;
  size_t n;

  n = percent_plus_unescape (p);
  p[n] = 0;

  return string;
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

  /* Try to auto set the character set.  */
  set_native_charset (NULL); 

  i18n_init ();

  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal( _("libgcrypt is too old (need %s, have %s)\n"),
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }

  gcry_set_log_handler (my_gcry_logger, NULL);
  
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);


#ifdef __MINGW32__
  opt_homedir = read_w32_registry_string ( NULL,
                                           "Software\\GNU\\GnuPG", "HomeDir" );
#else
  opt_homedir = getenv ("GNUPGHOME");
#endif
  if (!opt_homedir || !*opt_homedir)
    opt_homedir = GNUPG_DEFAULT_HOMEDIR;


  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* (do not remove the args) */
  while (arg_parse (&pargs, opts) )
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt.verbose++; break;
        case oArmor:   opt_armor=1; break;
        case oHomedir: opt_homedir = pargs.r.ret_str; break;

        case oProtect: cmd = oProtect; break;
        case oUnprotect: cmd = oUnprotect; break;
        case oShadow: cmd = oShadow; break;
        case oShowShadowInfo: cmd = oShowShadowInfo; break;
        case oShowKeygrip: cmd = oShowKeygrip; break;
        case oP12Import: cmd = oP12Import; break;
        case oP12Export: cmd = oP12Export; break;

        case oPassphrase: opt_passphrase = pargs.r.ret_str; break;
        case oStore: opt_store = 1; break;
        case oForce: opt_force = 1; break;
        case oNoFailOnExist: opt_no_fail_on_exist = 1; break;
        case oHaveCert: opt_have_cert = 1; break;
        case oPrompt: opt_prompt = pargs.r.ret_str; break;
          
        default : pargs.err = 2; break;
	}
    }
  if (log_get_errorcount(0))
    exit(2);

  fname = "-";
  if (argc == 1)
    fname = *argv;
  else if (argc > 1)
    usage (1);

  if (opt_prompt)
    opt_prompt = percent_plus_unescape_string (xstrdup (opt_prompt));

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
*/
static char *
get_passphrase (int promptno)
{
  char *pw;
  int err;
  const char *desc;

  if (opt_passphrase)
    return xstrdup (opt_passphrase);

  if (promptno == 1 && opt_prompt)
    desc = opt_prompt;
  else
    desc = _("Please enter the passphrase or the PIN\n"
             "needed to complete this operation.");

  pw = simple_pwquery (NULL,NULL, _("Passphrase:"), desc, &err);
  if (!pw)
    {
      if (err)
        log_error ("error while asking for the passphrase\n");
      else
        log_info ("cancelled\n");
      agent_exit (0);
    }

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
  int i;
  char *fname;
  FILE *fp;
  char hexgrip[40+4+1];
  
  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt_homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);
  if (force)
    fp = fopen (fname, "wb");
  else
    {
      if (!access (fname, F_OK))
      {
        if (opt_no_fail_on_exist)
          log_info ("secret key file `%s' already exists\n", fname);
        else
          log_error ("secret key file `%s' already exists\n", fname);
        xfree (fname);
        return opt_no_fail_on_exist? 0 : -1;
      }
      fp = fopen (fname, "wbx");  /* FIXME: the x is a GNU extension - let
                                     configure check whether this actually
                                     works */
    }

  if (!fp) 
    { 
      log_error ("can't create `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return -1;
    }

  if (fwrite (buffer, length, 1, fp) != 1)
    {
      log_error ("error writing `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      remove (fname);
      xfree (fname);
      return -1;
    }
  if ( fclose (fp) )
    {
      log_error ("error closing `%s': %s\n", fname, strerror (errno));
      remove (fname);
      xfree (fname);
      return -1;
    }
  log_info ("secret key stored as `%s'\n", fname);

  xfree (fname);
  return 0;
}
