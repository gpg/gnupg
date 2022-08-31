/* misc.c - miscellaneous functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
 *               2008, 2009, 2010 Free Software Foundation, Inc.
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
#include <unistd.h>
#include <errno.h>
#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
#include <asm/sysinfo.h>
#include <asm/unistd.h>
#endif
#ifdef HAVE_SETRLIMIT
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif
#ifdef ENABLE_SELINUX_HACKS
#include <sys/stat.h>
#endif

#ifdef HAVE_W32_SYSTEM
#include <time.h>
#include <process.h>
#ifdef HAVE_WINSOCK2_H
# define WIN32_LEAN_AND_MEAN 1
# include <winsock2.h>
#endif
#include <windows.h>
#include <shlobj.h>
#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA 0x001a
#endif
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA 0x001c
#endif
#ifndef CSIDL_FLAG_CREATE
#define CSIDL_FLAG_CREATE 0x8000
#endif
#endif /*HAVE_W32_SYSTEM*/

#include "gpg.h"
#ifdef HAVE_W32_SYSTEM
# include "../common/status.h"
#endif /*HAVE_W32_SYSTEM*/
#include "../common/util.h"
#include "main.h"
#include "photoid.h"
#include "options.h"
#include "call-agent.h"
#include "../common/i18n.h"
#include "../common/zb32.h"

/* FIXME: Libgcrypt 1.9 will support EAX.  Until we name this a
 * requirement we hardwire the enum used for EAX.  */
#define MY_GCRY_CIPHER_MODE_EAX 14


#ifdef ENABLE_SELINUX_HACKS
/* A object and a global variable to keep track of files marked as
   secured. */
struct secured_file_item
{
  struct secured_file_item *next;
  ino_t ino;
  dev_t dev;
};
static struct secured_file_item *secured_files;
#endif /*ENABLE_SELINUX_HACKS*/




/* For the sake of SELinux we want to restrict access through gpg to
   certain files we keep under our own control.  This function
   registers such a file and is_secured_file may then be used to
   check whether a file has ben registered as secured. */
void
register_secured_file (const char *fname)
{
#ifdef ENABLE_SELINUX_HACKS
  struct stat buf;
  struct secured_file_item *sf;

  /* Note that we stop immediately if something goes wrong here. */
  if (gnupg_stat (fname, &buf))
    log_fatal (_("fstat of '%s' failed in %s: %s\n"), fname,
               "register_secured_file", strerror (errno));
/*   log_debug ("registering '%s' i=%lu.%lu\n", fname, */
/*              (unsigned long)buf.st_dev, (unsigned long)buf.st_ino); */
  for (sf=secured_files; sf; sf = sf->next)
    {
      if (sf->ino == buf.st_ino && sf->dev == buf.st_dev)
        return; /* Already registered.  */
    }

  sf = xmalloc (sizeof *sf);
  sf->ino = buf.st_ino;
  sf->dev = buf.st_dev;
  sf->next = secured_files;
  secured_files = sf;
#else /*!ENABLE_SELINUX_HACKS*/
  (void)fname;
#endif /*!ENABLE_SELINUX_HACKS*/
}

/* Remove a file registered as secure. */
void
unregister_secured_file (const char *fname)
{
#ifdef ENABLE_SELINUX_HACKS
  struct stat buf;
  struct secured_file_item *sf, *sfprev;

  if (gnupg_stat (fname, &buf))
    {
      log_error (_("fstat of '%s' failed in %s: %s\n"), fname,
                 "unregister_secured_file", strerror (errno));
      return;
    }
/*   log_debug ("unregistering '%s' i=%lu.%lu\n", fname,  */
/*              (unsigned long)buf.st_dev, (unsigned long)buf.st_ino); */
  for (sfprev=NULL,sf=secured_files; sf; sfprev=sf, sf = sf->next)
    {
      if (sf->ino == buf.st_ino && sf->dev == buf.st_dev)
        {
          if (sfprev)
            sfprev->next = sf->next;
          else
            secured_files = sf->next;
          xfree (sf);
          return;
        }
    }
#else /*!ENABLE_SELINUX_HACKS*/
  (void)fname;
#endif /*!ENABLE_SELINUX_HACKS*/
}

/* Return true if FD is corresponds to a secured file.  Using -1 for
   FS is allowed and will return false. */
int
is_secured_file (int fd)
{
#ifdef ENABLE_SELINUX_HACKS
  struct stat buf;
  struct secured_file_item *sf;

  if (fd == -1)
    return 0; /* No file descriptor so it can't be secured either.  */

  /* Note that we print out a error here and claim that a file is
     secure if something went wrong. */
  if (fstat (fd, &buf))
    {
      log_error (_("fstat(%d) failed in %s: %s\n"), fd,
                 "is_secured_file", strerror (errno));
      return 1;
    }
/*   log_debug ("is_secured_file (%d) i=%lu.%lu\n", fd, */
/*              (unsigned long)buf.st_dev, (unsigned long)buf.st_ino); */
  for (sf=secured_files; sf; sf = sf->next)
    {
      if (sf->ino == buf.st_ino && sf->dev == buf.st_dev)
        return 1; /* Yes.  */
    }
#else /*!ENABLE_SELINUX_HACKS*/
  (void)fd;
#endif /*!ENABLE_SELINUX_HACKS*/
  return 0; /* No. */
}

/* Return true if FNAME is corresponds to a secured file.  Using NULL,
   "" or "-" for FS is allowed and will return false. This function is
   used before creating a file, thus it won't fail if the file does
   not exist. */
int
is_secured_filename (const char *fname)
{
#ifdef ENABLE_SELINUX_HACKS
  struct stat buf;
  struct secured_file_item *sf;

  if (iobuf_is_pipe_filename (fname) || !*fname)
    return 0;

  /* Note that we print out a error here and claim that a file is
     secure if something went wrong. */
  if (gnupg_stat (fname, &buf))
    {
      if (errno == ENOENT || errno == EPERM || errno == EACCES)
        return 0;
      log_error (_("fstat of '%s' failed in %s: %s\n"), fname,
                 "is_secured_filename", strerror (errno));
      return 1;
    }
/*   log_debug ("is_secured_filename (%s) i=%lu.%lu\n", fname, */
/*              (unsigned long)buf.st_dev, (unsigned long)buf.st_ino); */
  for (sf=secured_files; sf; sf = sf->next)
    {
      if (sf->ino == buf.st_ino && sf->dev == buf.st_dev)
        return 1; /* Yes.  */
    }
#else /*!ENABLE_SELINUX_HACKS*/
  (void)fname;
#endif /*!ENABLE_SELINUX_HACKS*/
  return 0; /* No. */
}



u16
checksum_u16( unsigned n )
{
    u16 a;

    a  = (n >> 8) & 0xff;
    a += n & 0xff;
    return a;
}


u16
checksum( byte *p, unsigned n )
{
    u16 a;

    for(a=0; n; n-- )
	a += *p++;
    return a;
}

u16
checksum_mpi (gcry_mpi_t a)
{
  u16 csum;
  byte *buffer;
  size_t nbytes;

  if ( gcry_mpi_print (GCRYMPI_FMT_PGP, NULL, 0, &nbytes, a) )
    BUG ();
  /* Fixme: For numbers not in secure memory we should use a stack
   * based buffer and only allocate a larger one if mpi_print returns
   * an error. */
  buffer = (gcry_is_secure(a)?
            gcry_xmalloc_secure (nbytes) : gcry_xmalloc (nbytes));
  if ( gcry_mpi_print (GCRYMPI_FMT_PGP, buffer, nbytes, NULL, a) )
    BUG ();
  csum = checksum (buffer, nbytes);
  xfree (buffer);
  return csum;
}


void
print_pubkey_algo_note (pubkey_algo_t algo)
{
  if(algo >= 100 && algo <= 110)
    {
      static int warn=0;
      if(!warn)
	{
	  warn=1;
          es_fflush (es_stdout);
	  log_info (_("WARNING: using experimental public key algorithm %s\n"),
		    openpgp_pk_algo_name (algo));
	}
    }
  else if (algo == PUBKEY_ALGO_ELGAMAL)
    {
      es_fflush (es_stdout);
      log_info (_("WARNING: Elgamal sign+encrypt keys are deprecated\n"));
    }
}

void
print_cipher_algo_note (cipher_algo_t algo)
{
  if(algo >= 100 && algo <= 110)
    {
      static int warn=0;
      if(!warn)
	{
	  warn=1;
          es_fflush (es_stdout);
	  log_info (_("WARNING: using experimental cipher algorithm %s\n"),
                    openpgp_cipher_algo_name (algo));
	}
    }
}

void
print_digest_algo_note (digest_algo_t algo)
{
  if(algo >= 100 && algo <= 110)
    {
      static int warn=0;
      const enum gcry_md_algos galgo = map_md_openpgp_to_gcry (algo);

      if(!warn)
	{
	  warn=1;
          es_fflush (es_stdout);
	  log_info (_("WARNING: using experimental digest algorithm %s\n"),
                    gcry_md_algo_name (galgo));
	}
    }
  else if (is_weak_digest (algo))
    {
      const enum gcry_md_algos galgo = map_md_openpgp_to_gcry (algo);
      es_fflush (es_stdout);
      log_info (_("WARNING: digest algorithm %s is deprecated\n"),
                gcry_md_algo_name (galgo));
    }
}


void
print_digest_rejected_note (enum gcry_md_algos algo)
{
  struct weakhash* weak;
  int show = 1;

  if (opt.quiet)
    return;

  for (weak = opt.weak_digests; weak; weak = weak->next)
    if (weak->algo == algo)
      {
        if (weak->rejection_shown)
          show = 0;
        else
          weak->rejection_shown = 1;
        break;
      }

  if (show)
    {
      es_fflush (es_stdout);
      log_info
        (_("Note: signatures using the %s algorithm are rejected\n"),
         gcry_md_algo_name(algo));
    }
}


void
print_sha1_keysig_rejected_note (void)
{
  static int shown;

  if (shown || opt.quiet)
    return;

  shown = 1;
  es_fflush (es_stdout);
  log_info (_("Note: third-party key signatures using"
              " the %s algorithm are rejected\n"),
            gcry_md_algo_name (GCRY_MD_SHA1));
  print_further_info ("use option \"%s\" to override",
                      "--allow-weak-key-signatures");
}


/* Print a message
 *  "(reported error: %s)\n
 * in verbose mode to further explain an error.  If the error code has
 * the value IGNORE_EC no message is printed.  A message is also not
 * printed if ERR is 0.  */
void
print_reported_error (gpg_error_t err, gpg_err_code_t ignore_ec)
{
  if (!opt.verbose)
    return;

  if (!gpg_err_code (err))
    ;
  else if (gpg_err_code (err) == ignore_ec)
    ;
  else if (gpg_err_source (err) == GPG_ERR_SOURCE_DEFAULT)
    log_info (_("(reported error: %s)\n"),
              gpg_strerror (err));
  else
    log_info (_("(reported error: %s <%s>)\n"),
              gpg_strerror (err), gpg_strsource (err));

}


/* Print a message
 *   "(further info: %s)\n
 * in verbose mode to further explain an error.  That message is
 * intended to help debug a problem and should not be translated.
 */
void
print_further_info (const char *format, ...)
{
  va_list arg_ptr;

  if (!opt.verbose)
    return;

  log_info (_("(further info: "));
  va_start (arg_ptr, format);
  log_logv (GPGRT_LOG_CONT, format, arg_ptr);
  va_end (arg_ptr);
  log_printf (")\n");
}


/* Map OpenPGP algo numbers to those used by Libgcrypt.  We need to do
   this for algorithms we implemented in Libgcrypt after they become
   part of OpenPGP.  */
enum gcry_cipher_algos
map_cipher_openpgp_to_gcry (cipher_algo_t algo)
{
  switch (algo)
    {
    case CIPHER_ALGO_NONE:        return GCRY_CIPHER_NONE;

#ifdef GPG_USE_IDEA
    case CIPHER_ALGO_IDEA:        return GCRY_CIPHER_IDEA;
#else
    case CIPHER_ALGO_IDEA:        return 0;
#endif

    case CIPHER_ALGO_3DES:	  return GCRY_CIPHER_3DES;

#ifdef GPG_USE_CAST5
    case CIPHER_ALGO_CAST5:	  return GCRY_CIPHER_CAST5;
#else
    case CIPHER_ALGO_CAST5:	  return 0;
#endif

#ifdef GPG_USE_BLOWFISH
    case CIPHER_ALGO_BLOWFISH:    return GCRY_CIPHER_BLOWFISH;
#else
    case CIPHER_ALGO_BLOWFISH:    return 0;
#endif

#ifdef GPG_USE_AES128
    case CIPHER_ALGO_AES:         return GCRY_CIPHER_AES;
#else
    case CIPHER_ALGO_AES:         return 0;
#endif

#ifdef GPG_USE_AES192
    case CIPHER_ALGO_AES192:      return GCRY_CIPHER_AES192;
#else
    case CIPHER_ALGO_AES192:      return 0;
#endif

#ifdef GPG_USE_AES256
    case CIPHER_ALGO_AES256:      return GCRY_CIPHER_AES256;
#else
    case CIPHER_ALGO_AES256:      return 0;
#endif

#ifdef GPG_USE_TWOFISH
    case CIPHER_ALGO_TWOFISH:     return GCRY_CIPHER_TWOFISH;
#else
    case CIPHER_ALGO_TWOFISH:     return 0;
#endif

#ifdef GPG_USE_CAMELLIA128
    case CIPHER_ALGO_CAMELLIA128: return GCRY_CIPHER_CAMELLIA128;
#else
    case CIPHER_ALGO_CAMELLIA128: return 0;
#endif

#ifdef GPG_USE_CAMELLIA192
    case CIPHER_ALGO_CAMELLIA192: return GCRY_CIPHER_CAMELLIA192;
#else
    case CIPHER_ALGO_CAMELLIA192: return 0;
#endif

#ifdef GPG_USE_CAMELLIA256
    case CIPHER_ALGO_CAMELLIA256: return GCRY_CIPHER_CAMELLIA256;
#else
    case CIPHER_ALGO_CAMELLIA256: return 0;
#endif
    default: return 0;
    }
}

/* The inverse function of above.  */
static cipher_algo_t
map_cipher_gcry_to_openpgp (enum gcry_cipher_algos algo)
{
  switch (algo)
    {
    case GCRY_CIPHER_NONE:        return CIPHER_ALGO_NONE;
    case GCRY_CIPHER_IDEA:        return CIPHER_ALGO_IDEA;
    case GCRY_CIPHER_3DES:        return CIPHER_ALGO_3DES;
    case GCRY_CIPHER_CAST5:       return CIPHER_ALGO_CAST5;
    case GCRY_CIPHER_BLOWFISH:    return CIPHER_ALGO_BLOWFISH;
    case GCRY_CIPHER_AES:         return CIPHER_ALGO_AES;
    case GCRY_CIPHER_AES192:      return CIPHER_ALGO_AES192;
    case GCRY_CIPHER_AES256:      return CIPHER_ALGO_AES256;
    case GCRY_CIPHER_TWOFISH:     return CIPHER_ALGO_TWOFISH;
    case GCRY_CIPHER_CAMELLIA128: return CIPHER_ALGO_CAMELLIA128;
    case GCRY_CIPHER_CAMELLIA192: return CIPHER_ALGO_CAMELLIA192;
    case GCRY_CIPHER_CAMELLIA256: return CIPHER_ALGO_CAMELLIA256;
    default: return 0;
    }
}

/* Map Gcrypt public key algorithm numbers to those used by OpenPGP.
   FIXME: This mapping is used at only two places - we should get rid
   of it.  */
pubkey_algo_t
map_pk_gcry_to_openpgp (enum gcry_pk_algos algo)
{
  switch (algo)
    {
    case GCRY_PK_EDDSA:  return PUBKEY_ALGO_EDDSA;
    case GCRY_PK_ECDSA:  return PUBKEY_ALGO_ECDSA;
    case GCRY_PK_ECDH:   return PUBKEY_ALGO_ECDH;
    default: return algo < 110 ? (pubkey_algo_t)algo : 0;
    }
}


/* Return the block length of an OpenPGP cipher algorithm.  */
int
openpgp_cipher_blocklen (cipher_algo_t algo)
{
  /* We use the numbers from OpenPGP to be sure that we get the right
     block length.  This is so that the packet parsing code works even
     for unknown algorithms (for which we assume 8 due to tradition).

     NOTE: If you change the returned blocklen above 16, check
     the callers because they may use a fixed size buffer of that
     size. */
  switch (algo)
    {
    case CIPHER_ALGO_AES:
    case CIPHER_ALGO_AES192:
    case CIPHER_ALGO_AES256:
    case CIPHER_ALGO_TWOFISH:
    case CIPHER_ALGO_CAMELLIA128:
    case CIPHER_ALGO_CAMELLIA192:
    case CIPHER_ALGO_CAMELLIA256:
      return 16;

    default:
      return 8;
    }
}

/****************
 * Wrapper around the libgcrypt function with additional checks on
 * the OpenPGP contraints for the algo ID.
 */
int
openpgp_cipher_test_algo (cipher_algo_t algo)
{
  enum gcry_cipher_algos ga;

  ga = map_cipher_openpgp_to_gcry (algo);
  if (!ga)
    return gpg_error (GPG_ERR_CIPHER_ALGO);

  return gcry_cipher_test_algo (ga);
}

/* Map the OpenPGP cipher algorithm whose ID is contained in ALGORITHM to a
   string representation of the algorithm name.  For unknown algorithm
   IDs this function returns "?".  */
const char *
openpgp_cipher_algo_name (cipher_algo_t algo)
{
  switch (algo)
    {
    case CIPHER_ALGO_IDEA:        return "IDEA";
    case CIPHER_ALGO_3DES:	  return "3DES";
    case CIPHER_ALGO_CAST5:	  return "CAST5";
    case CIPHER_ALGO_BLOWFISH:    return "BLOWFISH";
    case CIPHER_ALGO_AES:         return "AES";
    case CIPHER_ALGO_AES192:      return "AES192";
    case CIPHER_ALGO_AES256:      return "AES256";
    case CIPHER_ALGO_TWOFISH:     return "TWOFISH";
    case CIPHER_ALGO_CAMELLIA128: return "CAMELLIA128";
    case CIPHER_ALGO_CAMELLIA192: return "CAMELLIA192";
    case CIPHER_ALGO_CAMELLIA256: return "CAMELLIA256";
    case CIPHER_ALGO_NONE:
    default: return "?";
    }
}


/* Same as openpgp_cipher_algo_name but returns a string in the form
 * "ALGO.MODE" if AEAD is not 0.  Note that in this version we do not
 * print "ALGO.CFB" as we do in 2.3 to avoid confusing users.  */
const char *
openpgp_cipher_algo_mode_name (cipher_algo_t algo, aead_algo_t aead)
{

  if (aead == AEAD_ALGO_NONE)
    return openpgp_cipher_algo_name (algo);

  return map_static_strings ("openpgp_cipher_algo_mode_name", algo, aead,
                             openpgp_cipher_algo_name (algo),
                             ".",
                             openpgp_aead_algo_name (aead),
                             NULL);
}


/* Return 0 if ALGO is supported.  Return an error if not. */
gpg_error_t
openpgp_aead_test_algo (aead_algo_t algo)
{
  /* FIXME: We currently have no easy way to test whether libgcrypt
   * implements a mode.  The only way we can do this is to open a
   * cipher context with that mode and close it immediately.  That is
   * a bit costly.  So we look at the libgcrypt version and assume
   * nothing has been patched out.  */
  switch (algo)
    {
    case AEAD_ALGO_NONE:
      break;

    case AEAD_ALGO_EAX:
#if GCRYPT_VERSION_NUMBER < 0x010900
      break;
#else
      return 0;
#endif

    case AEAD_ALGO_OCB:
      return 0;
    }

  return gpg_error (GPG_ERR_INV_CIPHER_MODE);
}


/* Map the OpenPGP AEAD algorithm with ID ALGO to a string
 * representation of the algorithm name.  For unknown algorithm IDs
 * this function returns "?".  */
const char *
openpgp_aead_algo_name (aead_algo_t algo)
{
  switch (algo)
    {
    case AEAD_ALGO_NONE:  break;
    case AEAD_ALGO_EAX:   return "EAX";
    case AEAD_ALGO_OCB:   return "OCB";
    }

  return "?";
}


/* Return information for the AEAD algorithm ALGO.  The corresponding
 * Libgcrypt ciphermode is stored at R_MODE and the required number of
 * octets for the nonce at R_NONCELEN.  On error and error code is
 * returned.  Note that the taglen is always 128 bits.  */
gpg_error_t
openpgp_aead_algo_info (aead_algo_t algo, enum gcry_cipher_modes *r_mode,
                        unsigned int *r_noncelen)
{
  switch (algo)
    {
    case AEAD_ALGO_OCB:
      *r_mode = GCRY_CIPHER_MODE_OCB;
      *r_noncelen = 15;
      break;

    case AEAD_ALGO_EAX:
      *r_mode = MY_GCRY_CIPHER_MODE_EAX;
      *r_noncelen = 16;
      break;

    default:
      log_error ("unsupported AEAD algo %d\n", algo);
      return gpg_error (GPG_ERR_INV_CIPHER_MODE);
    }
  return 0;
}


/* Return 0 if ALGO is a supported OpenPGP public key algorithm.  */
int
openpgp_pk_test_algo (pubkey_algo_t algo)
{
  return openpgp_pk_test_algo2 (algo, 0);
}


/* Return 0 if ALGO is a supported OpenPGP public key algorithm and
   allows the usage USE.  */
int
openpgp_pk_test_algo2 (pubkey_algo_t algo, unsigned int use)
{
  enum gcry_pk_algos ga = 0;
  size_t use_buf = use;

  switch (algo)
    {
#ifdef GPG_USE_RSA
    case PUBKEY_ALGO_RSA:       ga = GCRY_PK_RSA;   break;
    case PUBKEY_ALGO_RSA_E:     ga = GCRY_PK_RSA_E; break;
    case PUBKEY_ALGO_RSA_S:     ga = GCRY_PK_RSA_S; break;
#else
    case PUBKEY_ALGO_RSA:       break;
    case PUBKEY_ALGO_RSA_E:     break;
    case PUBKEY_ALGO_RSA_S:     break;
#endif

    case PUBKEY_ALGO_ELGAMAL_E: ga = GCRY_PK_ELG;   break;
    case PUBKEY_ALGO_DSA:       ga = GCRY_PK_DSA;   break;

#ifdef GPG_USE_ECDH
    case PUBKEY_ALGO_ECDH:      ga = GCRY_PK_ECC;   break;
#else
    case PUBKEY_ALGO_ECDH:      break;
#endif

#ifdef GPG_USE_ECDSA
    case PUBKEY_ALGO_ECDSA:     ga = GCRY_PK_ECC;   break;
#else
    case PUBKEY_ALGO_ECDSA:     break;
#endif

#ifdef GPG_USE_EDDSA
    case PUBKEY_ALGO_EDDSA:     ga = GCRY_PK_ECC;   break;
#else
    case PUBKEY_ALGO_EDDSA:     break;
#endif

    case PUBKEY_ALGO_ELGAMAL:
      /* Dont't allow type 20 keys unless in rfc2440 mode.  */
      if (RFC2440)
        ga = GCRY_PK_ELG;
      break;

    default:
      break;
    }
  if (!ga)
    return gpg_error (GPG_ERR_PUBKEY_ALGO);

  /* Elgamal in OpenPGP used to support signing and Libgcrypt still
   * does.  However, we removed the signing capability from gpg ages
   * ago.  This function should reflect this so that errors are thrown
   * early and not only when we try to sign using Elgamal.  */
  if (ga == GCRY_PK_ELG && (use & (PUBKEY_USAGE_CERT | PUBKEY_USAGE_SIG)))
    return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

  /* Now check whether Libgcrypt has support for the algorithm.  */
  return gcry_pk_algo_info (ga, GCRYCTL_TEST_ALGO, NULL, &use_buf);
}


int
openpgp_pk_algo_usage ( int algo )
{
    int use = 0;

    /* They are hardwired in gpg 1.0. */
    switch ( algo ) {
      case PUBKEY_ALGO_RSA:
          use = (PUBKEY_USAGE_CERT | PUBKEY_USAGE_SIG
                 | PUBKEY_USAGE_ENC | PUBKEY_USAGE_AUTH);
          break;
      case PUBKEY_ALGO_RSA_E:
      case PUBKEY_ALGO_ECDH:
          use = PUBKEY_USAGE_ENC;
          break;
      case PUBKEY_ALGO_RSA_S:
          use = PUBKEY_USAGE_CERT | PUBKEY_USAGE_SIG;
          break;
      case PUBKEY_ALGO_ELGAMAL:
          if (RFC2440)
             use = PUBKEY_USAGE_ENC;
          break;
      case PUBKEY_ALGO_ELGAMAL_E:
          use = PUBKEY_USAGE_ENC;
          break;
      case PUBKEY_ALGO_DSA:
          use = PUBKEY_USAGE_CERT | PUBKEY_USAGE_SIG | PUBKEY_USAGE_AUTH;
          break;
      case PUBKEY_ALGO_ECDSA:
      case PUBKEY_ALGO_EDDSA:
          use = PUBKEY_USAGE_CERT | PUBKEY_USAGE_SIG | PUBKEY_USAGE_AUTH;
      default:
          break;
    }
    return use;
}

/* Map the OpenPGP pubkey algorithm whose ID is contained in ALGO to a
   string representation of the algorithm name.  For unknown algorithm
   IDs this function returns "?".  */
const char *
openpgp_pk_algo_name (pubkey_algo_t algo)
{
  switch (algo)
    {
    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_E:
    case PUBKEY_ALGO_RSA_S:     return "RSA";
    case PUBKEY_ALGO_ELGAMAL:
    case PUBKEY_ALGO_ELGAMAL_E: return "ELG";
    case PUBKEY_ALGO_DSA:       return "DSA";
    case PUBKEY_ALGO_ECDH:      return "ECDH";
    case PUBKEY_ALGO_ECDSA:     return "ECDSA";
    case PUBKEY_ALGO_EDDSA:     return "EDDSA";
    default: return "?";
    }
}


/* Explicit mapping of OpenPGP digest algos to Libgcrypt.  */
/* FIXME: We do not yes use it everywhere.  */
enum gcry_md_algos
map_md_openpgp_to_gcry (digest_algo_t algo)
{
  switch (algo)
    {
#ifdef GPG_USE_MD5
    case DIGEST_ALGO_MD5:    return GCRY_MD_MD5;
#else
    case DIGEST_ALGO_MD5:    return 0;
#endif

    case DIGEST_ALGO_SHA1:   return GCRY_MD_SHA1;

#ifdef GPG_USE_RMD160
    case DIGEST_ALGO_RMD160: return GCRY_MD_RMD160;
#else
    case DIGEST_ALGO_RMD160: return 0;
#endif

#ifdef GPG_USE_SHA224
    case DIGEST_ALGO_SHA224: return GCRY_MD_SHA224;
#else
    case DIGEST_ALGO_SHA224: return 0;
#endif

    case DIGEST_ALGO_SHA256: return GCRY_MD_SHA256;

#ifdef GPG_USE_SHA384
    case DIGEST_ALGO_SHA384: return GCRY_MD_SHA384;
#else
    case DIGEST_ALGO_SHA384: return 0;
#endif

#ifdef GPG_USE_SHA512
    case DIGEST_ALGO_SHA512: return GCRY_MD_SHA512;
#else
    case DIGEST_ALGO_SHA512: return 0;
#endif
    default: return 0;
    }
}


/* Return 0 if ALGO is suitable and implemented OpenPGP hash
   algorithm.  */
int
openpgp_md_test_algo (digest_algo_t algo)
{
  enum gcry_md_algos ga;

  ga = map_md_openpgp_to_gcry (algo);
  if (!ga)
    return gpg_error (GPG_ERR_DIGEST_ALGO);

  return gcry_md_test_algo (ga);
}


/* Map the OpenPGP digest algorithm whose ID is contained in ALGO to a
   string representation of the algorithm name.  For unknown algorithm
   IDs this function returns "?".  */
const char *
openpgp_md_algo_name (int algo)
{
  switch (algo)
    {
    case DIGEST_ALGO_MD5:    return "MD5";
    case DIGEST_ALGO_SHA1:   return "SHA1";
    case DIGEST_ALGO_RMD160: return "RIPEMD160";
    case DIGEST_ALGO_SHA256: return "SHA256";
    case DIGEST_ALGO_SHA384: return "SHA384";
    case DIGEST_ALGO_SHA512: return "SHA512";
    case DIGEST_ALGO_SHA224: return "SHA224";
    }
  return "?";
}


static unsigned long
get_signature_count (PKT_public_key *pk)
{
#ifdef ENABLE_CARD_SUPPORT
  struct agent_card_info_s info;

  (void)pk;
  if (!agent_scd_getattr ("SIG-COUNTER",&info))
    return info.sig_counter;
  else
    return 0;
#else
  (void)pk;
  return 0;
#endif
}

/* Expand %-strings.  Returns a string which must be xfreed.  Returns
   NULL if the string cannot be expanded (too large). */
char *
pct_expando(const char *string,struct expando_args *args)
{
  const char *ch=string;
  int idx=0,maxlen=0,done=0;
  u32 pk_keyid[2]={0,0},sk_keyid[2]={0,0};
  char *ret=NULL;

  /* The parser below would return NULL for an empty string, thus we
   * catch it here.  Also catch NULL here. */
  if (!string || !*string)
    return xstrdup ("");

  if(args->pk)
    keyid_from_pk(args->pk,pk_keyid);

  if(args->pksk)
    keyid_from_pk (args->pksk, sk_keyid);

  /* This is used so that %k works in photoid command strings in
     --list-secret-keys (which of course has a sk, but no pk). */
  if(!args->pk && args->pksk)
    keyid_from_pk (args->pksk, pk_keyid);

  while(*ch!='\0')
    {
      if(!done)
	{
	  /* 8192 is way bigger than we'll need here */
	  if(maxlen>=8192)
	    goto fail;

	  maxlen+=1024;
	  ret=xrealloc(ret,maxlen);
	}

      done=0;

      if(*ch=='%')
	{
	  switch(*(ch+1))
	    {
	    case 's': /* short key id */
	      if(idx+8<maxlen)
		{
		  sprintf(&ret[idx],"%08lX",(ulong)sk_keyid[1]);
		  idx+=8;
		  done=1;
		}
	      break;

	    case 'S': /* long key id */
	      if(idx+16<maxlen)
		{
		  sprintf(&ret[idx],"%08lX%08lX",
			  (ulong)sk_keyid[0],(ulong)sk_keyid[1]);
		  idx+=16;
		  done=1;
		}
	      break;

	    case 'k': /* short key id */
	      if(idx+8<maxlen)
		{
		  sprintf(&ret[idx],"%08lX",(ulong)pk_keyid[1]);
		  idx+=8;
		  done=1;
		}
	      break;

	    case 'K': /* long key id */
	      if(idx+16<maxlen)
		{
		  sprintf(&ret[idx],"%08lX%08lX",
			  (ulong)pk_keyid[0],(ulong)pk_keyid[1]);
		  idx+=16;
		  done=1;
		}
	      break;

	    case 'U': /* z-base-32 encoded user id hash. */
              if (args->namehash)
                {
                  char *tmp = zb32_encode (args->namehash, 8*20);
                  if (tmp)
                    {
                      if (idx + strlen (tmp) < maxlen)
                        {
                          strcpy (ret+idx, tmp);
                          idx += strlen (tmp);
                        }
                      xfree (tmp);
                      done = 1;
                    }
                }
	      break;

	    case 'c': /* signature count from card, if any. */
	      if(idx+10<maxlen)
		{
		  sprintf (&ret[idx],"%lu", get_signature_count (args->pksk));
		  idx+=strlen(&ret[idx]);
		  done=1;
		}
	      break;

	    case 'f': /* Fingerprint of key being signed */
	    case 'p': /* Fingerprint of the primary key making the signature. */
	    case 'g': /* Fingerprint of the key making the signature.  */
	      {
		byte array[MAX_FINGERPRINT_LEN];
		size_t len;
		int i;

		if ((*(ch+1))=='f' && args->pk)
		  fingerprint_from_pk (args->pk, array, &len);
		else if ((*(ch+1))=='p' && args->pksk)
		  {
		    if(args->pksk->flags.primary)
		      fingerprint_from_pk (args->pksk, array, &len);
		    else if (args->pksk->main_keyid[0]
                             || args->pksk->main_keyid[1])
		      {
                        /* Not the primary key: Find the fingerprint
                           of the primary key.  */
			PKT_public_key *pk=
			  xmalloc_clear(sizeof(PKT_public_key));

			if (!get_pubkey_fast (pk,args->pksk->main_keyid))
			  fingerprint_from_pk (pk, array, &len);
			else
			  memset (array, 0, (len=MAX_FINGERPRINT_LEN));
			free_public_key (pk);
		      }
		    else /* Oops: info about the primary key missing.  */
		      memset(array,0,(len=MAX_FINGERPRINT_LEN));
		  }
		else if((*(ch+1))=='g' && args->pksk)
		  fingerprint_from_pk (args->pksk, array, &len);
		else
		  memset(array,0,(len=MAX_FINGERPRINT_LEN));

		if(idx+(len*2)<maxlen)
		  {
		    for(i=0;i<len;i++)
		      {
			sprintf(&ret[idx],"%02X",array[i]);
			idx+=2;
		      }
		    done=1;
		  }
	      }
	      break;

	    case 'v': /* validity letters */
	      if(args->validity_info && idx+1<maxlen)
		{
		  ret[idx++]=args->validity_info;
		  ret[idx]='\0';
		  done=1;
		}
	      break;

	      /* The text string types */
	    case 't':
	    case 'T':
	    case 'V':
	      {
		const char *str=NULL;

		switch(*(ch+1))
		  {
		  case 't': /* e.g. "jpg" */
		    str=image_type_to_string(args->imagetype,0);
		    break;

		  case 'T': /* e.g. "image/jpeg" */
		    str=image_type_to_string(args->imagetype,2);
		    break;

		  case 'V': /* e.g. "full", "expired", etc. */
		    str=args->validity_string;
		    break;
		  }

		if(str && idx+strlen(str)<maxlen)
		  {
		    strcpy(&ret[idx],str);
		    idx+=strlen(str);
		    done=1;
		  }
	      }
	      break;

	    case '%':
	      if(idx+1<maxlen)
		{
		  ret[idx++]='%';
		  ret[idx]='\0';
		  done=1;
		}
	      break;

	      /* Any unknown %-keys (like %i, %o, %I, and %O) are
		 passed through for later expansion.  Note this also
		 handles the case where the last character in the
		 string is a '%' - the terminating \0 will end up here
		 and properly terminate the string. */
	    default:
	      if(idx+2<maxlen)
		{
		  ret[idx++]='%';
		  ret[idx++]=*(ch+1);
		  ret[idx]='\0';
		  done=1;
		}
	      break;
	      }

	  if(done)
	    ch++;
	}
      else
	{
	  if(idx+1<maxlen)
	    {
	      ret[idx++]=*ch;
	      ret[idx]='\0';
	      done=1;
	    }
	}

      if(done)
	ch++;
    }

  return ret;

 fail:
  xfree(ret);
  return NULL;
}

void
deprecated_warning(const char *configname,unsigned int configlineno,
		   const char *option,const char *repl1,const char *repl2)
{
  if(configname)
    {
      if(strncmp("--",option,2)==0)
	option+=2;

      if(strncmp("--",repl1,2)==0)
	repl1+=2;

      log_info(_("%s:%d: deprecated option \"%s\"\n"),
	       configname,configlineno,option);
    }
  else
    log_info(_("WARNING: \"%s\" is a deprecated option\n"),option);

  log_info(_("please use \"%s%s\" instead\n"),repl1,repl2);
}


void
deprecated_command (const char *name)
{
  log_info(_("WARNING: \"%s\" is a deprecated command - do not use it\n"),
           name);
}


void
obsolete_scdaemon_option (const char *configname, unsigned int configlineno,
                          const char *name)
{
  if (configname)
    log_info (_("%s:%u: \"%s\" is obsolete in this file"
                " - it only has effect in %s\n"),
              configname, configlineno, name, SCDAEMON_NAME EXTSEP_S "conf");
  else
    log_info (_("WARNING: \"%s%s\" is an obsolete option"
                " - it has no effect except on %s\n"),
              "--", name, SCDAEMON_NAME);
}


/*
 * Wrapper around gcry_cipher_map_name to provide a fallback using the
 * "Sn" syntax as used by the preference strings.
 */
int
string_to_cipher_algo (const char *string)
{
  int val;

  val = map_cipher_gcry_to_openpgp (gcry_cipher_map_name (string));
  if (!val && string && (string[0]=='S' || string[0]=='s'))
    {
      char *endptr;

      string++;
      val = strtol (string, &endptr, 10);
      if (!*string || *endptr || openpgp_cipher_test_algo (val))
        val = 0;
    }

  return val;
}

/*
 * Wrapper around gcry_md_map_name to provide a fallback using the
 * "Hn" syntax as used by the preference strings.
 */
int
string_to_digest_algo (const char *string)
{
  int val;

  /* FIXME: We should make use of our wrapper function and not assume
     that there is a 1 to 1 mapping between OpenPGP and Libgcrypt.  */
  val = gcry_md_map_name (string);
  if (!val && string && (string[0]=='H' || string[0]=='h'))
    {
      char *endptr;

      string++;
      val = strtol (string, &endptr, 10);
      if (!*string || *endptr || openpgp_md_test_algo (val))
        val = 0;
    }

  return val;
}



const char *
compress_algo_to_string(int algo)
{
  const char *s=NULL;

  switch(algo)
    {
    case COMPRESS_ALGO_NONE:
      s=_("Uncompressed");
      break;

    case COMPRESS_ALGO_ZIP:
      s="ZIP";
      break;

    case COMPRESS_ALGO_ZLIB:
      s="ZLIB";
      break;

#ifdef HAVE_BZIP2
    case COMPRESS_ALGO_BZIP2:
      s="BZIP2";
      break;
#endif
    }

  return s;
}

int
string_to_compress_algo(const char *string)
{
  /* TRANSLATORS: See doc/TRANSLATE about this string. */
  if(match_multistr(_("uncompressed|none"),string))
    return 0;
  else if(ascii_strcasecmp(string,"uncompressed")==0)
    return 0;
  else if(ascii_strcasecmp(string,"none")==0)
    return 0;
  else if(ascii_strcasecmp(string,"zip")==0)
    return 1;
  else if(ascii_strcasecmp(string,"zlib")==0)
    return 2;
#ifdef HAVE_BZIP2
  else if(ascii_strcasecmp(string,"bzip2")==0)
    return 3;
#endif
  else if(ascii_strcasecmp(string,"z0")==0)
    return 0;
  else if(ascii_strcasecmp(string,"z1")==0)
    return 1;
  else if(ascii_strcasecmp(string,"z2")==0)
    return 2;
#ifdef HAVE_BZIP2
  else if(ascii_strcasecmp(string,"z3")==0)
    return 3;
#endif
  else
    return -1;
}

int
check_compress_algo(int algo)
{
  switch (algo)
    {
    case 0: return 0;
#ifdef HAVE_ZIP
    case 1:
    case 2: return 0;
#endif
#ifdef HAVE_BZIP2
    case 3: return 0;
#endif
    default: return GPG_ERR_COMPR_ALGO;
    }
}

int
default_cipher_algo(void)
{
  if(opt.def_cipher_algo)
    return opt.def_cipher_algo;
  else if(opt.personal_cipher_prefs)
    return opt.personal_cipher_prefs[0].value;
  else
    return opt.s2k_cipher_algo;
}

/* There is no default_digest_algo function, but see
   sign.c:hash_for() */

int
default_compress_algo(void)
{
  if(opt.compress_algo!=-1)
    return opt.compress_algo;
  else if(opt.personal_compress_prefs)
    return opt.personal_compress_prefs[0].value;
  else
    return DEFAULT_COMPRESS_ALGO;
}


void
compliance_failure(void)
{
  char *ver="???";

  switch(opt.compliance)
    {
    case CO_GNUPG:
      ver="GnuPG";
      break;

    case CO_RFC4880:
      ver="OpenPGP";
      break;

    case CO_RFC2440:
      ver="OpenPGP (older)";
      break;

    case CO_PGP6:
      ver="PGP 6.x";
      break;

    case CO_PGP7:
      ver="PGP 7.x";
      break;

    case CO_PGP8:
      ver="PGP 8.x";
      break;

    case CO_DE_VS:
      /* For de-vs we do not allow any kind of fallback.  */
      write_status_failure ("compliance-check", gpg_error (GPG_ERR_FORBIDDEN));
      log_error (_("operation forced to fail due to"
                   " unfulfilled compliance rules\n"));
      g10_errors_seen = 1;
      return;
    }

  log_info(_("this message may not be usable by %s\n"),ver);
  opt.compliance=CO_GNUPG;
}

/* Break a string into successive option pieces.  Accepts single word
   options and key=value argument options. */
char *
optsep(char **stringp)
{
  char *tok,*end;

  tok=*stringp;
  if(tok)
    {
      end=strpbrk(tok," ,=");
      if(end)
	{
	  int sawequals=0;
	  char *ptr=end;

	  /* what we need to do now is scan along starting with *end,
	     If the next character we see (ignoring spaces) is an =
	     sign, then there is an argument. */

	  while(*ptr)
	    {
	      if(*ptr=='=')
		sawequals=1;
	      else if(*ptr!=' ')
		break;
	      ptr++;
	    }

	  /* There is an argument, so grab that too.  At this point,
	     ptr points to the first character of the argument. */
	  if(sawequals)
	    {
	      /* Is it a quoted argument? */
	      if(*ptr=='"')
		{
		  ptr++;
		  end=strchr(ptr,'"');
		  if(end)
		    end++;
		}
	      else
		end=strpbrk(ptr," ,");
	    }

	  if(end && *end)
	    {
	      *end='\0';
	      *stringp=end+1;
	    }
	  else
	    *stringp=NULL;
	}
      else
	*stringp=NULL;
    }

  return tok;
}

/* Breaks an option value into key and value.  Returns NULL if there
   is no value.  Note that "string" is modified to remove the =value
   part. */
char *
argsplit(char *string)
{
  char *equals,*arg=NULL;

  equals=strchr(string,'=');
  if(equals)
    {
      char *quote,*space;

      *equals='\0';
      arg=equals+1;

      /* Quoted arg? */
      quote=strchr(arg,'"');
      if(quote)
	{
	  arg=quote+1;

	  quote=strchr(arg,'"');
	  if(quote)
	    *quote='\0';
	}
      else
	{
	  size_t spaces;

	  /* Trim leading spaces off of the arg */
	  spaces=strspn(arg," ");
	  arg+=spaces;
	}

      /* Trim tailing spaces off of the tag */
      space=strchr(string,' ');
      if(space)
	*space='\0';
    }

  return arg;
}

/* Return the length of the initial token, leaving off any
   argument. */
static size_t
optlen(const char *s)
{
  char *end=strpbrk(s," =");

  if(end)
    return end-s;
  else
    return strlen(s);
}

int
parse_options(char *str,unsigned int *options,
	      struct parse_options *opts,int noisy)
{
  char *tok;

  if (str && !strcmp (str, "help"))
    {
      int i,maxlen=0;

      /* Figure out the longest option name so we can line these up
	 neatly. */
      for(i=0;opts[i].name;i++)
	if(opts[i].help && maxlen<strlen(opts[i].name))
	  maxlen=strlen(opts[i].name);

      for(i=0;opts[i].name;i++)
        if(opts[i].help)
	  es_printf("%s%*s%s\n",opts[i].name,
                    maxlen+2-(int)strlen(opts[i].name),"",_(opts[i].help));

      g10_exit(0);
    }

  while((tok=optsep(&str)))
    {
      int i,rev=0;
      char *otok=tok;

      if(tok[0]=='\0')
	continue;

      if(ascii_strncasecmp("no-",tok,3)==0)
	{
	  rev=1;
	  tok+=3;
	}

      for(i=0;opts[i].name;i++)
	{
	  size_t toklen=optlen(tok);

	  if(ascii_strncasecmp(opts[i].name,tok,toklen)==0)
	    {
	      /* We have a match, but it might be incomplete */
	      if(toklen!=strlen(opts[i].name))
		{
		  int j;

		  for(j=i+1;opts[j].name;j++)
		    {
		      if(ascii_strncasecmp(opts[j].name,tok,toklen)==0)
			{
			  if(noisy)
			    log_info(_("ambiguous option '%s'\n"),otok);
			  return 0;
			}
		    }
		}

	      if(rev)
		{
		  *options&=~opts[i].bit;
		  if(opts[i].value)
		    *opts[i].value=NULL;
		}
	      else
		{
		  *options|=opts[i].bit;
		  if(opts[i].value)
		    *opts[i].value=argsplit(tok);
		}
	      break;
	    }
	}

      if(!opts[i].name)
	{
	  if(noisy)
	    log_info(_("unknown option '%s'\n"),otok);
	  return 0;
	}
    }

  return 1;
}


/* Similar to access(2), but uses PATH to find the file. */
int
path_access(const char *file,int mode)
{
  char *envpath;
  int ret=-1;

  envpath=getenv("PATH");

  if(!envpath
#ifdef HAVE_DRIVE_LETTERS
     || (((file[0]>='A' && file[0]<='Z')
	  || (file[0]>='a' && file[0]<='z'))
	 && file[1]==':')
#else
     || file[0]=='/'
#endif
     )
    return access(file,mode);
  else
    {
      /* At least as large as, but most often larger than we need. */
      char *buffer=xmalloc(strlen(envpath)+1+strlen(file)+1);
      char *split,*item,*path=xstrdup(envpath);

      split=path;

      while((item=strsep(&split,PATHSEP_S)))
	{
	  strcpy(buffer,item);
	  strcat(buffer,"/");
	  strcat(buffer,file);
	  ret=access(buffer,mode);
	  if(ret==0)
	    break;
	}

      xfree(path);
      xfree(buffer);
    }

  return ret;
}



/* Return the number of public key parameters as used by OpenPGP.  */
int
pubkey_get_npkey (pubkey_algo_t algo)
{
  switch (algo)
    {
    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_E:
    case PUBKEY_ALGO_RSA_S:     return 2;
    case PUBKEY_ALGO_ELGAMAL_E: return 3;
    case PUBKEY_ALGO_DSA:       return 4;
    case PUBKEY_ALGO_ECDH:      return 3;
    case PUBKEY_ALGO_ECDSA:     return 2;
    case PUBKEY_ALGO_ELGAMAL:   return 3;
    case PUBKEY_ALGO_EDDSA:     return 2;
    default: return 0;
    }
}


/* Return the number of secret key parameters as used by OpenPGP.  */
int
pubkey_get_nskey (pubkey_algo_t algo)
{
  switch (algo)
    {
    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_E:
    case PUBKEY_ALGO_RSA_S:     return 6;
    case PUBKEY_ALGO_ELGAMAL_E: return 4;
    case PUBKEY_ALGO_DSA:       return 5;
    case PUBKEY_ALGO_ECDH:      return 4;
    case PUBKEY_ALGO_ECDSA:     return 3;
    case PUBKEY_ALGO_ELGAMAL:   return 4;
    case PUBKEY_ALGO_EDDSA:     return 3;
    default: return 0;
    }
}

/* Temporary helper. */
int
pubkey_get_nsig (pubkey_algo_t algo)
{
  switch (algo)
    {
    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_E:
    case PUBKEY_ALGO_RSA_S:     return 1;
    case PUBKEY_ALGO_ELGAMAL_E: return 0;
    case PUBKEY_ALGO_DSA:       return 2;
    case PUBKEY_ALGO_ECDH:      return 0;
    case PUBKEY_ALGO_ECDSA:     return 2;
    case PUBKEY_ALGO_ELGAMAL:   return 2;
    case PUBKEY_ALGO_EDDSA:     return 2;
    default: return 0;
    }
}


/* Temporary helper. */
int
pubkey_get_nenc (pubkey_algo_t algo)
{
  switch (algo)
    {
    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_E:
    case PUBKEY_ALGO_RSA_S:     return 1;
    case PUBKEY_ALGO_ELGAMAL_E: return 2;
    case PUBKEY_ALGO_DSA:       return 0;
    case PUBKEY_ALGO_ECDH:      return 2;
    case PUBKEY_ALGO_ECDSA:     return 0;
    case PUBKEY_ALGO_ELGAMAL:   return 2;
    case PUBKEY_ALGO_EDDSA:     return 0;
    default: return 0;
    }
}


/* Temporary helper. */
unsigned int
pubkey_nbits( int algo, gcry_mpi_t *key )
{
  int rc, nbits;
  gcry_sexp_t sexp;

  if (algo == PUBKEY_ALGO_DSA
      && key[0] && key[1] && key[2] && key[3])
    {
      rc = gcry_sexp_build (&sexp, NULL,
                            "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                            key[0], key[1], key[2], key[3] );
    }
  else if ((algo == PUBKEY_ALGO_ELGAMAL || algo == PUBKEY_ALGO_ELGAMAL_E)
           && key[0] && key[1] && key[2])
    {
      rc = gcry_sexp_build (&sexp, NULL,
                            "(public-key(elg(p%m)(g%m)(y%m)))",
                            key[0], key[1], key[2] );
    }
  else if (is_RSA (algo)
           && key[0] && key[1])
    {
      rc = gcry_sexp_build (&sexp, NULL,
                            "(public-key(rsa(n%m)(e%m)))",
                            key[0], key[1] );
    }
  else if ((algo == PUBKEY_ALGO_ECDSA || algo == PUBKEY_ALGO_ECDH
            || algo == PUBKEY_ALGO_EDDSA)
           && key[0] && key[1])
    {
      char *curve = openpgp_oid_to_str (key[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = gcry_sexp_build (&sexp, NULL,
                                "(public-key(ecc(curve%s)(q%m)))",
                                curve, key[1]);
          xfree (curve);
        }
    }
  else
    return 0;

  if (rc)
    BUG ();

  nbits = gcry_pk_get_nbits (sexp);
  gcry_sexp_release (sexp);
  return nbits;
}



int
mpi_print (estream_t fp, gcry_mpi_t a, int mode)
{
  int n = 0;
  size_t nwritten;

  if (!a)
    return es_fprintf (fp, "[MPI_NULL]");
  if (!mode)
    {
      unsigned int n1;
      n1 = gcry_mpi_get_nbits(a);
      n += es_fprintf (fp, "[%u bits]", n1);
    }
  else if (gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    {
      unsigned int nbits;
      unsigned char *p = gcry_mpi_get_opaque (a, &nbits);
      if (!p)
        n += es_fprintf (fp, "[invalid opaque value]");
      else
        {
          if (!es_write_hexstring (fp, p, (nbits + 7)/8, 0, &nwritten))
            n += nwritten;
        }
    }
  else
    {
      unsigned char *buffer;
      size_t buflen;

      if (gcry_mpi_aprint (GCRYMPI_FMT_USG, &buffer, &buflen, a))
        BUG ();
      if (!es_write_hexstring (fp, buffer, buflen, 0, &nwritten))
        n += nwritten;
      gcry_free (buffer);
    }
  return n;
}


/* pkey[1] or skey[1] is Q for ECDSA, which is an uncompressed point,
   i.e.  04 <x> <y> */
unsigned int
ecdsa_qbits_from_Q (unsigned int qbits)
{
  if ((qbits%8) > 3)
    {
      log_error (_("ECDSA public key is expected to be in SEC encoding "
                   "multiple of 8 bits\n"));
      return 0;
    }
  qbits -= qbits%8;
  qbits /= 2;
  return qbits;
}


/* Ignore signatures and certifications made over certain digest
 * algorithms by default, MD5 is considered weak.  This allows users
 * to deprecate support for other algorithms as well.
 */
void
additional_weak_digest (const char* digestname)
{
  struct weakhash *weak = NULL;
  const enum gcry_md_algos algo = string_to_digest_algo(digestname);

  if (algo == GCRY_MD_NONE)
    {
      log_error (_("unknown weak digest '%s'\n"), digestname);
      return;
    }

  /* Check to ensure it's not already present.  */
  for (weak = opt.weak_digests; weak; weak = weak->next)
    if (algo == weak->algo)
      return;

  /* Add it to the head of the list.  */
  weak = xmalloc(sizeof(*weak));
  weak->algo = algo;
  weak->rejection_shown = 0;
  weak->next = opt.weak_digests;
  opt.weak_digests = weak;
}


/* Return true if ALGO is in the list of weak digests.  */
int
is_weak_digest (digest_algo_t algo)
{
  const enum gcry_md_algos galgo = map_md_openpgp_to_gcry (algo);
  const struct weakhash *weak;

  for (weak = opt.weak_digests; weak; weak = weak->next)
    if (weak->algo == galgo)
      return 1;
  return 0;
}
