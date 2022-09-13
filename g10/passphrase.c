/* passphrase.c -  Get a passphrase
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005, 2006, 2007, 2009, 2011 Free Software Foundation, Inc.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif

#include "gpg.h"
#include "../common/util.h"
#include "options.h"
#include "../common/ttyio.h"
#include "keydb.h"
#include "main.h"
#include "../common/i18n.h"
#include "../common/status.h"
#include "call-agent.h"
#include "../common/shareddefs.h"

static char *fd_passwd = NULL;
static char *next_pw = NULL;
static char *last_pw = NULL;


int
have_static_passphrase (void)
{
  return (!!fd_passwd
          && (opt.batch || opt.pinentry_mode == PINENTRY_MODE_LOOPBACK));
}


/* Return a static passphrase.  The returned value is only valid as
   long as no other passphrase related function is called.  NULL may
   be returned if no passphrase has been set; better use
   have_static_passphrase first.  */
const char *
get_static_passphrase (void)
{
  return fd_passwd;
}


/****************
 * Set the passphrase to be used for the next query and only for the next
 * one.
 */
void
set_next_passphrase( const char *s )
{
  xfree(next_pw);
  next_pw = NULL;
  if ( s )
    {
      next_pw = xmalloc_secure( strlen(s)+1 );
      strcpy (next_pw, s );
    }
}

/****************
 * Get the last passphrase used in passphrase_to_dek.
 * Note: This removes the passphrase from this modules and
 * the caller must free the result.  May return NULL:
 */
char *
get_last_passphrase (void)
{
  char *p = last_pw;
  last_pw = NULL;
  return p;
}

/* Here's an interesting question: since this passphrase was passed in
   on the command line, is there really any point in using secure
   memory for it?  I'm going with 'yes', since it doesn't hurt, and
   might help in some small way (swapping). */

void
set_passphrase_from_string(const char *pass)
{
  xfree (fd_passwd);
  fd_passwd = xmalloc_secure(strlen(pass)+1);
  strcpy (fd_passwd, pass);
}


void
read_passphrase_from_fd( int fd )
{
  int i, len;
  char *pw;

  if (! gnupg_fd_valid (fd))
    log_fatal ("passphrase-fd is invalid: %s\n", strerror (errno));

  if ( !opt.batch && opt.pinentry_mode != PINENTRY_MODE_LOOPBACK)
    { /* Not used but we have to do a dummy read, so that it won't end
         up at the begin of the message if the quite usual trick to
         prepend the passphtrase to the message is used. */
      char buf[1];

      while (!(read (fd, buf, 1) != 1 || *buf == '\n' ))
        ;
      *buf = 0;
      return;
    }

  for (pw = NULL, i = len = 100; ; i++ )
    {
      if (i >= len-1 )
        {
          char *pw2 = pw;
          len += 100;
          pw = xmalloc_secure( len );
          if( pw2 )
            {
              memcpy(pw, pw2, i );
              xfree (pw2);
            }
          else
            i=0;
	}
      if (read( fd, pw+i, 1) != 1 || pw[i] == '\n' )
        break;
    }
  pw[i] = 0;
  if (!opt.batch && opt.pinentry_mode != PINENTRY_MODE_LOOPBACK)
    tty_printf("\b\b\b   \n" );

  xfree ( fd_passwd );
  fd_passwd = pw;
}


/*
 * Ask the GPG Agent for the passphrase.
 * If NOCACHE is set the symmetric passpharse caching will not be used.
 *
 * If REPEAT is positive, a new passphrase is requested and the agent
 * shall require REPEAT times repetitions of the entered passphrase.
 * This is used for symmetric encryption.
 *
 * Note that TRYAGAIN_TEXT must not be translated.  If CANCELED is not
 * NULL, the function does set it to 1 if the user canceled the
 * operation.  If CACHEID is not NULL, it will be used as the cacheID
 * for the gpg-agent; if is NULL and a key fingerprint can be
 * computed, this will be used as the cacheid.
 *
 * For FLAGS see passphrase_to_dek;
 */
static char *
passphrase_get (int newsymkey, int nocache, const char *cacheid, int repeat,
                const char *tryagain_text, unsigned int flags, int *canceled)
{
  int rc;
  char *pw = NULL;
  char *orig_codeset;
  const char *my_cacheid;
  const char *desc;

  if (canceled)
    *canceled = 0;

  orig_codeset = i18n_switchto_utf8 ();

  if (!nocache && cacheid)
    my_cacheid = cacheid;
  else
    my_cacheid = NULL;

  if (tryagain_text)
    tryagain_text = _(tryagain_text);

  if ((flags & GETPASSWORD_FLAG_SYMDECRYPT))
    desc = _("Please enter the passphrase for decryption.");
  else
    desc = _("Enter passphrase\n");

  /* Here we have:
   * REPEAT is set in create mode and if opt.passphrase_repeat is set.
   * (Thus it is not a clean indication that we want a new passphrase).
   * NOCACHE is set in create mode or if --no-symkey-cache is used.
   * CACHEID is only set if caching shall be used.
   * NEWSYMKEY has been added latter to make it clear that a new key
   * is requested.  The whole chain of API is a bit too complex since
   * we we stripped things out over time; however, there is no time
   * for a full state analysis and thus this new parameter.
   */
  rc = agent_get_passphrase (my_cacheid, tryagain_text, NULL,
                             desc,
                             newsymkey, repeat, nocache, &pw);

  i18n_switchback (orig_codeset);


  if (!rc)
    ;
  else if (gpg_err_code (rc) == GPG_ERR_CANCELED
            || gpg_err_code (rc) == GPG_ERR_FULLY_CANCELED)
    {
      log_info (_("cancelled by user\n") );
      if (canceled)
        *canceled = 1;
    }
  else
    {
      log_error (_("problem with the agent: %s\n"), gpg_strerror (rc));
      /* Due to limitations in the API of the upper layers they
         consider an error as no passphrase entered.  This works in
         most cases but not during key creation where this should
         definitely not happen and let it continue without requiring a
         passphrase.  Given that now all the upper layers handle a
         cancel correctly, we simply set the cancel flag now for all
         errors from the agent.  */
      if (canceled)
        *canceled = 1;

      write_status_errcode ("get_passphrase", rc);
    }

  if (rc)
    {
      xfree (pw);
      pw = NULL;
    }
  return pw;
}


/*
 * Clear the cached passphrase with CACHEID.
 */
void
passphrase_clear_cache (const char *cacheid)
{
  int rc;

  rc = agent_clear_passphrase (cacheid);
  if (rc)
    log_error (_("problem with the agent: %s\n"), gpg_strerror (rc));
}


/* Return a new DEK object using the string-to-key specifier S2K.
 * Returns NULL if the user canceled the passphrase entry and if
 * CANCELED is not NULL, sets it to true.
 *
 * If CREATE is true a new passphrase will be created.  If NOCACHE is
 * true the symmetric key caching will not be used.
 * FLAG bits are:
 *   GETPASSWORD_FLAG_SYMDECRYPT := for symmetric decryption
 */
DEK *
passphrase_to_dek (int cipher_algo, STRING2KEY *s2k,
                   int create, int nocache,
                   const char *tryagain_text, unsigned int flags,
                   int *canceled)
{
  char *pw = NULL;
  DEK *dek;
  STRING2KEY help_s2k;
  int dummy_canceled;
  char s2k_cacheidbuf[1+16+1];
  char *s2k_cacheid = NULL;

  if (!canceled)
    canceled = &dummy_canceled;
  *canceled = 0;

  if (opt.no_symkey_cache)
    nocache = 1;  /* Force no symmetric key caching.  */

  if ( !s2k )
    {
      log_assert (create && !nocache);
      /* This is used for the old rfc1991 mode
       * Note: This must match the code in encode.c with opt.rfc1991 set */
      memset (&help_s2k, 0, sizeof (help_s2k));
      s2k = &help_s2k;
      s2k->hash_algo = S2K_DIGEST_ALGO;
    }

  /* Create a new salt or what else to be filled into the s2k for a
     new key.  */
  if (create && (s2k->mode == 1 || s2k->mode == 3))
    {
      gcry_randomize (s2k->salt, 8, GCRY_STRONG_RANDOM);
      if ( s2k->mode == 3 )
        {
          /* We delay the encoding until it is really needed.  This is
             if we are going to dynamically calibrate it, we need to
             call out to gpg-agent and that should not be done during
             option processing in main().  */
          if (!opt.s2k_count)
            opt.s2k_count = encode_s2k_iterations (agent_get_s2k_count ());
          s2k->count = opt.s2k_count;
        }
    }

  /* If we do not have a passphrase available in NEXT_PW and status
     information are request, we print them now. */
  if ( !next_pw && is_status_enabled() )
    {
      char buf[50];

      snprintf (buf, sizeof buf, "%d %d %d",
                cipher_algo, s2k->mode, s2k->hash_algo );
      write_status_text ( STATUS_NEED_PASSPHRASE_SYM, buf );
    }

  if ( next_pw )
    {
      /* Simply return the passphrase we already have in NEXT_PW. */
      pw = next_pw;
      next_pw = NULL;
    }
  else if ( have_static_passphrase () )
    {
      /* Return the passphrase we have stored in FD_PASSWD. */
      pw = xmalloc_secure ( strlen(fd_passwd)+1 );
      strcpy ( pw, fd_passwd );
    }
  else
    {
      if (!nocache && (s2k->mode == 1 || s2k->mode == 3))
	{
	  memset (s2k_cacheidbuf, 0, sizeof s2k_cacheidbuf);
	  *s2k_cacheidbuf = 'S';
	  bin2hex (s2k->salt, 8, s2k_cacheidbuf + 1);
	  s2k_cacheid = s2k_cacheidbuf;
	}

      if (opt.pinentry_mode == PINENTRY_MODE_LOOPBACK)
        {
          char buf[32];

          snprintf (buf, sizeof (buf), "%u", 100);
          write_status_text (STATUS_INQUIRE_MAXLEN, buf);
        }

      /* Divert to the gpg-agent. */
      pw = passphrase_get (create, create && nocache, s2k_cacheid,
                           create? opt.passphrase_repeat : 0,
                           tryagain_text, flags, canceled);
      if (*canceled)
        {
          xfree (pw);
	  write_status( STATUS_CANCELED_BY_USER );
          return NULL;
        }
    }

  if ( !pw || !*pw )
    write_status( STATUS_MISSING_PASSPHRASE );

  /* Hash the passphrase and store it in a newly allocated DEK object.
     Keep a copy of the passphrase in LAST_PW for use by
     get_last_passphrase(). */
  dek = xmalloc_secure_clear ( sizeof *dek );
  dek->algo = cipher_algo;
  if ( (!pw || !*pw) && create)
    dek->keylen = 0;
  else
    {
      gpg_error_t err;

      dek->keylen = openpgp_cipher_get_algo_keylen (dek->algo);
      if (!(dek->keylen > 0 && dek->keylen <= DIM(dek->key)))
        BUG ();
      err = gcry_kdf_derive (pw, strlen (pw),
                             s2k->mode == 3? GCRY_KDF_ITERSALTED_S2K :
                             s2k->mode == 1? GCRY_KDF_SALTED_S2K :
                             /* */           GCRY_KDF_SIMPLE_S2K,
                             s2k->hash_algo, s2k->salt, 8,
                             S2K_DECODE_COUNT(s2k->count),
                             dek->keylen, dek->key);
      if (err)
        {
          log_error ("gcry_kdf_derive failed: %s", gpg_strerror (err));
          xfree (pw);
          xfree (dek);
	  write_status( STATUS_MISSING_PASSPHRASE );
          return NULL;
        }
    }
  if (s2k_cacheid)
    memcpy (dek->s2k_cacheid, s2k_cacheid, sizeof dek->s2k_cacheid);
  xfree(last_pw);
  last_pw = pw;
  return dek;
}


/* Emit the USERID_HINT and the NEED_PASSPHRASE status messages.
   MAINKEYID may be NULL. */
void
emit_status_need_passphrase (ctrl_t ctrl,
                             u32 *keyid, u32 *mainkeyid, int pubkey_algo)
{
  char buf[50];
  char *us;

  us = get_long_user_id_string (ctrl, keyid);
  write_status_text (STATUS_USERID_HINT, us);
  xfree (us);

  snprintf (buf, sizeof buf, "%08lX%08lX %08lX%08lX %d 0",
            (ulong)keyid[0],
            (ulong)keyid[1],
            (ulong)(mainkeyid? mainkeyid[0]:keyid[0]),
            (ulong)(mainkeyid? mainkeyid[1]:keyid[1]),
            pubkey_algo);

  write_status_text (STATUS_NEED_PASSPHRASE, buf);
}


/* Return an allocated utf-8 string describing the key PK.  If ESCAPED
   is true spaces and control characters are percent or plus escaped.
   MODE describes the use of the key description; use one of the
   FORMAT_KEYDESC_ macros. */
char *
gpg_format_keydesc (ctrl_t ctrl, PKT_public_key *pk, int mode, int escaped)
{
  char *uid;
  size_t uidlen;
  const char *algo_name;
  const char *timestr;
  char *orig_codeset;
  char *maink;
  char *desc;
  const char *prompt;
  const char *trailer = "";
  int is_subkey;

  if (mode == FORMAT_KEYDESC_KEYGRIP)
    {
      is_subkey = 0;
      algo_name = NULL;
      timestr = NULL;
      uid = NULL;
    }
  else
    {
      is_subkey = (pk->main_keyid[0] && pk->main_keyid[1]
                   && pk->keyid[0] != pk->main_keyid[0]
                   && pk->keyid[1] != pk->main_keyid[1]);
      algo_name = openpgp_pk_algo_name (pk->pubkey_algo);
      timestr = strtimestamp (pk->timestamp);
      uid = get_user_id (ctrl, is_subkey? pk->main_keyid:pk->keyid,
                         &uidlen, NULL);
    }

  orig_codeset = i18n_switchto_utf8 ();

  if (is_subkey)
    maink = xtryasprintf (_(" (main key ID %s)"), keystr (pk->main_keyid));
  else
    maink = NULL;

  switch (mode)
    {
    case FORMAT_KEYDESC_NORMAL:
      prompt = _("Please enter the passphrase to unlock the"
                 " OpenPGP secret key:");
      break;
    case FORMAT_KEYDESC_IMPORT:
      prompt = _("Please enter the passphrase to import the"
                 " OpenPGP secret key:");
      break;
    case FORMAT_KEYDESC_EXPORT:
      if (is_subkey)
        prompt = _("Please enter the passphrase to export the"
                   " OpenPGP secret subkey:");
      else
        prompt = _("Please enter the passphrase to export the"
                   " OpenPGP secret key:");
      break;
    case FORMAT_KEYDESC_DELKEY:
      if (is_subkey)
        prompt = _("Do you really want to permanently delete the"
                   " OpenPGP secret subkey key:");
      else
        prompt = _("Do you really want to permanently delete the"
                   " OpenPGP secret key:");
      trailer = "?";
      break;
    case FORMAT_KEYDESC_KEYGRIP:
      prompt = _("Please enter the passphrase to export the"
                 " secret key with keygrip:");
      break;
    default:
      prompt = "?";
      break;
    }

  if (mode == FORMAT_KEYDESC_KEYGRIP)
    desc = xtryasprintf ("%s\n\n"
                         "   %s\n",
                         prompt,
                         "<keygrip>");
  else
    desc = xtryasprintf (_("%s\n"
                           "\"%.*s\"\n"
                           "%u-bit %s key, ID %s,\n"
                           "created %s%s.\n%s"),
                         prompt,
                         (int)uidlen, uid,
                         nbits_from_pk (pk), algo_name,
                         keystr (pk->keyid), timestr,
                         maink?maink:"", trailer);
  xfree (maink);
  xfree (uid);

  i18n_switchback (orig_codeset);

  if (escaped)
    {
      char *tmp = percent_plus_escape (desc);
      xfree (desc);
      desc = tmp;
    }

  return desc;
}
