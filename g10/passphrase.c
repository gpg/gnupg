/* passphrase.c -  Get a passphrase
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005, 2006, 2007, 2009 Free Software Foundation, Inc.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif

#include "gpg.h"
#include "util.h"
#include "options.h"
#include "ttyio.h"
#include "cipher.h"
#include "keydb.h"
#include "main.h"
#include "i18n.h"
#include "status.h"
#include "call-agent.h"


static char *fd_passwd = NULL;
static char *next_pw = NULL;
static char *last_pw = NULL;



/* Pack an s2k iteration count into the form specified in 2440.  If
   we're in between valid values, round up.  With value 0 return the
   old default.  */
unsigned char
encode_s2k_iterations (int iterations)
{
  gpg_error_t err;
  unsigned char c=0;
  unsigned char result;
  unsigned int count;

  if (!iterations)
    {
      unsigned long mycnt;

      /* Ask the gpg-agent for a useful iteration count.  */
      err = agent_get_s2k_count (&mycnt);
      if (err || mycnt < 65536)
        {
          /* Don't print an error if an older agent is used.  */
          if (err && gpg_err_code (err) != GPG_ERR_ASS_PARAMETER)
            log_error (_("problem with the agent: %s\n"), gpg_strerror (err));
          /* Default to 65536 which we used up to 2.0.13.  */
          return 96; 
        }
      else if (mycnt >= 65011712)
        return 255; /* Largest possible value.  */
      else
        return encode_s2k_iterations ((int)mycnt);
    }

  if (iterations <= 1024)
    return 0;  /* Command line arg compatibility.  */

  if (iterations >= 65011712)
    return 255;
  
  /* Need count to be in the range 16-31 */
  for (count=iterations>>6; count>=32; count>>=1)
    c++;

  result = (c<<4)|(count-16);

  if (S2K_DECODE_COUNT(result) < iterations)
    result++;
  
  return result;
}



/* Hash a passphrase using the supplied s2k. 
   Always needs: dek->algo, s2k->mode, s2k->hash_algo.  */
static void
hash_passphrase ( DEK *dek, char *pw, STRING2KEY *s2k)
{
  gcry_md_hd_t md;
  int pass, i;
  int used = 0;
  int pwlen = strlen(pw);

  assert ( s2k->hash_algo );
  dek->keylen = openpgp_cipher_get_algo_keylen (dek->algo);
  if ( !(dek->keylen > 0 && dek->keylen <= DIM(dek->key)) )
    BUG();

  if (gcry_md_open (&md, s2k->hash_algo, 1))
    BUG ();
  for (pass=0; used < dek->keylen ; pass++ ) 
    {
      if ( pass ) 
        {
          gcry_md_reset (md);
          for (i=0; i < pass; i++ ) /* Preset the hash context.  */
            gcry_md_putc (md, 0 );
	}

      if ( s2k->mode == 1 || s2k->mode == 3 ) 
        {
          int len2 = pwlen + 8;
          ulong count = len2;
          
          if ( s2k->mode == 3 )
            {
              count = S2K_DECODE_COUNT(s2k->count);
              if ( count < len2 )
                count = len2;
	    }

          /* Fixme: To avoid DoS attacks by sending an sym-encrypted
             packet with a very high S2K count, we should either cap
             the iteration count or CPU seconds based timeout.  */

          /* A little bit complicated because we need a ulong for count. */
          while ( count > len2 )  /* maybe iterated+salted */
            { 
              gcry_md_write ( md, s2k->salt, 8 );
              gcry_md_write ( md, pw, pwlen );
              count -= len2;
	    }
          if ( count < 8 )
            gcry_md_write ( md, s2k->salt, count );
          else
            {
              gcry_md_write ( md, s2k->salt, 8 );
              count -= 8;
              gcry_md_write ( md, pw, count );
	    }
	}
      else
        gcry_md_write ( md, pw, pwlen );
      gcry_md_final( md );

      i = gcry_md_get_algo_dlen ( s2k->hash_algo );
      if ( i > dek->keylen - used )
        i = dek->keylen - used;

      memcpy (dek->key+used, gcry_md_read (md, s2k->hash_algo), i);
      used += i;
    }
  gcry_md_close(md);
}



int
have_static_passphrase()
{
  return !!fd_passwd && opt.batch;
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
get_last_passphrase()
{
  char *p = last_pw;
  last_pw = NULL;
  return p;
}

/* As if we had used the passphrase - make it the last_pw. */
void
next_to_last_passphrase(void)
{
  if (next_pw)
    {
      last_pw=next_pw;
      next_pw=NULL;
    }
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

  if ( !opt.batch ) 
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
  if (!opt.batch)
    tty_printf("\b\b\b   \n" );

  xfree ( fd_passwd );
  fd_passwd = pw;
}


/*
 * Ask the GPG Agent for the passphrase.
 * Mode 0:  Allow cached passphrase
 *      1:  No cached passphrase; that is we are asking for a new passphrase
 *          FIXME: Only partially implemented
 *
 * Note that TRYAGAIN_TEXT must not be translated.  If CANCELED is not
 * NULL, the function does set it to 1 if the user canceled the
 * operation.  If CACHEID is not NULL, it will be used as the cacheID
 * for the gpg-agent; if is NULL and a key fingerprint can be
 * computed, this will be used as the cacheid.
 */
static char *
passphrase_get ( u32 *keyid, int mode, const char *cacheid, int repeat,
                 const char *tryagain_text,
                 const char *custom_description,
                 const char *custom_prompt, int *canceled)
{
  int rc;
  char *atext = NULL;
  char *pw = NULL;
  PKT_public_key *pk = xmalloc_clear( sizeof *pk );
  byte fpr[MAX_FINGERPRINT_LEN];
  int have_fpr = 0;
  char *orig_codeset;
  char *my_prompt;
  char hexfprbuf[20*2+1];
  const char *my_cacheid;
  int check = (mode == 1);

  if (canceled)
    *canceled = 0;

#if MAX_FINGERPRINT_LEN < 20
#error agent needs a 20 byte fingerprint
#endif

  memset (fpr, 0, MAX_FINGERPRINT_LEN );
  if( keyid && get_pubkey( pk, keyid ) )
    {
      if (pk)
        free_public_key( pk );      
      pk = NULL; /* oops: no key for some reason */
    }
  
  orig_codeset = i18n_switchto_utf8 ();

  if (custom_description)
    atext = native_to_utf8 (custom_description);
  else if ( !mode && pk && keyid )
    { 
      char *uid;
      size_t uidlen;
      const char *algo_name = gcry_pk_algo_name ( pk->pubkey_algo );
      const char *timestr;
      char *maink;
      
      if ( !algo_name )
        algo_name = "?";

#define KEYIDSTRING _(" (main key ID %s)")

      maink = xmalloc ( strlen (KEYIDSTRING) + keystrlen() + 20 );
      if( keyid[2] && keyid[3] && keyid[0] != keyid[2] 
          && keyid[1] != keyid[3] )
        sprintf( maink, KEYIDSTRING, keystr(&keyid[2]) );
      else
        *maink = 0;
      
      uid = get_user_id ( keyid, &uidlen ); 
      timestr = strtimestamp (pk->timestamp);

#undef KEYIDSTRING

#define PROMPTSTRING _("Please enter the passphrase to unlock the" \
		       " secret key for the OpenPGP certificate:\n" \
		       "\"%.*s\"\n" \
		       "%u-bit %s key, ID %s,\n" \
                       "created %s%s.\n" )

      atext = xmalloc ( 100 + strlen (PROMPTSTRING)  
                        + uidlen + 15 + strlen(algo_name) + keystrlen()
                        + strlen (timestr) + strlen (maink) );
      sprintf (atext, PROMPTSTRING,
               (int)uidlen, uid,
               nbits_from_pk (pk), algo_name, keystr(&keyid[0]), timestr,
               maink  );
      xfree (uid);
      xfree (maink);

#undef PROMPTSTRING

      { 
        size_t dummy;
        fingerprint_from_pk( pk, fpr, &dummy );
        have_fpr = 1;
      }
      
    }
  else
    atext = xstrdup ( _("Enter passphrase\n") );
                

  if (!mode && cacheid)
    my_cacheid = cacheid;
  else if (!mode && have_fpr)
    my_cacheid = bin2hex (fpr, 20, hexfprbuf);
  else
    my_cacheid = NULL;

  if (tryagain_text)
    tryagain_text = _(tryagain_text);

  my_prompt = custom_prompt ? native_to_utf8 (custom_prompt): NULL;

  rc = agent_get_passphrase (my_cacheid, tryagain_text, my_prompt, atext,
                             repeat, check, &pw);
  
  xfree (my_prompt);
  xfree (atext); atext = NULL;

  i18n_switchback (orig_codeset);


  if (!rc)
    ;
  else if ( gpg_err_code (rc) == GPG_ERR_CANCELED )
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

      write_status_error ("get_passphrase", rc);
    }

  if (pk)
    free_public_key( pk );
  if (rc)
    {
      xfree (pw);
      return NULL;
    }
  return pw;
}


/*
 * Clear the cached passphrase.  If CACHEID is not NULL, it will be
 * used instead of a cache ID derived from KEYID.
 */
void
passphrase_clear_cache ( u32 *keyid, const char *cacheid, int algo )
{
  int rc;

  (void)algo;
    
  if (!cacheid)
    {
      PKT_public_key *pk;
#     if MAX_FINGERPRINT_LEN < 20
#       error agent needs a 20 byte fingerprint
#     endif
      byte fpr[MAX_FINGERPRINT_LEN];
      char hexfprbuf[2*20+1];
      size_t dummy;
      
      pk = xcalloc (1, sizeof *pk);
      if ( !keyid || get_pubkey( pk, keyid ) )
        {
          log_error ("key not found in passphrase_clear_cache\n");
          free_public_key (pk);
          return;
        }
      memset (fpr, 0, MAX_FINGERPRINT_LEN );
      fingerprint_from_pk ( pk, fpr, &dummy );
      bin2hex (fpr, 20, hexfprbuf);
      rc = agent_clear_passphrase (hexfprbuf);
      free_public_key ( pk );
    }
  else
    rc = agent_clear_passphrase (cacheid);

  if (rc)
    log_error (_("problem with the agent: %s\n"), gpg_strerror (rc));
}


/* Return a new DEK object Using the string-to-key sepcifier S2K.  Use
   KEYID and PUBKEY_ALGO to prompt the user.  Returns NULL is the user
   selected to cancel the passphrase entry and if CANCELED is not
   NULL, sets it to true.

   MODE 0:  Allow cached passphrase
        1:  Ignore cached passphrase 
        2:  Ditto, but create a new key
        3:  Allow cached passphrase; use the S2K salt as the cache ID
        4:  Ditto, but create a new key
*/
DEK *
passphrase_to_dek_ext (u32 *keyid, int pubkey_algo,
                       int cipher_algo, STRING2KEY *s2k, int mode,
                       const char *tryagain_text, 
                       const char *custdesc, const char *custprompt,
                       int *canceled)
{
  char *pw = NULL;
  DEK *dek;
  STRING2KEY help_s2k;
  int dummy_canceled;
  char s2k_cacheidbuf[1+16+1], *s2k_cacheid = NULL;

  if (!canceled)
    canceled = &dummy_canceled;
  *canceled = 0;
  
  if ( !s2k )
    {
      assert (mode != 3 && mode != 4);
      /* This is used for the old rfc1991 mode 
       * Note: This must match the code in encode.c with opt.rfc1991 set */
      s2k = &help_s2k;
      s2k->mode = 0;
      s2k->hash_algo = S2K_DIGEST_ALGO;
    }

  /* Create a new salt or what else to be filled into the s2k for a
     new key.  */
  if ((mode == 2 || mode == 4) && (s2k->mode == 1 || s2k->mode == 3))
    {
      gcry_randomize (s2k->salt, 8, GCRY_STRONG_RANDOM);
      if ( s2k->mode == 3 )
        {
          /* We delay the encoding until it is really needed.  This is
             if we are going to dynamically calibrate it, we need to
             call out to gpg-agent and that should not be done during
             option processing in main().  */
          if (!opt.s2k_count)
            opt.s2k_count = encode_s2k_iterations (0);
          s2k->count = opt.s2k_count;
        }
    }

  /* If we do not have a passphrase available in NEXT_PW and status
     information are request, we print them now. */
  if ( !next_pw && is_status_enabled() ) 
    {
      char buf[50];
      
      if ( keyid )
        {
          u32 used_kid[2];
          char *us;
          
          if ( keyid[2] && keyid[3] ) 
            {
              used_kid[0] = keyid[2];
              used_kid[1] = keyid[3];
            }
          else
            {
              used_kid[0] = keyid[0];
              used_kid[1] = keyid[1];
            }
          
          us = get_long_user_id_string ( keyid );
          write_status_text ( STATUS_USERID_HINT, us );
          xfree(us);
          
          snprintf (buf, sizeof buf -1, "%08lX%08lX %08lX%08lX %d 0",
                    (ulong)keyid[0], (ulong)keyid[1],
                    (ulong)used_kid[0], (ulong)used_kid[1],
                    pubkey_algo );
          
          write_status_text ( STATUS_NEED_PASSPHRASE, buf );
	}
      else
        {
          snprintf (buf, sizeof buf -1, "%d %d %d",
                    cipher_algo, s2k->mode, s2k->hash_algo );
          write_status_text ( STATUS_NEED_PASSPHRASE_SYM, buf );
	}
    }

  /* If we do have a keyID, we do not have a passphrase available in
     NEXT_PW, we are not running in batch mode and we do not want to
     ignore the passphrase cache (mode!=1), print a prompt with
     information on that key. */
  if ( keyid && !opt.batch && !next_pw && mode!=1 )
    {
      PKT_public_key *pk = xmalloc_clear( sizeof *pk );
      char *p;
      
      p = get_user_id_native(keyid);
      tty_printf ("\n");
      tty_printf (_("You need a passphrase to unlock the secret key for\n"
                    "user: \"%s\"\n"),p);
      xfree(p);

      if ( !get_pubkey( pk, keyid ) )
        {
          const char *s = gcry_pk_algo_name ( pk->pubkey_algo );
          
          tty_printf (_("%u-bit %s key, ID %s, created %s"),
                      nbits_from_pk( pk ), s?s:"?", keystr(keyid),
                      strtimestamp(pk->timestamp) );
          if ( keyid[2] && keyid[3]
               && keyid[0] != keyid[2] && keyid[1] != keyid[3] )
            {
              if ( keystrlen () > 10 )
                {
                  tty_printf ("\n");
                  tty_printf (_("         (subkey on main key ID %s)"),
                              keystr(&keyid[2]) );
                }
              else
                tty_printf ( _(" (main key ID %s)"), keystr(&keyid[2]) );
            }
          tty_printf("\n");
	}

      tty_printf("\n");
      if (pk)
        free_public_key( pk );
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
      if ((mode == 3 || mode == 4) && (s2k->mode == 1 || s2k->mode == 3))
	{
	  memset (s2k_cacheidbuf, 0, sizeof s2k_cacheidbuf);
	  *s2k_cacheidbuf = 'S';
	  bin2hex (s2k->salt, 8, s2k_cacheidbuf + 1);
	  s2k_cacheid = s2k_cacheidbuf;
	}

      /* Divert to the gpg-agent. */
      pw = passphrase_get (keyid, mode == 2, s2k_cacheid,
                           (mode == 2 || mode == 4)? opt.passphrase_repeat : 0,
                           tryagain_text, custdesc, custprompt, canceled);
      if (*canceled)
        {
          xfree (pw);
	  write_status( STATUS_MISSING_PASSPHRASE );
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
  if ( (!pw || !*pw) && (mode == 2 || mode == 4))
    dek->keylen = 0;
  else
    hash_passphrase (dek, pw, s2k);
  if (s2k_cacheid)
    memcpy (dek->s2k_cacheid, s2k_cacheid, sizeof dek->s2k_cacheid);
  xfree(last_pw);
  last_pw = pw;
  return dek;
}


DEK *
passphrase_to_dek (u32 *keyid, int pubkey_algo,
		   int cipher_algo, STRING2KEY *s2k, int mode,
                   const char *tryagain_text, int *canceled)
{
  return passphrase_to_dek_ext (keyid, pubkey_algo, cipher_algo,
                                s2k, mode, tryagain_text, NULL, NULL,
                                canceled);
}
