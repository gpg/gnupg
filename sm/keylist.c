/* keylist.c
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>

#include <gcrypt.h>
#include <ksba.h>

#include "gpgsm.h"
#include "keydb.h"




static void
print_key_data (KsbaCert cert, FILE *fp)
{
#if 0  
  int n = pk ? pubkey_get_npkey( pk->pubkey_algo ) : 0;
  int i;

  for(i=0; i < n; i++ ) 
    {
      fprintf (fp, "pkd:%d:%u:", i, mpi_get_nbits( pk->pkey[i] ) );
      mpi_print(stdout, pk->pkey[i], 1 );
      putchar(':');
      putchar('\n');
    }
#endif
}

static void
print_capabilities (KsbaCert cert, FILE *fp)
{
  putc ('e', fp);
  putc ('s', fp);
  putc ('c', fp);
  putc ('E', fp);
  putc ('S', fp);
  putc ('C', fp);
  putc (':', fp);
}


static void
print_time (time_t t, FILE *fp)
{
  if (!t)
    ;
  else if ( t == (time_t)(-1) )
    putc ('?', fp);
  else
    fprintf (fp, "%lu", (unsigned long)t);
}


/* return an allocated string with the email address extracted from a
   DN */
static char *
email_kludge (const char *name)
{
  const unsigned char *p;
  unsigned char *buf;
  int n;

  if (strncmp (name, "1.2.840.113549.1.9.1=#", 22))
    return NULL;
  /* This looks pretty much like an email address in the subject's DN
     we use this to add an additional user ID entry.  This way,
     openSSL generated keys get a nicer and usable listing */
  name += 22;    
  for (n=0, p=name; hexdigitp (p) && hexdigitp (p+1); p +=2, n++)
    ;
  if (*p != '#' || !n)
    return NULL;
  buf = xtrymalloc (n+3);
  if (!buf)
    return NULL; /* oops, out of core */
  *buf = '<';
  for (n=1, p=name; *p != '#'; p +=2, n++)
    buf[n] = xtoi_2 (p);
  buf[n++] = '>';
  buf[n] = 0;
  return buf;
}




/* List one certificate in colon mode */
static void
list_cert_colon (KsbaCert cert, FILE *fp, int have_secret)
{
  int idx, trustletter = 0;
  char *p;
  KsbaSexp sexp;

  fputs (have_secret? "crs:":"crt:", fp);
  trustletter = 0;
#if 0
  if (is_not_valid (cert))
    putc ('i', fp);
  else if ( is_revoked (cert) )
    putc ('r', fp);
  else if ( has_expired (cert))
    putcr ('e', fp);
  else
#endif
    {
      trustletter = '?'; /*get_validity_info ( pk, NULL );*/
      putc (trustletter, fp);
    }

  fprintf (fp, ":%u:%d::",
           /*keylen_of_cert (cert)*/1024,
           /* pubkey_algo_of_cert (cert)*/'R');

  /* we assume --fixed-list-mode for gpgsm */
  print_time ( ksba_cert_get_validity (cert, 0), fp);
  putc (':', fp);
  print_time ( ksba_cert_get_validity (cert, 1), fp);
  putc (':', fp);
  putc (':', fp);
  if ((sexp = ksba_cert_get_serial (cert)))
    {
      int len;
      const unsigned char *s = sexp;
      
      if (*s == '(')
        {
          s++;
          for (len=0; *s && *s != ':' && digitp (s); s++)
            len = len*10 + atoi_1 (s);
          if (*s == ':')
            for (s++; len; len--, s++)
              fprintf (fp,"%02X", *s);
        }
      xfree (sexp);
    }
  putc (':', fp);
  putc (':', fp);
  if ((p = ksba_cert_get_issuer (cert,0)))
    {
      fputs (p, fp);  /* FIXME: Escape colons and linefeeds */
      xfree (p);
    }
  putc (':', fp);
  print_capabilities (cert, fp);
  putc ('\n', fp);

  p = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  fprintf (fp, "fpr:::::::::%s:\n", p);
  xfree (p);
  if (opt.with_key_data)
    {
      if ( (p = gpgsm_get_keygrip_hexstring (cert)))
        {
          fprintf (fp, "grp:::::::::%s:\n", p);
          xfree (p);
        }
      print_key_data (cert, fp);
    }

  for (idx=0; (p = ksba_cert_get_subject (cert,idx)); idx++)
    {
      fprintf (fp, "uid:%c::::::::", trustletter);
      fputs (p, fp);  /* FIXME: Escape colons and linefeeds */
      putc (':', fp);
      putc (':', fp);
      putc ('\n', fp);
      if (!idx)
        {
          /* It would be better to get the faked email address from
             the keydb.  But as long as we don't have a way to pass
             the meta data back, we just check it the same way as the
             code used to create the keybox meta data does */
          char *pp = email_kludge (p);
          if (pp)
            {
              fprintf (fp, "uid:%c::::::::", trustletter);
              fputs (pp, fp);  /* FIXME: Escape colons and linefeeds */
              putc (':', fp);
              putc (':', fp);
              putc ('\n', fp);
              xfree (pp);
            }
        }
      xfree (p);
    }
}




/* List all keys or just the key given as NAMES.
   MODE controls the operation mode: 
      0 = list all public keys but don't flag secret ones
      1 = list only public keys
      2 = list only secret keys
      3 = list secret and public keys
 */
void
gpgsm_list_keys (CTRL ctrl, STRLIST names, FILE *fp, unsigned int mode)
{
  KEYDB_HANDLE hd;
  KsbaCert cert = NULL;
  int rc=0;
  const char *lastresname, *resname;
  int have_secret;

  hd = keydb_new (0);
  if (!hd)
    rc = GNUPG_General_Error;
  else
    rc = keydb_search_first (hd);
  if (rc)
    {
      if (rc != -1)
        log_error ("keydb_search_first failed: %s\n", gnupg_strerror (rc) );
      goto leave;
    }

  lastresname = NULL;
  do
    {
      rc = keydb_get_cert (hd, &cert);
      if (rc) 
        {
          log_error ("keydb_get_cert failed: %s\n", gnupg_strerror (rc));
          goto leave;
        }
      
      resname = keydb_get_resource_name (hd);
      
      if (lastresname != resname ) 
        {
          int i;
          
          if (ctrl->no_server)
            {
              fprintf (fp, "%s\n", resname );
              for (i=strlen(resname); i; i-- )
                putchar('-');
              putc ('\n', fp);
              lastresname = resname;
            }
        }

      have_secret = 0;
      if (mode)
        {
          char *p = gpgsm_get_keygrip_hexstring (cert);
          if (p)
            {
              if (!gpgsm_agent_havekey (p))
                have_secret = 1;
              xfree (p);
            }
        }

      if (!mode
          || ((mode & 1) && !have_secret)
          || ((mode & 2) && have_secret)  )
        {
          if (ctrl->with_colons)
            list_cert_colon (cert, fp, have_secret);
          else
            list_cert_colon (cert, fp, have_secret);
        }
      ksba_cert_release (cert); 
      cert = NULL;
    }
  while (!(rc = keydb_search_next (hd)));
  if (rc && rc != -1)
    log_error ("keydb_search_next failed: %s\n", gnupg_strerror (rc));
  
 leave:
  ksba_cert_release (cert);
  keydb_release (hd);
}

