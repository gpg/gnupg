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



/* List one certificate in colon mode */
static void
list_cert_colon (KsbaCert cert, FILE *fp)
{
  int trustletter = 0;
  char *p;

  fputs ("crt:", fp);
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

  fprintf (fp, ":%u:%d::%s:%s:::",
           /*keylen_of_cert (cert)*/1024,
           /* pubkey_algo_of_cert (cert)*/'R',
           /*colon_datestr_from_cert (cert)*/ "2001-11-11",
           /*colon_strtime_expire (cert)*/ "2001-11-12" );
    
  putc (':', fp);
  /* fixme: should we print the issuer name here? */
  putc (':', fp);
  print_capabilities (cert, fp);
  putc ('\n', fp);
  p = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  fprintf (fp, "fpr:::::::::%s:\n", p);
  xfree (p);
  if (opt.with_key_data)
    print_key_data (cert, fp);

  fprintf (fp, "uid:%c::::::::", trustletter);
  p = ksba_cert_get_subject (cert);
  if (p)
    fputs (p, fp);  /* FIXME: Escape colons and linefeeds */
  xfree (p);
  putc (':', fp);
  putc (':', fp);
  putc ('\n', fp);
}




/* List all keys or just the key given as NAMES */
void
gpgsm_list_keys (CTRL ctrl, STRLIST names, FILE *fp)
{
  KEYDB_HANDLE hd;
  KsbaCert cert = NULL;
  int rc=0;
  const char *lastresname, *resname;

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
          if (ctrl->with_colons)
            list_cert_colon (cert, fp);
          else
            list_cert_colon (cert, fp);
          ksba_cert_release (cert); 
          cert = NULL;
        } 
    }
  while (!(rc = keydb_search_next (hd)));
  if (rc && rc != -1)
    log_error ("keydb_search_next failed: %s\n", gnupg_strerror (rc));
  
 leave:
  ksba_cert_release (cert);
  keydb_release (hd);
}

