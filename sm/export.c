/* export.c
 * Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"

static void print_short_info (ksba_cert_t cert, FILE *fp);



/* Export all certificates or just those given in NAMES. */
void
gpgsm_export (CTRL ctrl, STRLIST names, FILE *fp)
{
  KEYDB_HANDLE hd;
  KEYDB_SEARCH_DESC *desc = NULL;
  int ndesc;
  Base64Context b64writer = NULL;
  ksba_writer_t writer;
  STRLIST sl;
  ksba_cert_t cert = NULL;
  int rc=0;
  int count = 0;
  int i;

  hd = keydb_new (0);
  if (!hd)
    {
      log_error ("keydb_new failed\n");
      goto leave;
    }

  if (!names)
    ndesc = 1;
  else
    {
      for (sl=names, ndesc=0; sl; sl = sl->next, ndesc++) 
        ;
    }

  desc = xtrycalloc (ndesc, sizeof *desc);
  if (!ndesc)
    {
      log_error ("allocating memory for export failed: %s\n",
                 gpg_strerror (OUT_OF_CORE (errno)));
      goto leave;
    }

  if (!names)
    desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
  else 
    {
      for (ndesc=0, sl=names; sl; sl = sl->next) 
        {
          rc = keydb_classify_name (sl->d, desc+ndesc);
          if (rc)
            {
              log_error ("key `%s' not found: %s\n",
                         sl->d, gpg_strerror (rc));
              rc = 0;
            }
          else
            ndesc++;
        }
    }

  /* If all specifications are done by fingerprint, we switch to
     ephemeral mode so that _all_ currently available and matching
     certificates are exported. 

     fixme: we should in this case keep a list of certificates to
     avoid accidential export of duplicate certificates. */
  if (names && ndesc)
    {
      for (i=0; (i < ndesc
                 && (desc[i].mode == KEYDB_SEARCH_MODE_FPR
                     || desc[i].mode == KEYDB_SEARCH_MODE_FPR20
                     || desc[i].mode == KEYDB_SEARCH_MODE_FPR16)); i++)
        ;
      if (i == ndesc)
        keydb_set_ephemeral (hd, 1);
    }
      
  while (!(rc = keydb_search (hd, desc, ndesc)))
    {
      const unsigned char *image;
      size_t imagelen;

      if (!names) 
        desc[0].mode = KEYDB_SEARCH_MODE_NEXT;

      rc = keydb_get_cert (hd, &cert);
      if (rc) 
        {
          log_error ("keydb_get_cert failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      image = ksba_cert_get_image (cert, &imagelen);
      if (!image)
        {
          log_error ("ksba_cert_get_image failed\n");
          goto leave;
        }

      if (ctrl->create_pem)
        {
          if (count)
            putc ('\n', fp);
          print_short_info (cert, fp);
          putc ('\n', fp);
        }
      count++;

      if (!b64writer)
        {
          ctrl->pem_name = "CERTIFICATE";
          rc = gpgsm_create_writer (&b64writer, ctrl, fp, &writer);
          if (rc)
            {
              log_error ("can't create writer: %s\n", gpg_strerror (rc));
              goto leave;
            }
        }

      rc = ksba_writer_write (writer, image, imagelen);
      if (rc)
        {
          log_error ("write error: %s\n", gpg_strerror (rc));
          goto leave;
        }

      if (ctrl->create_pem)
        {
          /* We want one certificate per PEM block */
          rc = gpgsm_finish_writer (b64writer);
          if (rc) 
            {
              log_error ("write failed: %s\n", gpg_strerror (rc));
              goto leave;
            }
          gpgsm_destroy_writer (b64writer);
          b64writer = NULL;
        }
      
      ksba_cert_release (cert); 
      cert = NULL;
    }
  if (rc && rc != -1)
    log_error ("keydb_search failed: %s\n", gpg_strerror (rc));
  else if (b64writer)
    {
      rc = gpgsm_finish_writer (b64writer);
      if (rc) 
        {
          log_error ("write failed: %s\n", gpg_strerror (rc));
          goto leave;
        }
    }
  
 leave:
  gpgsm_destroy_writer (b64writer);
  ksba_cert_release (cert);
  xfree (desc);
  keydb_release (hd);
}


/* Print some info about the certifciate CERT to FP */
static void
print_short_info (ksba_cert_t cert, FILE *fp)
{
  char *p;
  ksba_sexp_t sexp;
  int idx;

  for (idx=0; (p = ksba_cert_get_issuer (cert, idx)); idx++)
    {
      fputs (!idx?   "Issuer ...: "
                 : "\n   aka ...: ", fp); 
      gpgsm_print_name (fp, p);
      xfree (p);
    }
  putc ('\n', fp);

  fputs ("Serial ...: ", fp); 
  sexp = ksba_cert_get_serial (cert);
  if (sexp)
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
              fprintf (fp, "%02X", *s);
        }
      xfree (sexp);
    }
  putc ('\n', fp);

  for (idx=0; (p = ksba_cert_get_subject (cert, idx)); idx++)
    {
      fputs (!idx?   "Subject ..: "
                 : "\n    aka ..: ", fp); 
      gpgsm_print_name (fp, p);
      xfree (p);
    }
  putc ('\n', fp);
}






