/* import.c - Import certificates
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#include <ksba.h>

#include "gpgsm.h"

struct reader_cb_parm_s {
  FILE *fp;
};


static int
reader_cb (void *cb_value, unsigned char *buffer, size_t count, size_t *nread)
{
  struct reader_cb_parm_s *parm = cb_value;
  size_t n;
  int c = 0;

  *nread = 0;
  if (!buffer)
    return -1; /* not supported */

  for (n=0; n < count; n++)
    {
      c = getc (parm->fp);
      if (c == EOF)
        {
          if ( ferror (parm->fp) )
            return -1;
          if (n)
            break; /* return what we have beofre an EOF */
          return -1;
        }
      *buffer++ = c;
    }

  *nread = n;
  return 0;
}


static void
print_integer (unsigned char *p)
{
  unsigned long len;

  if (!p)
    fputs ("none", stdout);
  else
    {
      len = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
      for (p+=4; len; len--, p++)
        printf ("%02X", *p);
    }
}

static void
print_time (time_t t)
{

  if (!t)
    fputs ("none", stdout);
  else if ( t == (time_t)(-1) )
    fputs ("error", stdout);
  else
    {
      struct tm *tp;

      tp = gmtime (&t);
      printf ("%04d-%02d-%02d %02d:%02d:%02d",
              1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
              tp->tm_hour, tp->tm_min, tp->tm_sec);
      assert (!tp->tm_isdst);
    }
}

static void
print_dn (char *p)
{

  if (!p)
    fputs ("error", stdout);
  else
    printf ("`%s'", p);
}




int
gpgsm_import (int in_fd)
{
  int rc;
  KsbaReader reader = NULL;
  KsbaCert cert = NULL;
  struct reader_cb_parm_s rparm;

  memset (&rparm, 0, sizeof rparm);

  rparm.fp = fdopen ( dup (in_fd), "rb");
  if (!rparm.fp)
    {
      log_error ("fdopen() failed: %s\n", strerror (errno));
      rc = seterr (IO_Error);
      goto leave;
    }

  /* setup a skaba reader which uses a callback function so that we can 
     strip off a base64 encoding when necessary */
  reader = ksba_reader_new ();
  if (!reader)
    {
      rc = seterr (Out_Of_Core);
      goto leave;
    }

  rc = ksba_reader_set_cb (reader, reader_cb, &rparm );
  if (rc)
    {
      ksba_reader_release (reader);
      rc = map_ksba_err (rc);
      goto leave;
    }

  cert = ksba_cert_new ();
  if (!cert)
    {
      rc = seterr (Out_Of_Core);
      goto leave;
    }

  rc = ksba_cert_read_der (cert, reader);
  if (rc)
    {
      rc = map_ksba_err (rc);
      goto leave;
    }

  {
    unsigned char *p;
    char *dn;
    time_t t;
    
    p = ksba_cert_get_serial (cert);
    fputs ("serial: ", stdout);
    print_integer (p);
    ksba_free (p);
    putchar ('\n');

    t = ksba_cert_get_validity (cert, 0);
    fputs ("notBefore: ", stdout);
    print_time (t);
    putchar ('\n');
    t = ksba_cert_get_validity (cert, 1);
    fputs ("notAfter: ", stdout);
    print_time (t);
    putchar ('\n');
    
    dn = ksba_cert_get_issuer (cert);
    fputs ("issuer: ", stdout);
    print_dn (dn);
    ksba_free (dn);
    putchar ('\n');
    
    dn = ksba_cert_get_subject (cert);
    fputs ("subject: ", stdout);
    print_dn (dn);
    ksba_free (dn);
    putchar ('\n');

    printf ("hash algo: %d\n", ksba_cert_get_digest_algo (cert));
    
    ksba_cert_hash (cert, NULL, NULL);
  }

 leave:
  ksba_cert_release (cert);
  ksba_reader_release (reader);
  if (rparm.fp)
    fclose (rparm.fp);
  return rc;
}




