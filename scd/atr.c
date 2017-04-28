/* atr.c - ISO 7816 ATR functions
 * Copyright (C) 2003, 2011 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <gpg-error.h>
#include "../common/logging.h"
#include "atr.h"

static int const fi_table[16] = { 0, 372, 558, 744, 1116,1488, 1860, -1,
                                  -1, 512, 768, 1024, 1536, 2048, -1, -1 };
static int const di_table[16] = { -1, 1, 2, 4, 8, 16, -1, -1,
                                  0, -1, -2, -4, -8, -16, -32, -64};


/* Dump the ATR in (BUFFER,BUFLEN) to a human readable format and
   return that as a malloced buffer.  The caller must release this
   buffer using es_free!  On error this function returns NULL and sets
   ERRNO.  */
char *
atr_dump (const void *buffer, size_t buflen)
{
  const unsigned char *atr = buffer;
  size_t atrlen = buflen;
  estream_t fp;
  int have_ta, have_tb, have_tc, have_td;
  int n_historical;
  int idx, val;
  unsigned char chksum;
  char *result;

  fp = es_fopenmem (0, "rwb,samethread");
  if (!fp)
    return NULL;

  if (!atrlen)
    {
      es_fprintf (fp, "error: empty ATR\n");
      goto bailout;
    }

  for (idx=0; idx < atrlen ; idx++)
    es_fprintf (fp, "%s%02X", idx?" ":"", atr[idx]);
  es_putc ('\n', fp);

  if (*atr == 0x3b)
    es_fputs ("Direct convention\n", fp);
  else if (*atr == 0x3f)
    es_fputs ("Inverse convention\n", fp);
  else
    es_fprintf (fp,"error: invalid TS character 0x%02x\n", *atr);
  if (!--atrlen)
    goto bailout;
  atr++;

  chksum = *atr;
  for (idx=1; idx < atrlen-1; idx++)
    chksum ^= atr[idx];

  have_ta = !!(*atr & 0x10);
  have_tb = !!(*atr & 0x20);
  have_tc = !!(*atr & 0x40);
  have_td = !!(*atr & 0x80);
  n_historical = (*atr & 0x0f);
  es_fprintf (fp, "%d historical characters indicated\n", n_historical);

  if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
    es_fputs ("error: ATR shorter than indicated by format character\n", fp);
  if (!--atrlen)
    goto bailout;
  atr++;

  if (have_ta)
    {
      es_fputs ("TA1: F=", fp);
      val = fi_table[(*atr >> 4) & 0x0f];
      if (!val)
        es_fputs ("internal clock", fp);
      else if (val == -1)
        es_fputs ("RFU", fp);
      else
        es_fprintf (fp, "%d", val);
      es_fputs (" D=", fp);
      val = di_table[*atr & 0x0f];
      if (!val)
        es_fputs ("[impossible value]\n", fp);
      else if (val == -1)
        es_fputs ("RFU\n", fp);
      else if (val < 0 )
        es_fprintf (fp, "1/%d\n", val);
      else
        es_fprintf (fp, "%d\n", val);

      if (!--atrlen)
        goto bailout;
      atr++;
    }

  if (have_tb)
    {
      es_fprintf (fp, "TB1: II=%d PI1=%d%s\n",
                  ((*atr >> 5) & 3), (*atr & 0x1f),
                  (*atr & 0x80)? " [high bit not cleared]":"");
      if (!--atrlen)
        goto bailout;
      atr++;
    }

  if (have_tc)
    {
      if (*atr == 255)
        es_fputs ("TC1: guard time shortened to 1 etu\n", fp);
      else
        es_fprintf (fp, "TC1: (extra guard time) N=%d\n", *atr);

      if (!--atrlen)
        goto bailout;
      atr++;
    }

  if (have_td)
    {
      have_ta = !!(*atr & 0x10);
      have_tb = !!(*atr & 0x20);
      have_tc = !!(*atr & 0x40);
      have_td = !!(*atr & 0x80);
      es_fprintf (fp, "TD1: protocol T%d supported\n", (*atr & 0x0f));

      if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
        es_fputs ("error: ATR shorter than indicated by format character\n",
                  fp);

      if (!--atrlen)
        goto bailout;
      atr++;
    }
  else
    have_ta = have_tb = have_tc = have_td = 0;

  if (have_ta)
    {
      es_fprintf (fp, "TA2: (PTS) %stoggle, %splicit, T=%02X\n",
                  (*atr & 0x80)? "no-":"",
                  (*atr & 0x10)? "im": "ex",
                  (*atr & 0x0f));
      if ((*atr & 0x60))
        es_fprintf (fp, "note: reserved bits are set (TA2=0x%02X)\n", *atr);
      if (!--atrlen)
        goto bailout;
      atr++;
    }

  if (have_tb)
    {
      es_fprintf (fp, "TB2: PI2=%d\n", *atr);
      if (!--atrlen)
        goto bailout;
      atr++;
    }

  if (have_tc)
    {
      es_fprintf (fp, "TC2: PWI=%d\n", *atr);
      if (!--atrlen)
        goto bailout;
      atr++;
    }

  if (have_td)
    {
      have_ta = !!(*atr & 0x10);
      have_tb = !!(*atr & 0x20);
      have_tc = !!(*atr & 0x40);
      have_td = !!(*atr & 0x80);
      es_fprintf (fp, "TD2: protocol T%d supported\n", *atr & 0x0f);

      if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
        es_fputs ("error: ATR shorter than indicated by format character\n",
                  fp);

      if (!--atrlen)
        goto bailout;
      atr++;
    }
  else
    have_ta = have_tb = have_tc = have_td = 0;

  for (idx = 3; have_ta || have_tb || have_tc || have_td; idx++)
    {
      if (have_ta)
        {
          es_fprintf (fp, "TA%d: IFSC=%d\n", idx, *atr);
          if (!--atrlen)
            goto bailout;
          atr++;
        }

      if (have_tb)
        {
          es_fprintf (fp, "TB%d: BWI=%d CWI=%d\n",
                   idx, (*atr >> 4) & 0x0f, *atr & 0x0f);
          if (!--atrlen)
            goto bailout;
          atr++;
        }

      if (have_tc)
        {
          es_fprintf (fp, "TC%d: 0x%02X\n", idx, *atr);
          if (!--atrlen)
            goto bailout;
          atr++;
        }

      if (have_td)
        {
          have_ta = !!(*atr & 0x10);
          have_tb = !!(*atr & 0x20);
          have_tc = !!(*atr & 0x40);
          have_td = !!(*atr & 0x80);
          es_fprintf (fp, "TD%d: protocol T%d supported\n", idx, *atr & 0x0f);

          if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
            es_fputs ("error: "
                      "ATR shorter than indicated by format character\n",
                      fp);

          if (!--atrlen)
            goto bailout;
          atr++;
        }
      else
        have_ta = have_tb = have_tc = have_td = 0;
    }

  if (n_historical + 1 > atrlen)
    es_fputs ("error: ATR shorter than required for historical bytes "
              "and checksum\n", fp);

  if (n_historical)
    {
      es_fputs ("HCH:", fp);
      for (; n_historical && atrlen ; n_historical--, atrlen--, atr++)
        es_fprintf (fp, " %02X", *atr);
      es_putc ('\n', fp);
    }

  if (!atrlen)
    es_fputs ("error: checksum missing\n", fp);
  else if (*atr == chksum)
    es_fprintf (fp, "TCK: %02X (good)\n", *atr);
  else
    es_fprintf (fp, "TCK: %02X (bad; computed %02X)\n", *atr, chksum);

  atrlen--;
  if (atrlen)
    es_fprintf (fp, "error: %u bytes garbage at end of ATR\n",
                (unsigned int)atrlen );

 bailout:
  es_putc ('\0', fp); /* We want a string.  */
  if (es_fclose_snatch (fp, (void**)&result, NULL))
    {
      log_error ("oops: es_fclose_snatch failed: %s\n", strerror (errno));
      return NULL;
    }

  return result;
}
