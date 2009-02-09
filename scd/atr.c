/* atr.c - ISO 7816 ATR fucntions
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "scdaemon.h"
#include "apdu.h"
#include "atr.h"
#include "dynload.h"

static int const fi_table[16] = { 0, 372, 558, 744, 1116,1488, 1860, -1,
                                  -1, 512, 768, 1024, 1536, 2048, -1, -1 };
static int const di_table[16] = { -1, 1, 2, 4, 8, 16, -1, -1,
                                  0, -1, -2, -4, -8, -16, -32, -64};
                                  

/* Dump the ATR of the card at SLOT in a human readable format to
   stream FP.  */
int
atr_dump (int slot, FILE *fp)
{
  unsigned char *atrbuffer, *atr;
  size_t atrlen;
  int have_ta, have_tb, have_tc, have_td;
  int n_historical;
  int idx, val;
  unsigned char chksum;

  atr = atrbuffer = apdu_get_atr (slot, &atrlen);
  if (!atr)
    return gpg_error (GPG_ERR_GENERAL);
  
  fprintf (fp, "Info on ATR of length %u at slot %d\n",
           (unsigned int)atrlen, slot);
  if (!atrlen)
    {
      fprintf (fp, "error: empty ATR\n");
      goto bailout;
    }

  
  if (*atr == 0x3b)
    fputs ("direct convention\n", fp);
  else if (*atr == 0x3f)
    fputs ("inverse convention\n", fp);
  else
    fprintf (fp,"error: invalid TS character 0x%02x\n", *atr);
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
  fprintf (fp, "%d historical characters indicated\n", n_historical);

  if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
    fputs ("error: ATR shorter than indicated by format character\n", fp);
  if (!--atrlen)
    goto bailout;
  atr++;

  if (have_ta)
    {
      fputs ("TA1: F=", fp);
      val = fi_table[(*atr >> 4) & 0x0f];
      if (!val)
        fputs ("internal clock", fp);
      else if (val == -1)
        fputs ("RFU", fp);
      else
        fprintf (fp, "%d", val);
      fputs (" D=", fp);
      val = di_table[*atr & 0x0f]; 
      if (!val)
        fputs ("[impossible value]\n", fp);
      else if (val == -1)
        fputs ("RFU\n", fp);
      else if (val < 0 )
        fprintf (fp, "1/%d\n", val);
      else 
        fprintf (fp, "%d\n", val);
      
      if (!--atrlen)
        goto bailout;
      atr++;
    }
     
  if (have_tb)
    {
      fprintf (fp, "TB1: II=%d PI1=%d%s\n", (*atr >> 5) & 3, *atr & 0x1f,
               (*atr & 0x80)? " [high bit not cleared]":"");
      if (!--atrlen)
        goto bailout;
      atr++;
    }

  if (have_tc)
    {
      if (*atr == 255)
        fputs ("TC1: guard time shortened to 1 etu\n", fp);
      else
        fprintf (fp, "TC1: (extra guard time) N=%d\n", *atr);

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
      fprintf (fp, "TD1: protocol T%d supported\n", *atr & 0x0f);

      if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
        fputs ("error: ATR shorter than indicated by format character\n", fp);

      if (!--atrlen)
        goto bailout;
      atr++;
    }
  else
    have_ta = have_tb = have_tc = have_td = 0;

  if (have_ta)
    {
      fprintf (fp, "TA2: (PTS) %stoggle, %splicit, T=%02X\n",
               (*atr & 0x80)? "no-":"",
               (*atr & 0x10)? "im": "ex",
               (*atr & 0x0f));
      if ((*atr & 0x60))
        fprintf (fp, "note: reserved bits are set (TA2=0x%02X)\n", *atr);
      if (!--atrlen)
        goto bailout;
      atr++;
    }

  if (have_tb)
    {
      fprintf (fp, "TB2: PI2=%d\n", *atr);
      if (!--atrlen)
        goto bailout;
      atr++;
    }

  if (have_tc)
    {
      fprintf (fp, "TC2: PWI=%d\n", *atr);
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
      fprintf (fp, "TD2: protocol T%d supported\n", *atr & 0x0f);

      if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
        fputs ("error: ATR shorter than indicated by format character\n", fp);

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
          fprintf (fp, "TA%d: IFSC=%d\n", idx, *atr);
          if (!--atrlen)
            goto bailout;
          atr++;
        }

      if (have_tb)
        {
          fprintf (fp, "TB%d: BWI=%d CWI=%d\n",
                   idx, (*atr >> 4) & 0x0f, *atr & 0x0f);
          if (!--atrlen)
            goto bailout;
          atr++;
        }

      if (have_tc)
        {
          fprintf (fp, "TC%d: 0x%02X\n", idx, *atr);
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
          fprintf (fp, "TD%d: protocol T%d supported\n", idx, *atr & 0x0f);

          if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
            fputs ("error: ATR shorter than indicated by format character\n",
                   fp);

          if (!--atrlen)
            goto bailout;
          atr++;
        }
      else
        have_ta = have_tb = have_tc = have_td = 0;
    }

  if (n_historical + 1 > atrlen)
    fputs ("error: ATR shorter than required for historical bytes "
           "and checksum\n", fp);
  
  if (n_historical)
    {
      fputs ("Historical:", fp);
      for (; n_historical && atrlen ; n_historical--, atrlen--, atr++)
        fprintf (fp, " %02X", *atr);
      putchar ('\n');
    }

  if (!atrlen)
    fputs ("error: checksum missing\n", fp);
  else if (*atr == chksum)
    fprintf (fp, "TCK: %02X (good)\n", *atr);
  else
    fprintf (fp, "TCK: %02X (bad; calculated %02X)\n", *atr, chksum);

  atrlen--;
  if (atrlen)
    fprintf (fp, "error: %u bytes garbage at end of ATR\n",
             (unsigned int)atrlen );

 bailout:
  xfree (atrbuffer);

  return 0;
}


/* Note: This code has not yet been tested!  It shall return -1 on
   error or the number of historical bytes and store them at
   HISTORICAL.  */
int
atr_get_historical (int slot, unsigned char historical[])
{
  int result = -1;
  unsigned char *atrbuffer = NULL;
  unsigned char *atr;
  size_t atrlen;
  int have_ta, have_tb, have_tc, have_td;
  int n_historical;
  int idx;
  unsigned char chksum;

  atr = atrbuffer = apdu_get_atr (slot, &atrlen);
  if (!atr || atrlen < 2)
    goto leave;
  atrlen--;
  atr++;

  chksum = *atr;
  for (idx=1; idx < atrlen-1; idx++)
    chksum ^= atr[idx];

  have_ta = !!(*atr & 0x10);
  have_tb = !!(*atr & 0x20);
  have_tc = !!(*atr & 0x40);
  have_td = !!(*atr & 0x80);
  n_historical = (*atr & 0x0f);

  if (have_ta + have_tb + have_tc + have_td + n_historical >= atrlen)
    goto leave; /* ATR shorter than indicated by format character.  */
  atrlen--;
  atr++;

  if (have_ta + have_tb + have_tc >= atrlen)
    goto leave;
  atrlen -= have_ta + have_tb + have_tc;
  atr    += have_ta + have_tb + have_tc;

  if (have_td)
    {
      have_ta = !!(*atr & 0x10);
      have_tb = !!(*atr & 0x20);
      have_tc = !!(*atr & 0x40);
      have_td = !!(*atr & 0x80);
      if (have_ta + have_tb + have_tc + have_td + n_historical >= atrlen)
        goto leave; /* ATR shorter than indicated by format character.  */
      atrlen--;
      atr++;
    }
  else
    have_ta = have_tb = have_tc = have_td = 0;

  if (have_ta + have_tb + have_tc >= atrlen)
    goto leave;
  atrlen -= have_ta + have_tb + have_tc;
  atr    += have_ta + have_tb + have_tc;

  if (have_td)
    {
      have_ta = !!(*atr & 0x10);
      have_tb = !!(*atr & 0x20);
      have_tc = !!(*atr & 0x40);
      have_td = !!(*atr & 0x80);
      if (have_ta + have_tb + have_tc + have_td + n_historical >= atrlen)
        goto leave; /* ATR shorter than indicated by format character.  */
      atrlen--;
      atr++;
    }
  else
    have_ta = have_tb = have_tc = have_td = 0;

  for (idx = 3; have_ta || have_tb || have_tc || have_td; idx++)
    {
      if (have_ta + have_tb + have_tc >= atrlen)
        goto leave;
      atrlen -= have_ta + have_tb + have_tc;
      atr    += have_ta + have_tb + have_tc;

      if (have_td)
        {
          have_ta = !!(*atr & 0x10);
          have_tb = !!(*atr & 0x20);
          have_tc = !!(*atr & 0x40);
          have_td = !!(*atr & 0x80);
          if (have_ta + have_tb + have_tc + have_td + n_historical >= atrlen)
            goto leave; /* ATR shorter than indicated by format character.  */
          atrlen--;
          atr++;
        }
      else
        have_ta = have_tb = have_tc = have_td = 0;
    }

  if (n_historical >= atrlen)
    goto leave; /* ATR shorter than required for historical bytes. */
  
  if (n_historical)
    {
      for (idx=0; n_historical && atrlen; n_historical--, atrlen--, atr++)
        historical[idx] = *atr;
    }

  if (!atrlen || *atr != chksum)
    goto leave;

  /* Don't care about garbage at the end of the ATR.  */

  result = n_historical;

 leave:
  xfree (atrbuffer);

  return result;
}

