/* app-p15.c - The pkcs#15 card application.
 *	Copyright (C) 2004 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "scdaemon.h"

#include "iso7816.h"
#include "app-common.h"
#include "tlv.h"


/* Context local to this application. */
struct app_local_s 
{
  unsigned short home_df;  /* The home DF. Note, that we don't yet
                              support a multilevel hierachy.  Thus we
                              assume this is directly below the MF.  */
  struct
  {
    unsigned short private_keys;
    unsigned short public_keys;
    unsigned short trusted_public_keys;
    unsigned short secret_keys;
    unsigned short certificates;
    unsigned short trusted_certificates;
    unsigned short useful_certificates;
    unsigned short data_objects;
    unsigned short auth_objects;
  } odf;  


};




/* Do a select and a read for the file with EFID.  EFID is a
   desctription of the EF to be used with error messages.  On success
   BUFFER and BUFLEN contain the entire content of the EF.  The caller
   must free BUFFER but only on success. */
static gpg_error_t 
select_and_read_binary (int slot, unsigned short efid, const char *efid_desc,
                        unsigned char **buffer, size_t *buflen)
{
  gpg_error_t err;

  err = iso7816_select_file (slot, efid, 0, NULL, NULL);
  if (err)
    {
      log_error ("error selecting %s (0x%04X): %s\n",
                 efid_desc, efid, gpg_strerror (err));
      return err;
    }
  err = iso7816_read_binary (slot, 0, 0, buffer, buflen);
  if (err)
    {
      log_error ("error reading %s (0x%04X): %s\n",
                 efid_desc, efid, gpg_strerror (err));
      return err;
    }
  return 0;
}




/* Read and parse the Object Directory File and store away the
   pointers.

   Example of such a file:

   A0 06 30 04 04 02 60 34  = Private Keys
   A4 06 30 04 04 02 60 35  = Certificates 
   A5 06 30 04 04 02 60 36  = TrustedCertificates
   A7 06 30 04 04 02 60 37  = DataObjects
   A8 06 30 04 04 02 60 38  = AuthObjects
    
   These are all PathOrObjects using the path CHOICE.  The paths are
   octet strings of length 2.  Using this Path CHOICE is recommended,
   so we only implement that for now.
*/
static gpg_error_t
read_ef_odf (app_t app)
{
  gpg_error_t err;
  unsigned char *buffer, *p;
  size_t buflen;
  unsigned short value;

  err = select_and_read_binary (app->slot, 0x5031, "ODF", &buffer, &buflen);
  if (err)
    return err;

  if (len < 8)
    {
      log_error ("error: ODF too short\n");
      xfree (buffer);
      return gpg_error (GPG_ERR_INV_OBJ);
    }
  for (p=buffer; buflen >= 8; p += 8, buflen -= 8)
    {
      if ( (p[0] & 0xf0) != 0xA0
           || memcmp (p+1, "\x06\x30\x04\x04\x02", 5) )
        {
          log_error ("ODF format is not supported by us\n");
          xfree (buffer);
          return gpg_error (GPG_ERR_INV_OBJ);
        }
      switch ((p[0] & 0x0f))
        {
        case 0: value = app->app_local->odf.private_keys; break;
        case 1: value = app->app_local->odf.public_keys; break;
        case 2: value = app->app_local->odf.trusted_public_keys; break;
        case 3: value = app->app_local->odf.secret_keys; break;
        case 4: value = app->app_local->odf.certificates; break;
        case 5: value = app->app_local->odf.trusted_certificates; break;
        case 6: value = app->app_local->odf.useful_certificates; break;
        case 7: value = app->app_local->odf.data_objects; break;
        case 8: value = app->app_local->odf.auth_objects; break;
        default: value = 0; break;
        }
      if (value)
        {
          log_error ("duplicate object type %d in ODF ignored\n",(p[0)&0x0f));
          continue;
        }
      value = ((p[6] << 8) | p[7]);
      switch ((p[0] & 0x0f))
        {
        case 0: app->app_local->odf.private_keys = value; break;
        case 1: app->app_local->odf.public_keys = value; break;
        case 2: app->app_local->odf.trusted_public_keys = value; break;
        case 3: app->app_local->odf.secret_keys = value; break;
        case 4: app->app_local->odf.certificates = value; break;
        case 5: app->app_local->odf.trusted_certificates = value; break;
        case 6: app->app_local->odf.useful_certificates = value; break;
        case 7: app->app_local->odf.data_objects = value; break;
        case 8: app->app_local->odf.auth_objects = value; break;
        default: 
          log_error ("unknown object type %d in ODF ignored\n", (p[0)&0x0f));
        }
    }

  if (buflen)
    log_info ("warning: %u bytes of garbage detected at end of ODF\n", buflen);

  xfree (buffer);
  return 0;
}



/* Read and  parse the Private Key Directory Files. */
/*
  6034 (privatekeys)

30 33 30 11 0C 08 53 4B 2E  43 48 2E 44 53 03 02   030...SK.CH.DS..
06 80 04 01 07 30 0C 04 01  01 03 03 06 00 40 02   .....0........@.
02 00 50 A1 10 30 0E 30 08  04 06 3F 00 40 16 00   ..P..0.0...?.@..
50 02 02 04 00 30 33 30 11  0C 08 53 4B 2E 43 48   P....030...SK.CH
2E 4B 45 03 02 06 80 04 01  0A 30 0C 04 01 0C 03   .KE.......0.....
03 06 44 00 02 02 00 52 A1  10 30 0E 30 08 04 06   ..D....R..0.0...
3F 00 40 16 00 52 02 02 04  00 30 34 30 12 0C 09   ?.@..R....040...
53 4B 2E 43 48 2E 41 55 54  03 02 06 80 04 01 0A   SK.CH.AUT.......
30 0C 04 01 0D 03 03 06 20  00 02 02 00 51 A1 10   0....... ....Q..
30 0E 30 08 04 06 3F 00 40  16 00 51 02 02 04 00   0.0...?.@..Q....
30 37 30 15 0C 0C 53 4B 2E  43 48 2E 44 53 2D 53   070...SK.CH.DS-S
50 58 03 02 06 80 04 01 0A  30 0C 04 01 02 03 03   PX.......0......
06 20 00 02 02 00 53 A1 10  30 0E 30 08 04 06 3F   . ....S..0.0...?
00 40 16 00 53 02 02 04 00  00 00 00 00 00 00 00   .@..S...........
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................

*/
static gpg_error_t
read_ef_prkdf (app_t app)
{


}

/* Read and  parse the Public Key Directory Files. */
static gpg_error_t
read_ef_pukdf (app_t app)
{


}


/* Read and parse the Certificate Directory Files. */
/* 

6035 (certificates)

30 2A 30 15 0C 0C 43 5F 58  35 30 39 2E 43 48 2E   0*0...C_X509.CH.
44 53 03 02 06 40 04 01 0A  30 03 04 01 01 A1 0C   DS...@...0......
30 0A 30 08 04 06 3F 00 40  16 C0 00 30 2A 30 15   0.0...?.@...0*0.
0C 0C 43 5F 58 35 30 39 2E  43 48 2E 4B 45 03 02   ..C_X509.CH.KE..
06 40 04 01 0A 30 03 04 01  0C A1 0C 30 0A 30 08   .@...0......0.0.
04 06 3F 00 40 16 C2 00 30  2B 30 16 0C 0D 43 5F   ..?.@...0+0...C_
58 35 30 39 2E 43 48 2E 41  55 54 03 02 06 40 04   X509.CH.AUT...@.
01 0A 30 03 04 01 0D A1 0C  30 0A 30 08 04 06 3F   ..0......0.0...?
00 40 16 C5 00 30 2E 30 19  0C 10 43 5F 58 35 30   .@...0.0...C_X50
39 2E 43 48 2E 44 53 2D 53  50 58 03 02 06 40 04   9.CH.DS-SPX...@.
01 0A 30 03 04 01 02 A1 0C  30 0A 30 08 04 06 3F   ..0......0.0...?
00 40 16 C1 20 00 00 00 00  00 00 00 00 00 00 00   .@.. ...........
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................

   0   42: SEQUENCE {
   2   21:   SEQUENCE {   -- commonObjectAttributes
   4   12:     UTF8String 'C_X509.CH.DS'
  18    2:     BIT STRING 6 unused bits
         :       '10'B (bit 1)
  22    1:     OCTET STRING 0A
         :     }
  25    3:   SEQUENCE {   -- commonCertificateAttributes
  27    1:     OCTET STRING 01
         :     }
  30   12:   [1] {        -- certAttributes
  32   10:     SEQUENCE {
  34    8:       SEQUENCE {
  36    6:         OCTET STRING 3F 00 40 16 C0 00
         :         }
         :       }
         :     }
         :   }



6036 (trustedcertificates)

30 35 30 06 03 02 00 00 04  00 30 16 04 14 2D 36   050.......0...-6
33 39 33 33 39 34 30 33 39  37 37 36 34 30 31 32   3933940397764012
31 36 A1 13 30 11 30 0F 04  06 3F 00 40 16 C7 08   16..0.0...?.@...
02 01 00 80 02 02 29 30 35  30 06 03 02 00 00 04   ......)050......
00 30 16 04 14 2D 34 30 31  39 30 35 32 37 32 36   .0...-4019052726
38 30 31 36 39 33 34 39 32  A1 13 30 11 30 0F 04   801693492..0.0..
06 3F 00 40 16 C7 0E 02 01  00 80 02 04 12 30 34   .?.@..........04
30 06 03 02 00 00 04 00 30  15 04 13 37 39 36 33   0.......0...7963
32 38 33 36 35 30 37 36 36  34 38 32 39 36 30 A1   283650766482960.
13 30 11 30 0F 04 06 3F 00  40 16 C0 08 02 01 00   .0.0...?.@......
80 02 04 11 00 00 00 00 00  00 00 00 00 00 00 00   ................
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................

   0   53: SEQUENCE {
   2    6:   SEQUENCE {
   4    2:     BIT STRING
         :       '00000000'B
         :       Error: Spurious zero bits in bitstring.
   8    0:     OCTET STRING
         :       Error: Object has zero length.
         :     }
  10   22:   SEQUENCE {
  12   20:     OCTET STRING '-6393394039776401216'
         :     }
  34   19:   [1] {
  36   17:     SEQUENCE {
  38   15:       SEQUENCE {
  40    6:         OCTET STRING 3F 00 40 16 C7 08
  48    1:         INTEGER 0       -- index
  51    2:         [0] 02 29       -- length
         :         }
         :       }
         :     }
         :   }


*/
static gpg_error_t
read_ef_cdf (app_t app)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  size_t buflen;
  unsigned short value;
  unsigned short fid;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  
  fid = app->app_local->odf.certificates;
  if (!fid)
    return 0; /* No certificates. */
  
  err = select_and_read_binary (app->slot, fid, "CDF", &buffer, &buflen);
  if (err)
    return err;
  
  p = buffer;
  n = buflen;

  /* Loop over the records.  We stop as soon as we detect a new record
     starting with 0x00 or 0xff as these values are commonly used to pad
     the the read datablocks and are no valid ASN.1 encoding. */
  while (n && *p && *p == 0xff)
    {
      const unsigned char *pp;
      size_t nn;

      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > n || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        {
          log_error ("error parsing CDF record: %s\n", gpg_strerror (err));
          goto leave;
        }
      pp = p;
      nn = objlen;
      p += objlen;
      n -= objlen;

      /* Skip the commonObjectAttributes.  */
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > nn || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        {
          log_error ("error parsing CDF record: %s - skipped\n",
                     gpg_strerror (err));
          continue;
        }
      pp += objlen;
      nn -= objlen;

      /* Skip the commonCertificateAttributes.  */
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > nn || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        {
          log_error ("error parsing CDF record: %s - skipped\n",
                     gpg_strerror (err));
          continue;
        }
      pp += objlen;
      nn -= objlen;

      /* FIXME: Check that this is a reference to a certificate. */


    }


 leave:
  xfree (buffer);
  return err;
}

/* Read and parse Authentication Object Directory Files.  */
static gpg_error_t 
read_ef_aodf (app_t app)
{

}


/* 6037 (dataobjects)

30 1E 30 0B 0C 06 45 46 2E  47 44 4F 04 01 0A 30   0.0...EF.GDO...0
02 0C 00 A1 0B 30 09 04 04  3F 00 2F 02 80 01 0E   .....0...?./....
30 30 30 18 0C 0F 64 69 73  70 6C 61 79 20 6D 65   000...display me
73 73 61 67 65 03 02 06 C0  04 01 0A 30 05 0C 03   ssage.......0...
42 53 53 A1 0D 30 0B 04 06  3F 00 40 16 D0 00 80   BSS..0...?.@....
01 20 30 2B 30 0C 0C 03 53  53 4F 03 02 06 C0 04   . 0+0...SSO.....
01 0A 30 0B 0C 09 53 61 66  65 47 75 61 72 64 A1   ..0...SafeGuard.
0E 30 0C 04 06 3F 00 0F FF  30 02 80 02 03 00 30   .0...?...0.....0
30 30 11 0C 08 53 47 41 53  64 61 74 61 03 02 06   00...SGASdata...
C0 04 01 0A 30 0B 0C 09 53  61 66 65 47 75 61 72   ....0...SafeGuar
64 A1 0E 30 0C 04 06 3F 00  0F FF 40 01 80 02 00   d..0...?...@....
80 30 30 30 11 0C 08 55 73  65 72 64 61 74 61 03   .000...Userdata.
02 06 40 04 01 0A 30 0B 0C  09 53 61 66 65 47 75   ..@...0...SafeGu
61 72 64 A1 0E 30 0C 04 06  3F 00 0F FF 30 01 80   ard..0...?...0..
02 01 00 30 2C 30 13 0C 0A  62 61 73 69 63 20 64   ...0,0...basic d
61 74 61 03 02 06 C0 04 01  0A 30 05 0C 03 49 44   ata.......0...ID
44 A1 0E 30 0C 04 06 3F 00  40 17 D0 01 80 02 02   D..0...?.@......
00 30 2F 30 16 0C 0D 65 78  74 65 6E 64 65 64 20   .0/0...extended 
64 61 74 61 03 02 06 C0 04  01 0A 30 05 0C 03 49   data.......0...I
44 44 A1 0E 30 0C 04 06 3F  00 40 17 D0 02 80 02   DD..0...?.@.....
08 00 30 34 30 1B 0C 12 73  70 65 63 69 61 6C 20   ..040...special 
70 72 69 76 69 6C 65 67 65  73 03 02 06 C0 04 01   privileges......
0A 30 05 0C 03 49 44 44 A1  0E 30 0C 04 06 3F 00   .0...IDD..0...?.
40 17 D0 03 80 02 04 00                            @.......        

   0   30: SEQUENCE {
   2   11:   SEQUENCE {
   4    6:     UTF8String 'EF.GDO'
  12    1:     OCTET STRING 0A
         :     }
  15    2:   SEQUENCE {
  17    0:     UTF8String
         :       Error: Object has zero length.
         :     }
  19   11:   [1] {
  21    9:     SEQUENCE {
  23    4:       OCTET STRING 3F 00 2F 02
  29    1:       [0] 0E
         :       }
         :     }
         :   }



6038 (authobjects)

30 2A 30 0B 0C 05 62 61 73  69 63 03 02 00 C0 30   0*0...basic....0
03 04 01 0A A1 16 30 14 03  03 00 0C 10 0A 01 01   ......0.........
02 01 06 02 01 06 02 01 08  80 01 01 30 51 30 19   ............0Q0.
0C 13 73 70 65 63 69 66 69  63 20 50 49 4E 20 66   ..specific PIN f
6F 72 20 44 53 03 02 00 C0  30 03 04 01 07 A1 2F   or DS....0...../
30 2D 03 03 00 4C 10 0A 01  01 02 01 06 02 01 06   0-...L..........
02 01 08 80 01 02 18 0F 32  30 30 32 30 34 31 39   ........20020419
31 32 31 33 34 31 5A 30 06  04 04 3F 00 40 16      121341Z0...?.@. 

   0   42: SEQUENCE {
   2   11:   SEQUENCE {
   4    5:     UTF8String 'basic'
  11    2:     BIT STRING
         :       '00000011'B
         :       Error: Spurious zero bits in bitstring.
         :     }
  15    3:   SEQUENCE {
  17    1:     OCTET STRING 0A
         :     }
  20   22:   [1] {
  22   20:     SEQUENCE {
  24    3:       BIT STRING
         :         '0000100000110000'B
         :         Error: Spurious zero bits in bitstring.
  29    1:       ENUMERATED 1
  32    1:       INTEGER 6
  35    1:       INTEGER 6
  38    1:       INTEGER 8
  41    1:       [0] 01
         :       }
         :     }
         :   }



*/


/* Read and parse the EF(TokenInfo). 

TokenInfo ::= SEQUENCE {
    version		INTEGER {v1(0)} (v1,...),
    serialNumber	OCTET STRING,
    manufacturerID 	Label OPTIONAL,
    label 		[0] Label OPTIONAL,
    tokenflags 		TokenFlags,
    seInfo 		SEQUENCE OF SecurityEnvironmentInfo OPTIONAL,
    recordInfo 		[1] RecordInfo OPTIONAL,
    supportedAlgorithms	[2] SEQUENCE OF AlgorithmInfo OPTIONAL,
    ...,
    issuerId		[3] Label OPTIONAL,
    holderId		[4] Label OPTIONAL,
    lastUpdate		[5] LastUpdate OPTIONAL,
    preferredLanguage	PrintableString OPTIONAL -- In accordance with
    -- IETF RFC 1766 
} (CONSTRAINED BY { -- Each AlgorithmInfo.reference value must be unique --})

TokenFlags ::= BIT STRING {
    readonly		(0),
    loginRequired 	(1),
    prnGeneration 	(2),
    eidCompliant  	(3)
}


 5032:

30 31 02 01 00 04 04 05 45  36 9F 0C 0C 44 2D 54   01......E6...D-T
72 75 73 74 20 47 6D 62 48  80 14 4F 66 66 69 63   rust GmbH..Offic
65 20 69 64 65 6E 74 69 74  79 20 63 61 72 64 03   e identity card.
02 00 40 20 63 61 72 64 03  02 00 40 00 00 00 00   ..@ card...@....
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................

   0   49: SEQUENCE {
   2    1:   INTEGER 0
   5    4:   OCTET STRING 05 45 36 9F
  11   12:   UTF8String 'D-Trust GmbH'
  25   20:   [0] 'Office identity card'
  47    2:   BIT STRING
         :     '00000010'B (bit 1)
         :     Error: Spurious zero bits in bitstring.
         :   }




 */
static gpg_error_t
read_ef_tokeninfo (app_t app)
{
  unsigned short efid = 0x5032;

}


/* Get all the basic information from the pkcs#15 card, check the
   structure and init our context.  This is used once at application
   initialization. */
static gpg_error_t
read_p15_info (app_t app)
{
  gpg_error_t err;

  err = read_ed_odf (app);
  if (err)
    return err;

}


static int
do_learn_status (APP app, CTRL ctrl)
{
  gpg_error_t err;
  char ct_buf[100], id_buf[100];
  int i;

  /* Output information about all useful objects. */
  for (i=0; objlist[i].fid; i++)
    {
      if (filelist[i].certtype)
        {
          size_t len;

          len = app_help_read_length_of_cert (app->slot,
                                              filelist[i].fid, NULL);
          if (len)
            {
              /* FIXME: We should store the length in the application's
                 context so that a following readcert does only need to
                 read that many bytes. */
              sprintf (ct_buf, "%d", filelist[i].certtype);
              sprintf (id_buf, "P15-DF01.%04X", filelist[i].fid);
              send_status_info (ctrl, "CERTINFO",
                                ct_buf, strlen (ct_buf), 
                                id_buf, strlen (id_buf), 
                                NULL, (size_t)0);
            }
        }
      else if (filelist[i].iskeypair)
        {
          char gripstr[40+1];

          err = keygripstr_from_pk_file (app->slot, filelist[i].fid, gripstr);
          if (err)
            log_error ("can't get keygrip from FID 0x%04X: %s\n",
                       filelist[i].fid, gpg_strerror (err));
          else
            {
              sprintf (id_buf, "P15-DF01.%04X", filelist[i].fid);
              send_status_info (ctrl, "KEYPAIRINFO",
                                gripstr, 40, 
                                id_buf, strlen (id_buf), 
                                NULL, (size_t)0);
            }
        }
    }

  return 0;
}




/* Release all resources.  */
static void
do_deinit (app_t app)
{
  if (app && app->app_local)
    {
      xfree (app->app_local);
      app->app_local = NULL;
    }
}


/* Select the PKCS#15 application on the card in SLOT.  */
int
app_select_p15 (APP app)
{
  static char const aid[] = { 0xA0, 0, 0, 0, 0x63,
                              0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };
  int slot = app->slot;
  int rc;
  
  rc = iso7816_select_application (slot, aid, sizeof aid);
  if (!rc)
    {
      app->apptype = "P15";

      app->app_local = xtrycalloc (1, sizeof *app->app_local);
      if (!app->app_local)
        {
          rc = gpg_error_from_errno (errno);
          goto leave;
        }

      /* Read basic information and check whether this is a real
         card.  */
      rc = read_p15_info (app);
      
      /* Special serial number munging.  We need to do one case here
         because we need to access the EF(TokenInfo).  */
      if (app->serialnolen == 12
          && !memcmp (app->serial, "\xD2\x76\0\0\0\0\0\0\0\0\0\0", 12))
        {
          /* This is a German card with a silly serial number.  Try to get
             the serial number from the EF(TokenInfo). We indicate such a
             serial number by the using the prefix: "FF0100". */
          const char *efser = card->p15card->serial_number;
          char *p;
          
          if (!efser)
            efser = "";
          
          xfree (*serial);
          *serial = NULL;
          p = xtrymalloc (strlen (efser) + 7);
          if (!p)
            rc = gpg_error (gpg_err_code_from_errno (errno));
          else
            {
              strcpy (p, "FF0100");
              strcpy (p+6, efser);
              *serial = p;
            }
        }
      else
        rc = app_munge_serialno (app);

      app->fnc.deinit = do_deinit;
      app->fnc.learn_status = do_learn_status;
      app->fnc.readcert = do_readcert;
      app->fnc.getattr = NULL;
      app->fnc.setattr = NULL;
      app->fnc.genkey = NULL;
      app->fnc.sign = do_sign;
      app->fnc.auth = NULL;
      app->fnc.decipher = do_decipher;
      app->fnc.change_pin = NULL;
      app->fnc.check_pin = NULL;

    leave:
      if (rc)
        {
          xfree (app->app_local);
          app->app_local = NULL;
        }
      
   }

  return rc;
}


