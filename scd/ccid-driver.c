/* ccid-driver.c - USB ChipCardInterfaceDevices driver
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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


/* CCID (ChipCardInterfaceDevices) is a specification for accessing
   smartcard via a reader connected to the USB.  

   This is a limited driver allowing to use some CCID drivers directly
   without any other specila drivers. This is a fallback driver to be
   used when nothing else works or the system should be kept minimal
   for security reasons.  It makes use of the libusb library to gain
   portable access to USB.

   This driver has been tested with the SCM SCR335 smartcard reader
   and requires that reader implements the TPDU level exchange and
   does fully automatic initialization.
*/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if defined(HAVE_LIBUSB) || defined(TEST)
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <usb.h>


#include "ccid-driver.h"

enum {
  RDR_to_PC_NotifySlotChange= 0x50,
  RDR_to_PC_HardwareError   = 0x51,

  PC_to_RDR_SetParameters   = 0x61,
  PC_to_RDR_IccPowerOn      = 0x62,
  PC_to_RDR_IccPowerOff     = 0x63,
  PC_to_RDR_GetSlotStatus   = 0x65,
  PC_to_RDR_Secure          = 0x69,
  PC_to_RDR_T0APDU          = 0x6a,
  PC_to_RDR_Escape          = 0x6b,
  PC_to_RDR_GetParameters   = 0x6c,
  PC_to_RDR_ResetParameters = 0x6d,
  PC_to_RDR_IccClock        = 0x6e,
  PC_to_RDR_XfrBlock        = 0x6f,
  PC_to_RDR_Mechanical      = 0x71,
  PC_to_RDR_Abort           = 0x72,
  PC_to_RDR_SetDataRate     = 0x73,

  RDR_to_PC_DataBlock       = 0x80,
  RDR_to_PC_SlotStatus      = 0x81,
  RDR_to_PC_Parameters      = 0x82,
  RDR_to_PC_Escape          = 0x83,
  RDR_to_PC_DataRate        = 0x84
};


/* Store information on the driver's state.  A pointer to such a
   structure is used as handle for most functions. */
struct ccid_driver_s {
  usb_dev_handle *idev;
  int seqno;
  unsigned char t1_seqno;
};




/* Open the reader with the internal number READERNO and return a a
   pointer to be used as handle in HANDLE.  Returns 0 on success. */
int 
ccid_open_reader (ccid_driver_t *handle, int readerno)
{
  static int initialized;

  int rc;
  usb_match_handle *match = NULL;
  struct usb_device *dev = NULL;
  usb_dev_handle *idev = NULL;

  *handle = NULL;
  if (!initialized)
    {
      usb_init ();
      initialized = 1;
    }
  
  rc = usb_create_match (&match, -1, -1, 11, -1, -1);
  if (rc)
    {
      fprintf (stderr, "ccid-driver: usb_create_match failed: %d\n", rc);
      return -1;
    }

  while (usb_find_device(match, dev, &dev) >= 0) 
    {
      fprintf(stderr, "ccid-driver: %-40s %04X/%04X\n", dev->filename,
              dev->descriptor->idVendor, dev->descriptor->idProduct);
      if (!readerno)
        {
          rc = usb_open (dev, &idev);
          if (rc)
            {
              fprintf (stderr, "ccid-driver: usb_open failed: %d\n", rc);
              goto leave;
            }

          rc = usb_claim_interface (idev, 0);
          if (rc)
            {
              fprintf (stderr, "ccid-driver: usb_claim_interface failed: %d\n",
                       rc);
              goto leave;
            }

          *handle = calloc (1, sizeof **handle);
          if (!*handle)
            {
              fprintf (stderr, "ccid-driver: out of memory\n");
              rc = -1;
              goto leave;
            }
          (*handle)->idev = idev;
          idev = NULL;
          break;
        }
      readerno--;
    }


 leave:
  if (idev)
    usb_close (idev);
  /* fixme: Do we need to release dev or is it supposed to be a
     shallow copy of the list created internally by usb_init ? */
  usb_free_match (match);

  return rc;
}


/* Return False if a card is present and powered. */
int
ccid_check_card_presence (ccid_driver_t handle)
{

  return -1;
}


static void
set_msg_len (unsigned char *msg, unsigned int length)
{
  msg[1] = length;
  msg[2] = length >> 8;
  msg[3] = length >> 16;
  msg[4] = length >> 24;
}


/* Write a MSG of length MSGLEN to the designated bulk out endpoint.
   Returns 0 on success. */
static int
bulk_out (ccid_driver_t handle, unsigned char *msg, size_t msglen)
{
  int rc;

  rc = usb_bulk_write (handle->idev, 
                       1, /*endpoint */
                       msg, msglen,
                       1000 /* ms timeout */);
  if (rc == msglen)
    return 0;

  if (rc == -1)
    fprintf (stderr, "ccid-driver: usb_bulk_write error: %s\n",
             strerror (errno));
  else
    fprintf (stderr, "ccid-driver: usb_bulk_write failed: %d\n", rc);
  return -1;
}


/* Read a maximum of LENGTH bytes from the bulk in endpoint into
   BUFFER and return the actual read number if bytes in NREAD.
   Returns 0 on success. */
static int
bulk_in (ccid_driver_t handle, unsigned char *buffer, size_t length,
         size_t *nread)
{
  int rc;

  rc = usb_bulk_read (handle->idev, 
                      0x82,
                      buffer, length,
                      1000 /* ms timeout */ );
  if (rc < 0)
    {
      fprintf (stderr, "ccid-driver: usb_bulk_read error: %s\n",
               strerror (errno));
      return -1;
    }

  *nread = rc;
  return 0;
}


/* experimental */
int
ccid_poll (ccid_driver_t handle)
{
  int rc;
  unsigned char msg[10];
  size_t msglen;
  int i, j;

  rc = usb_bulk_read (handle->idev, 
                      0x83,
                      msg, sizeof msg,
                      0 /* ms timeout */ );
  if (rc < 0 && errno == ETIMEDOUT)
    return 0;

  if (rc < 0)
    {
        fprintf (stderr, "ccid-driver: usb_intr_read error: %s\n",
                 strerror (errno));
      return -1;
    }

  msglen = rc;
  rc = 0;

  if (msglen < 1)
    {
      fprintf (stderr, "ccid-driver: intr-in msg too short\n");
      return -1;
    }

  if (msg[0] == RDR_to_PC_NotifySlotChange)
    {
      fprintf (stderr, "ccid-driver: notify slot change:");
      for (i=1; i < msglen; i++)
        for (j=0; j < 4; j++)
          fprintf (stderr, " %d:%c%c",
                   (i-1)*4+j, 
                   (msg[i] & (1<<(j*2)))? 'p':'-',
                   (msg[i] & (2<<(j*2)))? '*':' ');
      putc ('\n', stderr);
    }
  else if (msg[0] == RDR_to_PC_HardwareError)    
    {
      fprintf (stderr, "ccid-driver: hardware error occured\n");
    }
  else
    {
      fprintf (stderr, "ccid-driver: unknown intr-in msg of type %02X\n",
               msg[0]);
    }

  return 0;
}



int 
ccid_slot_status (ccid_driver_t handle)
{
  int rc;
  unsigned char msg[100];
  size_t msglen;
  unsigned char seqno;

  msg[0] = PC_to_RDR_GetSlotStatus;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 0; /* RFU */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  set_msg_len (msg, 0);

  rc = bulk_out (handle, msg, 10);
  if (rc)
    return rc;
  rc = bulk_in (handle, msg, sizeof msg, &msglen);
  if (rc)
    return rc;
  if (msglen < 10)
    {
      fprintf (stderr, "ccid-driver: bulk-in msg too short (%u)\n",
               (unsigned int)msglen);
      return -1;
    }
  if (msg[0] != RDR_to_PC_SlotStatus)
    {
      fprintf (stderr, "ccid-driver: unexpected bulk-in msg type (%02x)\n",
               msg[0]);
      return -1;
    }
  if (msg[5] != 0)    
    {
      fprintf (stderr, "ccid-driver: unexpected bulk-in slot (%d)\n",
               msg[5]);
      return -1;
    }
  if (msg[6] != seqno)    
    {
      fprintf (stderr, "ccid-driver: bulk-in seqno does not match (%d/%d)\n",
               seqno, msg[6]);
      return -1;
    }

  fprintf (stderr,
           "ccid-driver: status: %02X  error: %02X clock-status: %02X\n",
           msg[7], msg[8], msg[9] );

  return 0;
}


int 
ccid_get_atr (ccid_driver_t handle,
              unsigned char *atr, size_t maxatrlen, size_t *atrlen)
{
  int rc;
  unsigned char msg[100];
  size_t msglen;
  unsigned char seqno;
  int i;

  msg[0] = PC_to_RDR_IccPowerOn;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 0; /* power select (0=auto, 1=5V, 2=3V, 3=1.8V) */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  set_msg_len (msg, 0);
  msglen = 10;

  rc = bulk_out (handle, msg, msglen);
  if (rc)
    return rc;
  rc = bulk_in (handle, msg, sizeof msg, &msglen);
  if (rc)
    return rc;
  if (msglen < 10)
    {
      fprintf (stderr, "ccid-driver: bulk-in msg too short (%u)\n",
               (unsigned int)msglen);
      return -1;
    }
  if (msg[0] != RDR_to_PC_DataBlock)
    {
      fprintf (stderr, "ccid-driver: unexpected bulk-in msg type (%02x)\n",
               msg[0]);
      return -1;
    }
  if (msg[5] != 0)    
    {
      fprintf (stderr, "ccid-driver: unexpected bulk-in slot (%d)\n",
               msg[5]);
      return -1;
    }
  if (msg[6] != seqno)    
    {
      fprintf (stderr, "ccid-driver: bulk-in seqno does not match (%d/%d)\n",
               seqno, msg[6]);
      return -1;
    }

  fprintf (stderr,
           "ccid-driver: status: %02X  error: %02X clock-status: %02X\n"
           "               data:",  msg[7], msg[8], msg[9] );
  for (i=10; i < msglen; i++)
    fprintf (stderr, " %02X", msg[i]);
  putc ('\n', stderr);
  
  if (atr)
    {
      size_t n = msglen - 10;

      if (n > maxatrlen)
        n = maxatrlen;
      memcpy (atr, msg+10, n);
      *atrlen = n;
    }

  return 0;
}



/*
  Protocol T=1 overview

  Block Structure:
           Prologue Field:
   1 byte     Node Address (NAD) 
   1 byte     Protocol Control Byte (PCB)
   1 byte     Length (LEN) 
           Information Field:
   0-254 byte APDU or Control Information (INF)
           Epilogue Field:
   1 byte     Error Detection Code (EDC)

  NAD:  
   bit 7     unused
   bit 4..6  Destination Node Address (DAD)
   bit 3     unused
   bit 2..0  Source Node Address (SAD)

   If node adresses are not used, SAD and DAD should be set to 0 on
   the first block sent to the card.  If they are used they should
   have different values (0 for one is okay); that first block sets up
   the addresses of the node.

  PCB:
   Information Block (I-Block):
      bit 7    0
      bit 6    Sequence number (yep, that is modulo 2)
      bit 5    Chaining flag 
      bit 4..0 reserved
   Received-Ready Block (R-Block):
      bit 7    1
      bit 6    0
      bit 5    0
      bit 4    Sequence number
      bit 3..0  0 = no error
                1 = EDC or parity error
                2 = other error
                other values are reserved
   Supervisory Block (S-Block):
      bit 7    1
      bit 6    1
      bit 5    clear=request,set=response
      bit 4..0  0 = resyncronisation request
                1 = information field size request
                2 = abort request
                3 = extension of BWT request
                4 = VPP error
                other values are reserved

*/

int
ccid_transceive (ccid_driver_t handle,
                 const unsigned char *apdu, size_t apdulen,
                 unsigned char *resp, size_t maxresplen, size_t *nresp)
{
  int rc;
  unsigned char msg[10+258], *tpdu, *p;
  size_t msglen;
  unsigned char seqno;
  int i;
  unsigned char crc;

  
  /* Construct an I-Block. */
  if (apdulen > 254)
    return -1; /* Invalid length. */

  tpdu = msg+10;
  tpdu[0] = ((1 << 4) | 0); /* NAD: DAD=1, SAD=0 */
  tpdu[1] = ((handle->t1_seqno & 1) << 6); /* I-block */
  tpdu[2] = apdulen;
  memcpy (tpdu+3, apdu, apdulen);
  crc = 0;
  for (i=0,p=tpdu; i < apdulen+3; i++)
    crc ^= *p++;
  tpdu[3+apdulen] = crc;

  handle->t1_seqno ^= 1;

  msg[0] = PC_to_RDR_XfrBlock;
  msg[5] = 0; /* slot */
  msg[6] = seqno = handle->seqno++;
  msg[7] = 4; /* bBWI */
  msg[8] = 0; /* RFU */
  msg[9] = 0; /* RFU */
  set_msg_len (msg, apdulen+4);
  msglen = 10 + apdulen + 4;

  fprintf (stderr, "ccid-driver: sending");
  for (i=0; i < msglen; i++)
    fprintf (stderr, " %02X", msg[i]);
  putc ('\n', stderr);

  rc = bulk_out (handle, msg, msglen);
  if (rc)
    return rc;
  rc = bulk_in (handle, msg, sizeof msg, &msglen);
  if (rc)
    return rc;
  if (msglen < 10)
    {
      fprintf (stderr, "ccid-driver: bulk-in msg too short (%u)\n",
               (unsigned int)msglen);
      return -1;
    }
  if (msg[0] != RDR_to_PC_DataBlock)
    {
      fprintf (stderr, "ccid-driver: unexpected bulk-in msg type (%02x)\n",
               msg[0]);
      return -1;
    }
  if (msg[5] != 0)    
    {
      fprintf (stderr, "ccid-driver: unexpected bulk-in slot (%d)\n",
               msg[5]);
      return -1;
    }
  if (msg[6] != seqno)    
    {
      fprintf (stderr, "ccid-driver: bulk-in seqno does not match (%d/%d)\n",
               seqno, msg[6]);
      return -1;
    }

  fprintf (stderr,
           "ccid-driver: status: %02X  error: %02X clock-status: %02X\n"
           "               data:",  msg[7], msg[8], msg[9] );
  for (i=10; i < msglen; i++)
    fprintf (stderr, " %02X", msg[i]);
  putc ('\n', stderr);

  if (resp)
    {
      size_t n = msglen - 10;
      
      if (n < 4)
        n = 0; /* fixme: this is an empty I-block or some other block
                  - we ignore it for now until we have implemented the
                  T=1 machinery. */
      else
        {
          p = msg + 10 + 3; /* Skip ccid header and prologue field. */
          n -= 3;
          n--; /* Strip the epilogue field. */
          if (n > maxresplen)
            n = maxresplen; /* fixme: return an error instead of truncating. */
          memcpy (resp, p, n);
        }
      *nresp = n;
    }

  return 0;
}




#ifdef TEST
int
main (int argc, char **argv)
{
  int rc;
  ccid_driver_t ccid;

  rc = ccid_open_reader (&ccid, 0);
  if (rc)
    return 1;

  ccid_poll (ccid);
  fputs ("getting ATR ...\n", stderr);
  rc = ccid_get_atr (ccid, NULL, 0, NULL);
  if (rc)
    return 1;

  ccid_poll (ccid);
  fputs ("getting slot status ...\n", stderr);
  rc = ccid_slot_status (ccid);
  if (rc)
    return 1;

  ccid_poll (ccid);

  {
    static unsigned char apdu[] = {
      0, 0xA4, 4, 0, 6, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
  rc = ccid_transceive (ccid,
                        apdu, sizeof apdu,
                        NULL, 0, NULL);
  }
  ccid_poll (ccid);

  {
    static unsigned char apdu[] = {
      0, 0xCA, 0, 0x65, 254 };
  rc = ccid_transceive (ccid,
                        apdu, sizeof apdu,
                        NULL, 0, NULL);
  }
  ccid_poll (ccid);


  return 0;
}

/*
 * Local Variables:
 *  compile-command: "gcc -DTEST -Wall -I/usr/local/include -lusb -g ccid-driver.c"
 * End:
 */
#endif /*TEST*/
#endif /*HAVE_LIBUSB*/
