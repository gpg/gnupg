/* gpga-prot.h  - GnuPG Agent protocol definition
 *	Copyright (C) 2000 Free Software Foundation, Inc.
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

/*
 * The gpg-agent protocol:
 * The protocol is connection based and runs over a Unix Domain socket.
 * The client requests a service from the server and waits for the result.
 * A connection request starts with a magic string to transfer the
 * version number the followed by the regular traffic.  All numbers
 * are transfered in network-byte-order, strings are prefixed with a
 * 32 bit length and NOT 0 terminated.
 * The magic string is:
 *  0x47, 0x50, 0x47, 0x41, 0x00, 0x00, 0x00, 0x01
 * which nicely fits into 2 32 bit words.
 * The server does not respond to this magic string if the protocol
   is supported; otherwise it will return an error packet and close
   the connection.
   Standard request and reply packets are composed like this
   u32     Length of following packet ( 4 <= n < 2048 )
   u32     Request/Reply type or error code
   n-bytes Data specific to the request/reply

   Request codes are just the given number,
   Reply codes are all to be ORed with 0x00010000,
   Error codes are all to be ORer with 0x00020000.

   Requests:
   =========
   GET_VERSION 

   GET_PASSPHRASE, expected data:
       20 Bytes fingerprint of the key 
                (use all zeroes to get a passphrase not associated with a key)
        n Bytes with the text to be displayed in case the
          passphrase is not cached or the fingerprint was all zero.

   CLEAR_PASSPHRASE, expected data:
       20 Bytes fingerprint of the key
 
       Returns either OKAY or NO_PASSPHRASE

   HAVE_PASSPHRASE, expected data:
       20 Bytes fingerprint of the key

       Returns either OKAY or NO_PASSPHRASE


   Replies:
   ========
   OKAY (reply code 1)
      Data may be interpreted as the version string

   GOT_PASSPHRASE (reply code 2)
       u32     Length of passphrase 
       n bytes passphrase
       m bytes padding so that the packets have some standard length

  
   Error Replies:
   ==============
   PROTOCOL_ERROR 
       no data yes specified

   CANCELED  
       User canceled the input

   NO_PASSPHRASE 
       No user intercation possible and passphrase not available.
       Also return as answer on HAVE_PASSPHRASE etc.
       
   BAD_PASSPHRASE 
       Returned when the user does not repeat the passphrase correctly

   INVALID_DATA 

 */



#ifndef GPG_GPGA_PROT_H
#define GPG_GPGA_PROT_H 1

enum gpga_protocol_codes {
    /* Request codes */
    GPGA_PROT_GET_VERSION     = 1,
    GPGA_PROT_GET_PASSPHRASE  = 2,
    GPGA_PROT_CLEAR_PASSPHRASE= 3,
    GPGA_PROT_SHUTDOWN        = 4,

    /* Reply codes */
    GPGA_PROT_REPLY_BASE     = 0x10000,
    GPGA_PROT_OKAY           = 0x10001,
    GPGA_PROT_GOT_PASSPHRASE = 0x10002,

    /* Error codes */
    GPGA_PROT_ERROR_BASE     = 0x20000,
    GPGA_PROT_PROTOCOL_ERROR = 0x20001,
    GPGA_PROT_INVALID_REQUEST= 0x20002,
    GPGA_PROT_CANCELED       = 0x20003,    
    GPGA_PROT_NO_PASSPHRASE  = 0x20004,    
    GPGA_PROT_BAD_PASSPHRASE = 0x20005,
    GPGA_PROT_INVALID_DATA   = 0x20006,
    GPGA_PROT_NOT_IMPLEMENTED= 0x20007,
    GPGA_PROT_UI_PROBLEM     = 0x20008,
};



#endif /*GPG_GPGA_PROT_H*/
