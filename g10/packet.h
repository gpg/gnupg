/* packet.h - packet read/write stuff
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef G10_PACKET_H
#define G10_PACKET_H

#include "types.h"
#include "iobuf.h"
#include "mpi.h"
#include "cipher.h"
#include "filter.h"


#define PKT_PUBKEY_ENC	 1  /* public key encrypted packet */
#define PKT_SIGNATURE	 2  /* secret key encrypted packet */
#define PKT_SECKEY_CERT  5  /* secret key certificate */
#define PKT_PUBKEY_CERT  6  /* public key certificate */
#define PKT_COMPR_DATA	 8  /* compressed data packet */
#define PKT_ENCR_DATA	 9  /* conventional encrypted data */
#define PKT_PLAINTEXT	11  /* plaintext data with filename and mode */
#define PKT_RING_TRUST	12  /* keyring trust packet */
#define PKT_USER_ID	13  /* user id packet */
#define PKT_COMMENT	14  /* comment packet */

typedef struct packet_struct PACKET;

typedef struct {
    u32     keyid[2];	    /* 64 bit keyid */
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    union {
      struct {
	MPI  rsa_integer;   /* integer containing the DEK */
      } rsa;
    } d;
} PKT_pubkey_enc;


typedef struct {
    u32     keyid[2];	    /* 64 bit keyid */
    u32     timestamp;	    /* signature made */
    byte    sig_class;	    /* sig classification, append for MD calculation*/
    byte    pubkey_algo;    /* algorithm used for public key scheme */
			    /* (PUBKEY_ALGO_xxx) */
    union {
      struct {
	byte digest_algo;   /* algorithm used for digest (DIGEST_ALGO_xxxx) */
	byte digest_start[2]; /* first 2 byte of the digest */
	MPI  rsa_integer;   /* the encrypted digest */
      } rsa;
    } d;
} PKT_signature;


typedef struct {
    u32     timestamp;	    /* certificate made */
    u16     valid_days;     /* valid for this number of days */
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    md_filter_context_t mfx;
    union {
      struct {
	MPI rsa_n;	    /* public modulus */
	MPI rsa_e;	    /* public exponent */
      } rsa;
    } d;
} PKT_pubkey_cert;

typedef struct {
    u32     timestamp;	    /* certificate made */
    u16     valid_days;     /* valid for this number of days */
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    union {
      struct {
	MPI rsa_n;	    /* public modulus */
	MPI rsa_e;	    /* public exponent */
	MPI rsa_d;	    /* secret descryption exponent */
	MPI rsa_p;	    /* secret first prime number */
	MPI rsa_q;	    /* secret second prime number */
	MPI rsa_u;	    /* secret multiplicative inverse */
	u16 csum;	    /* checksum */
	u16 calc_csum;	    /* and a place to store the calculated csum */
	byte is_protected;  /* The above infos are protected and must */
			    /* be deciphered before use */
	byte protect_algo;  /* cipher used to protect the secret informations*/
	union { 	    /* information for the protection */
	  struct {
	    byte iv[8];     /* initialization vector for CFB mode */
			    /* when protected, the MPIs above are pointers
			     * to plain storage */
	  } idea;
	  struct {
	    byte iv[8];
	  } blowfish;
	} protect;
      } rsa;
    } d;
} PKT_seckey_cert;


typedef struct {
    int  len;		  /* length of data */
    char data[1];
} PKT_comment;

typedef struct {
    int  len;		  /* length of the name */
    char name[1];
} PKT_user_id;

typedef struct {
    u32  len;		  /* reserved */
    byte  algorithm;
    IOBUF buf;		  /* IOBUF reference */
} PKT_compressed;

typedef struct {
    u32  len;		  /* length of encrypted data */
    IOBUF buf;		  /* IOBUF reference */
} PKT_encr_data;

typedef struct {
    u32  len;		  /* length of encrypted data */
    IOBUF buf;		  /* IOBUF reference */
    int mode;
    u32 timestamp;
    int  namelen;
    char name[1];
} PKT_plaintext;

/* combine all packets into a union */
struct packet_struct {
    int pkttype;
    PKT_pubkey_cert *pkc_parent;     /* the pubkey to which it belongs */
    PKT_seckey_cert *skc_parent;      /* the seckey to which it belongs */
    PKT_user_id     *user_parent;     /* the user_id to which it belongs */
    union {
	void *generic;
	PKT_pubkey_enc *pubkey_enc;	/* PKT_PUBKEY_ENC */
	PKT_signature *signature;	/* PKT_SIGNATURE */
	PKT_pubkey_cert *pubkey_cert;	/* PKT_PUBKEY_CERT */
	PKT_seckey_cert *seckey_cert;	/* PKT_SECKEY_CERT */
	PKT_comment	*comment;	/* PKT_COMMENT */
	PKT_user_id	*user_id;	/* PKT_USER_ID */
	PKT_compressed	*compressed;	/* PKT_COMPRESSED */
	PKT_encr_data	*encr_data;	/* PKT_ENCR_DATA */
	PKT_plaintext	*plaintext;	/* PKT_PLAINTEXT */
    } pkt;
};

#define init_packet(a) do { (a)->pkttype = 0;		\
			    (a)->pkc_parent = NULL;	\
			    (a)->skc_parent = NULL;	\
			    (a)->user_parent = NULL;	\
			    (a)->pkt.generic = NULL;	\
		       } while(0)

/*-- mainproc.c --*/
int proc_packets( IOBUF a );

/*-- parse-packet.c --*/
int set_packet_list_mode( int mode );
int parse_packet( IOBUF inp, PACKET *ret_pkt);

/*-- build-packet.c --*/
int build_packet( IOBUF inp, PACKET *pkt );
u32 calc_packet_length( PACKET *pkt );

/*-- free-packet.c --*/
void free_pubkey_enc( PKT_pubkey_enc *enc );
void free_seckey_enc( PKT_signature *enc );
void free_pubkey_cert( PKT_pubkey_cert *cert );
void free_seckey_cert( PKT_seckey_cert *cert );
void free_user_id( PKT_user_id *uid );
void free_comment( PKT_comment *rem );
void free_packet( PACKET *pkt );
PKT_pubkey_cert *copy_pubkey_cert( PKT_pubkey_cert *d, PKT_pubkey_cert *s );


/*-- sig-check.c --*/
int signature_check( PKT_signature *sig, MD_HANDLE digest );

/*-- seckey-cert.c --*/
int check_secret_key( PKT_seckey_cert *cert );

/*-- pubkey-enc.c --*/
int get_session_key( PKT_pubkey_enc *k, DEK *dek );

/*-- compressed.c --*/
int handle_compressed( PKT_compressed *zd );

/*-- encr-data.c --*/
int decrypt_data( PKT_encr_data *ed, DEK *dek );
int encrypt_data( PKT_encr_data *ed, DEK *dek );

/*-- plaintext.c --*/
int handle_plaintext( PKT_plaintext *pt );

#endif /*G10_PACKET_H*/
