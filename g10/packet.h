/* packet.h - packet read/write stuff
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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

typedef enum {
	PKT_NONE	   =0,
	PKT_PUBKEY_ENC	   =1, /* public key encrypted packet */
	PKT_SIGNATURE	   =2, /* secret key encrypted packet */
	PKT_SESSION_KEY    =3, /* session key packet (OpenPGP)*/
	PKT_ONEPASS_SIG    =4, /* one pass sig packet (OpenPGP)*/
	PKT_SECRET_CERT    =5, /* secret key certificate */
	PKT_PUBLIC_CERT    =6, /* public key certificate */
	PKT_SECKEY_SUBCERT =7, /* secret subkey certificate (OpenPGP) */
	PKT_COMPRESSED	   =8, /* compressed data packet */
	PKT_ENCRYPTED	   =9, /* conventional encrypted data */
	PKT_MARKER	  =10, /* marker packet (OpenPGP) */
	PKT_PLAINTEXT	  =11, /* plaintext data with filename and mode */
	PKT_RING_TRUST	  =12, /* keyring trust packet */
	PKT_USER_ID	  =13, /* user id packet */
	PKT_PUBKEY_SUBCERT=14, /* subkey certificate (OpenPGP) */
	PKT_COMMENT	  =16  /* new comment packet (OpenPGP) */
} pkttype_t;

typedef struct packet_struct PACKET;

typedef struct {
    u32     keyid[2];	    /* 64 bit keyid */
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    union {
      struct {
	MPI  a, b;	    /* integers with the encrypteded DEK */
      } elg;
      struct {
	MPI  rsa_integer;   /* integer containing the DEK */
      } rsa;
    } d;
} PKT_pubkey_enc;


typedef struct {
    u32     keyid[2];	    /* 64 bit keyid */
    byte    sig_class;	    /* sig classification */
    byte    digest_algo;    /* algorithm used for digest */
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    byte    last;	    /* a stupid flag */
} PKT_onepass_sig;


typedef struct {
    u32     keyid[2];	    /* 64 bit keyid */
    ulong   local_id;	    /* internal use, valid if > 0 */
    u32     timestamp;	    /* signature made */
    byte    version;
    byte    sig_class;	    /* sig classification, append for MD calculation*/
    byte    pubkey_algo;    /* algorithm used for public key scheme */
			    /* (PUBKEY_ALGO_xxx) */
    byte digest_algo;	    /* algorithm used for digest (DIGEST_ALGO_xxxx) */
    byte *hashed_data;	    /* all subpackets with hashed  data (v4 only) */
    byte *unhashed_data;    /* ditto for unhashed data */
    byte digest_start[2];   /* first 2 bytes of the digest */
    union {
      struct {
	MPI  a, b;	      /* integers with the digest */
      } elg;
      struct {
	MPI  r, s;	      /* integers with the digest */
      } dsa;
      struct {
	MPI  rsa_integer;     /* the encrypted digest */
      } rsa;
    } d;
} PKT_signature;


typedef struct {
    u32     timestamp;	    /* certificate made */
    u16     valid_days;     /* valid for this number of days */
    byte    hdrbytes;	    /* number of header bytes */
    byte    version;
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    ulong   local_id;	    /* internal use, valid if > 0 */
    union {
      struct {
	MPI p;		    /* prime */
	MPI g;		    /* group generator */
	MPI y;		    /* g^x mod p */
      } elg;
      struct {
	MPI p;		    /* prime */
	MPI q;		    /* group order */
	MPI g;		    /* group generator */
	MPI y;		    /* g^x mod p */
      } dsa;
      struct {
	MPI rsa_n;	    /* public modulus */
	MPI rsa_e;	    /* public exponent */
      } rsa;
    } d;
} PKT_public_cert;

typedef struct {
    u32     timestamp;	    /* certificate made */
    u16     valid_days;     /* valid for this number of days */
    byte    hdrbytes;	    /* number of header bytes */
    byte    version;
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    union {
      struct {
	MPI p;		    /* prime */
	MPI g;		    /* group generator */
	MPI y;		    /* g^x mod p */
	MPI x;		    /* secret exponent */
	u16 csum;	    /* checksum */
	byte is_protected;  /* The above infos are protected and must */
			    /* be decrypteded before use. */
	struct {
	    byte algo;	/* cipher used to protect the secret informations*/
	    byte s2k;
	    byte hash;
	    byte salt[8];
	    byte count;
	    byte iv[8]; /* initialization vector for CFB mode */
	} protect;	    /* when protected, the MPIs above are pointers
			     * to plain storage */
      } elg;
      struct {
	MPI p;		    /* prime */
	MPI q;		    /* group order */
	MPI g;		    /* group generator */
	MPI y;		    /* g^x mod p */
	MPI x;		    /* secret exponent */
	u16 csum;	    /* checksum */
	byte is_protected;  /* The above infos are protected and must */
			    /* be decrypteded before use. */
	struct {
	    byte algo;	/* cipher used to protect the secret informations*/
	    byte s2k;
	    byte hash;
	    byte salt[8];
	    byte count;
	    byte iv[8]; /* initialization vector for CFB mode */
	} protect;	    /* when protected, the MPIs above are pointers
			     * to plain storage */
      } dsa;
      struct {
	MPI rsa_n;	    /* public modulus */
	MPI rsa_e;	    /* public exponent */
	MPI rsa_d;	    /* secret descryption exponent */
	MPI rsa_p;	    /* secret first prime number */
	MPI rsa_q;	    /* secret second prime number */
	MPI rsa_u;	    /* secret multiplicative inverse */
	u16 csum;	    /* checksum */
	byte is_protected;  /* The above infos are protected and must */
			    /* be decrypteded before use */
	byte protect_algo;  /* cipher used to protect the secret informations*/
	union { 	    /* information for the protection */
	  struct {
	    byte iv[8];     /* initialization vector for CFB mode */
			    /* when protected, the MPIs above are pointers
			     * to plain storage */
	  } blowfish;
	} protect;
      } rsa;
    } d;
} PKT_secret_cert;


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
} PKT_encrypted;

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
    pkttype_t pkttype;
    union {
	void *generic;
	PKT_pubkey_enc	*pubkey_enc;	/* PKT_PUBKEY_ENC */
	PKT_onepass_sig *onepass_sig;	/* PKT_ONEPASS_SIG */
	PKT_signature	*signature;	/* PKT_SIGNATURE */
	PKT_public_cert *public_cert;	/* PKT_PUBLIC_CERT */
	PKT_secret_cert *secret_cert;	/* PKT_SECRET_CERT */
	PKT_comment	*comment;	/* PKT_COMMENT */
	PKT_user_id	*user_id;	/* PKT_USER_ID */
	PKT_compressed	*compressed;	/* PKT_COMPRESSED */
	PKT_encrypted	*encrypted;	/* PKT_ENCRYPTED */
	PKT_plaintext	*plaintext;	/* PKT_PLAINTEXT */
    } pkt;
};

#define init_packet(a) do { (a)->pkttype = 0;		\
			    (a)->pkt.generic = NULL;	\
		       } while(0)

/*-- mainproc.c --*/
int proc_packets( IOBUF a );
int proc_signature_packets( IOBUF a, STRLIST signedfiles );
int proc_encryption_packets( IOBUF a );
int list_packets( IOBUF a );

/*-- parse-packet.c --*/
int set_packet_list_mode( int mode );
int search_packet( IOBUF inp, PACKET *pkt, int pkttype, ulong *retpos );
int parse_packet( IOBUF inp, PACKET *ret_pkt);
int copy_all_packets( IOBUF inp, IOBUF out );
int copy_some_packets( IOBUF inp, IOBUF out, ulong stopoff );
int skip_some_packets( IOBUF inp, unsigned n );

/*-- build-packet.c --*/
int build_packet( IOBUF inp, PACKET *pkt );
u32 calc_packet_length( PACKET *pkt );
void hash_public_cert( MD_HANDLE md, PKT_public_cert *pkc );

/*-- free-packet.c --*/
void free_pubkey_enc( PKT_pubkey_enc *enc );
void free_seckey_enc( PKT_signature *enc );
int  digest_algo_from_sig( PKT_signature *sig );
void release_public_cert_parts( PKT_public_cert *cert );
void free_public_cert( PKT_public_cert *cert );
void release_secret_cert_parts( PKT_secret_cert *cert );
void free_secret_cert( PKT_secret_cert *cert );
void free_user_id( PKT_user_id *uid );
void free_comment( PKT_comment *rem );
void free_packet( PACKET *pkt );
PKT_public_cert *copy_public_cert( PKT_public_cert *d, PKT_public_cert *s );
PKT_secret_cert *copy_secret_cert( PKT_secret_cert *d, PKT_secret_cert *s );
int cmp_public_certs( PKT_public_cert *a, PKT_public_cert *b );
int cmp_public_secret_cert( PKT_public_cert *pkc, PKT_secret_cert *skc );
int cmp_user_ids( PKT_user_id *a, PKT_user_id *b );


/*-- sig-check.c --*/
int signature_check( PKT_signature *sig, MD_HANDLE digest );

/*-- seckey-cert.c --*/
int is_secret_key_protected( PKT_secret_cert *cert );
int check_secret_key( PKT_secret_cert *cert );
int protect_secret_key( PKT_secret_cert *cert, DEK *dek );

/*-- pubkey-enc.c --*/
int get_session_key( PKT_pubkey_enc *k, DEK *dek );

/*-- compress.c --*/
int handle_compressed( PKT_compressed *cd,
		       int (*callback)(IOBUF, void *), void *passthru );

/*-- encr-data.c --*/
int decrypt_data( PKT_encrypted *ed, DEK *dek );
int encrypt_data( PKT_encrypted *ed, DEK *dek );

/*-- plaintext.c --*/
int handle_plaintext( PKT_plaintext *pt, md_filter_context_t *mfx );
int ask_for_detached_datafile( md_filter_context_t *mfx, const char *inname );

/*-- comment.c --*/
int write_comment( IOBUF out, const char *s );

/*-- sign.c --*/
int make_keysig_packet( PKT_signature **ret_sig, PKT_public_cert *pkc,
			PKT_user_id *uid, PKT_secret_cert *skc,
			int sigclass, int digest_algo );

#endif /*G10_PACKET_H*/
