/* packet.h - packet definitions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
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

#ifndef G10_PACKET_H
#define G10_PACKET_H

#include "types.h"
#include "iobuf.h"
#include "mpi.h"
#include "cipher.h"
#include "filter.h"
#include "global.h"

#define DEBUG_PARSE_PACKET 1

typedef enum {
	PKT_NONE	   =0,
	PKT_PUBKEY_ENC	   =1, /* public key encrypted packet */
	PKT_SIGNATURE	   =2, /* secret key encrypted packet */
	PKT_SYMKEY_ENC	   =3, /* session key packet (OpenPGP)*/
	PKT_ONEPASS_SIG    =4, /* one pass sig packet (OpenPGP)*/
	PKT_SECRET_KEY	   =5, /* secret key */
	PKT_PUBLIC_KEY	   =6, /* public key */
	PKT_SECRET_SUBKEY  =7, /* secret subkey (OpenPGP) */
	PKT_COMPRESSED	   =8, /* compressed data packet */
	PKT_ENCRYPTED	   =9, /* conventional encrypted data */
	PKT_MARKER	  =10, /* marker packet (OpenPGP) */
	PKT_PLAINTEXT	  =11, /* plaintext data with filename and mode */
	PKT_RING_TRUST	  =12, /* keyring trust packet */
	PKT_USER_ID	  =13, /* user id packet */
	PKT_PUBLIC_SUBKEY =14, /* public subkey (OpenPGP) */
	PKT_OLD_COMMENT   =16, /* comment packet from an OpenPGP draft */
	PKT_ATTRIBUTE     =17, /* PGP's attribute packet */
	PKT_ENCRYPTED_MDC =18, /* integrity protected encrypted data */
	PKT_MDC 	  =19, /* manipulation detection code packet */
	PKT_COMMENT	  =61, /* new comment packet (private) */
        PKT_GPG_CONTROL   =63  /* internal control packet */
} pkttype_t;

typedef struct packet_struct PACKET;

/* PKT_GPG_CONTROL types */
typedef enum {
    CTRLPKT_CLEARSIGN_START = 1,
    CTRLPKT_PIPEMODE = 2,
    CTRLPKT_PLAINTEXT_MARK =3
} ctrlpkttype_t;

typedef enum {
    PREFTYPE_NONE = 0,
    PREFTYPE_SYM = 1,
    PREFTYPE_HASH = 2,
    PREFTYPE_ZIP = 3
} preftype_t;

typedef struct {
    byte type; 
    byte value;
} prefitem_t;

typedef struct {
    int  mode;
    byte hash_algo;
    byte salt[8];
    u32  count;
} STRING2KEY;

typedef struct {
    byte version;
    byte cipher_algo;	 /* cipher algorithm used */
    STRING2KEY s2k;
    byte seskeylen;   /* keylength in byte or 0 for no seskey */
    byte seskey[1];
} PKT_symkey_enc;

typedef struct {
    u32     keyid[2];	    /* 64 bit keyid */
    byte    version;
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    byte    throw_keyid;
    MPI     data[PUBKEY_MAX_NENC];
} PKT_pubkey_enc;


typedef struct {
    u32     keyid[2];	    /* 64 bit keyid */
    byte    sig_class;	    /* sig classification */
    byte    digest_algo;    /* algorithm used for digest */
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    byte    last;	    /* a stupid flag */
} PKT_onepass_sig;


typedef struct {
    size_t size;  /* allocated */
    size_t len;   /* used */
    byte data[1];
} subpktarea_t;

struct revocation_key {
  byte class;
  byte algid;
  byte fpr[MAX_FINGERPRINT_LEN];
};


/* Object to keep information about a PKA DNS record. */
typedef struct
{
  int valid;    /* An actual PKA record exists for EMAIL. */
  int checked;  /* Set to true if the FPR has been checked against the
                   actual key. */
  char *uri;    /* Malloced string with the URI. NULL if the URI is
                   not available.*/
  unsigned char fpr[20]; /* The fingerprint as stored in the PKA RR. */
  char email[1];/* The email address from the notation data. */
} pka_info_t;


/* Object to keep information pertaining to a signature. */
typedef struct 
{
  struct 
  {
    unsigned checked:1;         /* Signature has been checked. */
    unsigned valid:1;           /* Signature is good (if checked is set). */
    unsigned chosen_selfsig:1;  /* A selfsig that is the chosen one. */
    unsigned unknown_critical:1;
    unsigned exportable:1;
    unsigned revocable:1;
    unsigned policy_url:1;  /* At least one policy URL is present */
    unsigned notation:1;    /* At least one notation is present */
    unsigned pref_ks:1;     /* At least one preferred keyserver is present */
    unsigned expired:1;
    unsigned pka_tried:1;   /* Set if we tried to retrieve the PKA record. */
  } flags;
  u32     keyid[2];	  /* 64 bit keyid */
  u32     timestamp;	  /* Signature made (seconds since Epoch). */
  u32     expiredate;     /* Expires at this date or 0 if not at all. */
  byte    version;
  byte    sig_class;	  /* Sig classification, append for MD calculation. */
  byte    pubkey_algo;    /* Algorithm used for public key scheme */
                          /* (PUBKEY_ALGO_xxx) */
  byte    digest_algo;    /* Algorithm used for digest (DIGEST_ALGO_xxxx). */
  byte    trust_depth;
  byte    trust_value;
  const byte *trust_regexp;
  struct revocation_key **revkey;
  int numrevkeys;
  pka_info_t *pka_info;      /* Malloced PKA data or NULL if not
                                available.  See also flags.pka_tried. */
  subpktarea_t *hashed;      /* All subpackets with hashed data (v4 only). */
  subpktarea_t *unhashed;    /* Ditto for unhashed data. */
  byte digest_start[2];      /* First 2 bytes of the digest. */
  MPI  data[PUBKEY_MAX_NSIG];
} PKT_signature;

#define ATTRIB_IMAGE 1

/* This is the cooked form of attributes */
struct user_attribute {
  byte type;
  const byte *data;
  u32 len;
};

typedef struct
{
  int ref;              /* reference counter */
  int len;	        /* length of the name */
  struct user_attribute *attribs;
  int numattribs;
  byte *attrib_data;    /* if this is not NULL, the packet is an attribute */
  unsigned long attrib_len;
  byte *namehash;
  int help_key_usage;
  u32 help_key_expire;
  int help_full_count;
  int help_marginal_count;
  int is_primary;       /* 2 if set via the primary flag, 1 if calculated */
  int is_revoked;
  int is_expired;
  u32 expiredate;       /* expires at this date or 0 if not at all */
  prefitem_t *prefs;    /* list of preferences (may be NULL)*/
  u32 created;          /* according to the self-signature */
  byte selfsigversion;
  struct
  {
    /* TODO: Move more flags here */
    unsigned mdc:1;
    unsigned ks_modify:1;
    unsigned compacted:1;
  } flags;
  char name[1];
} PKT_user_id;

struct revoke_info
{
  /* revoked at this date */
  u32 date;
  /* the keyid of the revoking key (selfsig or designated revoker) */
  u32 keyid[2];
  /* the algo of the revoking key */
  byte algo;
};

/****************
 * Note about the pkey/skey elements:  We assume that the secret keys
 * has the same elemts as the public key at the begin of the array, so
 * that npkey < nskey and it is possible to compare the secret and
 * public keys by comparing the first npkey elements of pkey againts skey.
 */
typedef struct {
    u32     timestamp;	    /* key made */
    u32     expiredate;     /* expires at this date or 0 if not at all */
    u32     max_expiredate; /* must not expire past this date */
    struct revoke_info revoked;
    byte    hdrbytes;	    /* number of header bytes */
    byte    version;
    byte    selfsigversion; /* highest version of all of the self-sigs */
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    byte    pubkey_usage;   /* for now only used to pass it to getkey() */
    byte    req_usage;      /* hack to pass a request to getkey() */
    byte    req_algo;       /* Ditto */
    u32     has_expired;    /* set to the expiration date if expired */ 
    int     is_revoked;     /* key has been revoked, 1 if by the
			       owner, 2 if by a designated revoker */
    int     maybe_revoked;  /* a designated revocation is present, but
			       without the key to check it */
    int     is_valid;       /* key (especially subkey) is valid */
    int     dont_cache;     /* do not cache this */
    byte    backsig;        /* 0=none, 1=bad, 2=good */
    u32     main_keyid[2];  /* keyid of the primary key */
    u32     keyid[2];	    /* calculated by keyid_from_pk() */
    byte    is_primary;
    byte    is_disabled;    /* 0 for unset, 1 for enabled, 2 for disabled. */
    prefitem_t *prefs;      /* list of preferences (may be NULL) */
    int     mdc_feature;    /* mdc feature set */
    PKT_user_id *user_id;   /* if != NULL: found by that uid */
    struct revocation_key *revkey;
    int     numrevkeys;
    u32     trust_timestamp;
    byte    trust_depth;
    byte    trust_value;
    const byte *trust_regexp;
    MPI     pkey[PUBKEY_MAX_NPKEY];
} PKT_public_key;

/* Evaluates as true if the pk is disabled, and false if it isn't.  If
   there is no disable value cached, fill one in. */
#define pk_is_disabled(a) (((a)->is_disabled)?((a)->is_disabled==2):(cache_disabled_value((a))))

typedef struct {
    u32     timestamp;	    /* key made */
    u32     expiredate;     /* expires at this date or 0 if not at all */
    u32     max_expiredate; /* must not expire past this date */
    byte    hdrbytes;	    /* number of header bytes */
    byte    version;
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    byte    pubkey_usage;
    byte    req_usage;
    byte    req_algo;
    u32     has_expired;    /* set to the expiration date if expired */ 
    int     is_revoked;     /* key has been revoked */
    int     is_valid;       /* key (especially subkey) is valid */
    u32     main_keyid[2];  /* keyid of the primary key */
    u32     keyid[2];   
    byte is_primary;
    byte is_protected;	/* The secret info is protected and must */
			/* be decrypted before use, the protected */
			/* MPIs are simply (void*) pointers to memory */
			/* and should never be passed to a mpi_xxx() */
    struct {
	byte algo;  /* cipher used to protect the secret information*/
        byte sha1chk;  /* SHA1 is used instead of a 16 bit checksum */ 
	STRING2KEY s2k;
	byte ivlen;  /* used length of the iv */
	byte iv[16]; /* initialization vector for CFB mode */
    } protect;
    MPI skey[PUBKEY_MAX_NSKEY];
    u16 csum;		/* checksum */
} PKT_secret_key;


typedef struct {
    int  len;		  /* length of data */
    char data[1];
} PKT_comment;

typedef struct {
    u32  len;		  /* reserved */
    byte  new_ctb;
    byte  algorithm;
    IOBUF buf;		  /* IOBUF reference */
} PKT_compressed;

typedef struct {
    u32  len;		  /* length of encrypted data */
    int  extralen;        /* this is (blocksize+2) */
    byte new_ctb;	  /* uses a new CTB */
    byte is_partial;      /* partial length encoded */
    byte mdc_method;	  /* > 0: integrity protected encrypted data packet */
    IOBUF buf;		  /* IOBUF reference */
} PKT_encrypted;

typedef struct {
    byte hash[20];
} PKT_mdc;

typedef struct {
    unsigned int trustval;
    unsigned int sigcache;
} PKT_ring_trust;

typedef struct {
    u32  len;		  /* length of encrypted data */
    IOBUF buf;		  /* IOBUF reference */
    byte new_ctb;
    byte is_partial;      /* partial length encoded */
    int mode;
    u32 timestamp;
    int  namelen;
    char name[1];
} PKT_plaintext;

typedef struct {
    int  control;
    size_t datalen;
    char data[1];
} PKT_gpg_control;

/* combine all packets into a union */
struct packet_struct {
    pkttype_t pkttype;
    union {
	void *generic;
	PKT_symkey_enc	*symkey_enc;	/* PKT_SYMKEY_ENC */
	PKT_pubkey_enc	*pubkey_enc;	/* PKT_PUBKEY_ENC */
	PKT_onepass_sig *onepass_sig;	/* PKT_ONEPASS_SIG */
	PKT_signature	*signature;	/* PKT_SIGNATURE */
	PKT_public_key	*public_key;	/* PKT_PUBLIC_[SUB)KEY */
	PKT_secret_key	*secret_key;	/* PKT_SECRET_[SUB]KEY */
	PKT_comment	*comment;	/* PKT_COMMENT */
	PKT_user_id	*user_id;	/* PKT_USER_ID */
	PKT_compressed	*compressed;	/* PKT_COMPRESSED */
	PKT_encrypted	*encrypted;	/* PKT_ENCRYPTED[_MDC] */
	PKT_mdc 	*mdc;		/* PKT_MDC */
	PKT_ring_trust	*ring_trust;	/* PKT_RING_TRUST */
	PKT_plaintext	*plaintext;	/* PKT_PLAINTEXT */
        PKT_gpg_control *gpg_control;   /* PKT_GPG_CONTROL */
    } pkt;
};

#define init_packet(a) do { (a)->pkttype = 0;		\
			    (a)->pkt.generic = NULL;	\
		       } while(0)

typedef enum {
    SIGSUBPKT_TEST_CRITICAL=-3,
    SIGSUBPKT_LIST_UNHASHED=-2,
    SIGSUBPKT_LIST_HASHED  =-1,
    SIGSUBPKT_NONE	   = 0,
    SIGSUBPKT_SIG_CREATED  = 2, /* signature creation time */
    SIGSUBPKT_SIG_EXPIRE   = 3, /* signature expiration time */
    SIGSUBPKT_EXPORTABLE   = 4, /* exportable */
    SIGSUBPKT_TRUST	   = 5, /* trust signature */
    SIGSUBPKT_REGEXP	   = 6, /* regular expression */
    SIGSUBPKT_REVOCABLE    = 7, /* revocable */
    SIGSUBPKT_KEY_EXPIRE   = 9, /* key expiration time */
    SIGSUBPKT_ARR	   =10, /* additional recipient request */
    SIGSUBPKT_PREF_SYM	   =11, /* preferred symmetric algorithms */
    SIGSUBPKT_REV_KEY	   =12, /* revocation key */
    SIGSUBPKT_ISSUER	   =16, /* issuer key ID */
    SIGSUBPKT_NOTATION	   =20, /* notation data */
    SIGSUBPKT_PREF_HASH    =21, /* preferred hash algorithms */
    SIGSUBPKT_PREF_COMPR   =22, /* preferred compression algorithms */
    SIGSUBPKT_KS_FLAGS	   =23, /* key server preferences */
    SIGSUBPKT_PREF_KS	   =24, /* preferred key server */
    SIGSUBPKT_PRIMARY_UID  =25, /* primary user id */
    SIGSUBPKT_POLICY	   =26, /* policy URL */
    SIGSUBPKT_KEY_FLAGS    =27, /* key flags */
    SIGSUBPKT_SIGNERS_UID  =28, /* signer's user id */
    SIGSUBPKT_REVOC_REASON =29, /* reason for revocation */
    SIGSUBPKT_FEATURES     =30, /* feature flags */

    SIGSUBPKT_SIGNATURE    =32, /* embedded signature */

    SIGSUBPKT_FLAG_CRITICAL=128
} sigsubpkttype_t;

struct notation
{
  char *name;
  char *value;
  char *altvalue;
  unsigned char *bdat;
  size_t blen;
  struct
  {
    unsigned int critical:1;
    unsigned int ignore:1;
  } flags;
  struct notation *next;
};

/*-- mainproc.c --*/
void reset_literals_seen(void);
int proc_packets( void *ctx, IOBUF a );
int proc_signature_packets( void *ctx, IOBUF a,
			    STRLIST signedfiles, const char *sigfile );
int proc_encryption_packets( void *ctx, IOBUF a );
int list_packets( IOBUF a );

/*-- parse-packet.c --*/
int set_packet_list_mode( int mode );

#if DEBUG_PARSE_PACKET
int dbg_search_packet( IOBUF inp, PACKET *pkt, off_t *retpos, int with_uid,
                       const char* file, int lineno  );
int dbg_parse_packet( IOBUF inp, PACKET *ret_pkt,
                      const char* file, int lineno );
int dbg_copy_all_packets( IOBUF inp, IOBUF out,
                          const char* file, int lineno  );
int dbg_copy_some_packets( IOBUF inp, IOBUF out, off_t stopoff,
                           const char* file, int lineno  );
int dbg_skip_some_packets( IOBUF inp, unsigned n,
                           const char* file, int lineno	);
#define search_packet( a,b,c,d )   \
             dbg_search_packet( (a), (b), (c), (d), __FILE__, __LINE__ )
#define parse_packet( a, b )  \
	     dbg_parse_packet( (a), (b), __FILE__, __LINE__ )
#define copy_all_packets( a,b )  \
             dbg_copy_all_packets((a),(b), __FILE__, __LINE__ )
#define copy_some_packets( a,b,c ) \
             dbg_copy_some_packets((a),(b),(c), __FILE__, __LINE__ )
#define skip_some_packets( a,b ) \
             dbg_skip_some_packets((a),(b), __FILE__, __LINE__ )
#else
int search_packet( IOBUF inp, PACKET *pkt, off_t *retpos, int with_uid );
int parse_packet( IOBUF inp, PACKET *ret_pkt);
int copy_all_packets( IOBUF inp, IOBUF out );
int copy_some_packets( IOBUF inp, IOBUF out, off_t stopoff );
int skip_some_packets( IOBUF inp, unsigned n );
#endif

int parse_signature( IOBUF inp, int pkttype, unsigned long pktlen,
		     PKT_signature *sig );
const byte *enum_sig_subpkt ( const subpktarea_t *subpkts,
                              sigsubpkttype_t reqtype,
                              size_t *ret_n, int *start, int *critical );
const byte *parse_sig_subpkt ( const subpktarea_t *buffer,
                               sigsubpkttype_t reqtype,
                               size_t *ret_n );
const byte *parse_sig_subpkt2 ( PKT_signature *sig,
                                sigsubpkttype_t reqtype,
                                size_t *ret_n );
int parse_one_sig_subpkt( const byte *buffer, size_t n, int type );
void parse_revkeys(PKT_signature *sig);
int parse_attribute_subpkts(PKT_user_id *uid);
void make_attribute_uidname(PKT_user_id *uid, size_t max_namelen);
PACKET *create_gpg_control ( ctrlpkttype_t type,
                             const byte *data,
                             size_t datalen );

/*-- build-packet.c --*/
int build_packet( IOBUF inp, PACKET *pkt );
u32 calc_packet_length( PACKET *pkt );
void build_sig_subpkt( PKT_signature *sig, sigsubpkttype_t type,
			const byte *buffer, size_t buflen );
void build_sig_subpkt_from_sig( PKT_signature *sig );
int  delete_sig_subpkt(subpktarea_t *buffer, sigsubpkttype_t type );
void build_attribute_subpkt(PKT_user_id *uid,byte type,
			    const void *buf,u32 buflen,
			    const void *header,u32 headerlen);
struct notation *string_to_notation(const char *string,int is_utf8);
struct notation *sig_to_notation(PKT_signature *sig);
void free_notation(struct notation *notation);

/*-- free-packet.c --*/
void free_symkey_enc( PKT_symkey_enc *enc );
void free_pubkey_enc( PKT_pubkey_enc *enc );
void free_seckey_enc( PKT_signature *enc );
int  digest_algo_from_sig( PKT_signature *sig );
void release_public_key_parts( PKT_public_key *pk );
void free_public_key( PKT_public_key *key );
void release_secret_key_parts( PKT_secret_key *sk );
void free_secret_key( PKT_secret_key *sk );
void free_attributes(PKT_user_id *uid);
void free_user_id( PKT_user_id *uid );
void free_comment( PKT_comment *rem );
void free_packet( PACKET *pkt );
prefitem_t *copy_prefs (const prefitem_t *prefs);
PKT_public_key *copy_public_key( PKT_public_key *d, PKT_public_key *s );
void copy_public_parts_to_secret_key( PKT_public_key *pk, PKT_secret_key *sk );
PKT_secret_key *copy_secret_key( PKT_secret_key *d, PKT_secret_key *s );
PKT_signature *copy_signature( PKT_signature *d, PKT_signature *s );
PKT_user_id *scopy_user_id (PKT_user_id *sd );
int cmp_public_keys( PKT_public_key *a, PKT_public_key *b );
int cmp_secret_keys( PKT_secret_key *a, PKT_secret_key *b );
int cmp_signatures( PKT_signature *a, PKT_signature *b );
int cmp_public_secret_key( PKT_public_key *pk, PKT_secret_key *sk );
int cmp_user_ids( PKT_user_id *a, PKT_user_id *b );


/*-- sig-check.c --*/
int signature_check( PKT_signature *sig, MD_HANDLE digest );
int signature_check2( PKT_signature *sig, MD_HANDLE digest, u32 *r_expiredate,
		      int *r_expired, int *r_revoked, PKT_public_key *ret_pk );

/*-- seckey-cert.c --*/
int is_secret_key_protected( PKT_secret_key *sk );
int check_secret_key( PKT_secret_key *sk, int retries );
int protect_secret_key( PKT_secret_key *sk, DEK *dek );

/*-- pubkey-enc.c --*/
int get_session_key( PKT_pubkey_enc *k, DEK *dek );
int get_override_session_key( DEK *dek, const char *string );

/*-- compress.c --*/
int handle_compressed( void *ctx, PKT_compressed *cd,
		       int (*callback)(IOBUF, void *), void *passthru );

/*-- encr-data.c --*/
int decrypt_data( void *ctx, PKT_encrypted *ed, DEK *dek );

/*-- plaintext.c --*/
int handle_plaintext( PKT_plaintext *pt, md_filter_context_t *mfx,
					int nooutput, int clearsig );
int ask_for_detached_datafile( MD_HANDLE md, MD_HANDLE md2,
			       const char *inname, int textmode );

/*-- sign.c --*/
int make_keysig_packet( PKT_signature **ret_sig, PKT_public_key *pk,
			PKT_user_id *uid, PKT_public_key *subpk,
			PKT_secret_key *sk, int sigclass, int digest_algo,
			int sigversion, u32 timestamp, u32 duration,
			int (*mksubpkt)(PKT_signature *, void *),
			void *opaque  );
int update_keysig_packet( PKT_signature **ret_sig,
                      PKT_signature *orig_sig,
                      PKT_public_key *pk,
                      PKT_user_id *uid,
                      PKT_public_key *subpk,
                      PKT_secret_key *sk,
                      int (*mksubpkt)(PKT_signature *, void *),
                      void *opaque   );

/*-- keygen.c --*/
PKT_user_id *generate_user_id(void);

#endif /*G10_PACKET_H*/
