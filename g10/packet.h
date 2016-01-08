/* packet.h - OpenPGP packet definitions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
 * Copyright (C) 2015 g10 Code GmbH
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
#include "../common/iobuf.h"
#include "../common/strlist.h"
#include "dek.h"
#include "filter.h"
#include "../common/openpgpdefs.h"
#include "../common/userids.h"

#define DEBUG_PARSE_PACKET 1


/* Constants to allocate static MPI arrays. */
#define PUBKEY_MAX_NPKEY  5
#define PUBKEY_MAX_NSKEY  7
#define PUBKEY_MAX_NSIG   2
#define PUBKEY_MAX_NENC   2

/* Usage flags */
#define PUBKEY_USAGE_SIG     GCRY_PK_USAGE_SIGN  /* Good for signatures. */
#define PUBKEY_USAGE_ENC     GCRY_PK_USAGE_ENCR  /* Good for encryption. */
#define PUBKEY_USAGE_CERT    GCRY_PK_USAGE_CERT  /* Also good to certify keys.*/
#define PUBKEY_USAGE_AUTH    GCRY_PK_USAGE_AUTH  /* Good for authentication. */
#define PUBKEY_USAGE_UNKNOWN GCRY_PK_USAGE_UNKN  /* Unknown usage flag. */
#define PUBKEY_USAGE_NONE    256                 /* No usage given. */
#if  (GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR | GCRY_PK_USAGE_CERT \
      | GCRY_PK_USAGE_AUTH | GCRY_PK_USAGE_UNKN) >= 256
# error Please choose another value for PUBKEY_USAGE_NONE
#endif

/* Helper macros.  */
#define is_RSA(a)     ((a)==PUBKEY_ALGO_RSA || (a)==PUBKEY_ALGO_RSA_E \
		       || (a)==PUBKEY_ALGO_RSA_S )
#define is_ELGAMAL(a) ((a)==PUBKEY_ALGO_ELGAMAL_E)
#define is_DSA(a)     ((a)==PUBKEY_ALGO_DSA)

/* A pointer to the packet object.  */
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

typedef struct
{
  int  mode;      /* Must be an integer due to the GNU modes 1001 et al.  */
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
    gcry_mpi_t     data[PUBKEY_MAX_NENC];
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
  struct revocation_key *revkey;
  int numrevkeys;
  pka_info_t *pka_info;      /* Malloced PKA data or NULL if not
                                available.  See also flags.pka_tried. */
  subpktarea_t *hashed;      /* All subpackets with hashed data (v4 only). */
  subpktarea_t *unhashed;    /* Ditto for unhashed data. */
  byte digest_start[2];      /* First 2 bytes of the digest. */
  gcry_mpi_t  data[PUBKEY_MAX_NSIG];
  /* The message digest and its length (in bytes).  Note the maximum
     digest length is 512 bits (64 bytes).  If DIGEST_LEN is 0, then
     the digest's value has not been saved here.  */
  byte digest[512 / 8];
  int digest_len;
} PKT_signature;

#define ATTRIB_IMAGE 1

/* This is the cooked form of attributes.  */
struct user_attribute {
  byte type;
  const byte *data;
  u32 len;
};


/* (See also keybox-search-desc.h) */
struct gpg_pkt_user_id_s
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
    unsigned int mdc:1;
    unsigned int ks_modify:1;
    unsigned int compacted:1;
  } flags;
  char name[1];
};
typedef struct gpg_pkt_user_id_s PKT_user_id;



struct revoke_info
{
  /* revoked at this date */
  u32 date;
  /* the keyid of the revoking key (selfsig or designated revoker) */
  u32 keyid[2];
  /* the algo of the revoking key */
  byte algo;
};


/* Information pertaining to secret keys. */
struct seckey_info
{
  int is_protected:1;	/* The secret info is protected and must */
			/* be decrypted before use, the protected */
			/* MPIs are simply (void*) pointers to memory */
			/* and should never be passed to a mpi_xxx() */
  int sha1chk:1;        /* SHA1 is used instead of a 16 bit checksum */
  u16 csum;		/* Checksum for old protection modes.  */
  byte algo;            /* Cipher used to protect the secret information. */
  STRING2KEY s2k;       /* S2K parameter.  */
  byte ivlen;           /* Used length of the IV.  */
  byte iv[16];          /* Initialization vector for CFB mode.  */
};


/****************
 * We assume that secret keys have the same number of parameters as
 * the public key and that the public parameters are the first items
 * in the PKEY array.  Thus NPKEY is always less than NSKEY and it is
 * possible to compare the secret and public keys by comparing the
 * first NPKEY elements of the PKEY array.  Note that since GnuPG 2.1
 * we don't use secret keys anymore directly because they are managed
 * by gpg-agent.  However for parsing OpenPGP key files we need a way
 * to temporary store those secret keys.  We do this by putting them
 * into the public key structure and extending the PKEY field to NSKEY
 * elements; the extra secret key information are stored in the
 * SECKEY_INFO field.
 */
typedef struct
{
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
  u32     has_expired;    /* set to the expiration date if expired */
  u32     main_keyid[2];  /* keyid of the primary key */
  u32     keyid[2];	    /* calculated by keyid_from_pk() */
  prefitem_t *prefs;      /* list of preferences (may be NULL) */
  struct
  {
    unsigned int mdc:1;           /* MDC feature set.  */
    unsigned int disabled_valid:1;/* The next flag is valid.  */
    unsigned int disabled:1;      /* The key has been disabled.  */
    unsigned int primary:1;       /* This is a primary key.  */
    unsigned int revoked:2;       /* Key has been revoked.
                                     1 = revoked by the owner
                                     2 = revoked by designated revoker.  */
    unsigned int maybe_revoked:1; /* A designated revocation is
                                     present, but without the key to
                                     check it.  */
    unsigned int valid:1;         /* Key (especially subkey) is valid.  */
    unsigned int dont_cache:1;    /* Do not cache this key.  */
    unsigned int backsig:2;       /* 0=none, 1=bad, 2=good.  */
    unsigned int serialno_valid:1;/* SERIALNO below is valid.  */
    unsigned int exact:1;         /* Found via exact (!) search.  */
  } flags;
  PKT_user_id *user_id;   /* If != NULL: found by that uid. */
  struct revocation_key *revkey;
  int     numrevkeys;
  u32     trust_timestamp;
  byte    trust_depth;
  byte    trust_value;
  const byte *trust_regexp;
  char    *serialno;      /* Malloced hex string or NULL if it is
                             likely not on a card.  See also
                             flags.serialno_valid.  */
  struct seckey_info *seckey_info;  /* If not NULL this malloced
                                       structure describes a secret
                                       key.  */
  gcry_mpi_t  pkey[PUBKEY_MAX_NSKEY]; /* Right, NSKEY elements.  */
} PKT_public_key;

/* Evaluates as true if the pk is disabled, and false if it isn't.  If
   there is no disable value cached, fill one in. */
#define pk_is_disabled(a)                                       \
  (((a)->flags.disabled_valid)?                                 \
   ((a)->flags.disabled):(cache_disabled_value((a))))


typedef struct {
    int  len;		  /* length of data */
    char data[1];
} PKT_comment;

typedef struct {
    u32  len;		  /* reserved */
    byte  new_ctb;
    byte  algorithm;
    iobuf_t buf;	  /* IOBUF reference */
} PKT_compressed;

typedef struct {
    u32  len;		  /* Remaining length of encrypted data. */
    int  extralen;        /* This is (blocksize+2).  Used by build_packet. */
    byte new_ctb;	  /* uses a new CTB */
    byte is_partial;      /* partial length encoded */
    byte mdc_method;	  /* > 0: integrity protected encrypted data packet */
    iobuf_t buf;	  /* IOBUF reference */
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
    iobuf_t buf;	  /* IOBUF reference */
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
	PKT_public_key	*public_key;	/* PKT_PUBLIC_[SUB]KEY */
	PKT_public_key	*secret_key;	/* PKT_SECRET_[SUB]KEY */
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
int proc_packets (ctrl_t ctrl, void *ctx, iobuf_t a );
int proc_signature_packets (ctrl_t ctrl, void *ctx, iobuf_t a,
			    strlist_t signedfiles, const char *sigfile );
int proc_signature_packets_by_fd (ctrl_t ctrl,
                                  void *anchor, IOBUF a, int signed_data_fd );
int proc_encryption_packets (ctrl_t ctrl, void *ctx, iobuf_t a);
int list_packets( iobuf_t a );

/*-- parse-packet.c --*/

/* Sets the packet list mode to MODE (i.e., whether we are dumping a
   packet or not).  Returns the current mode.  This allows for
   temporarily suspending dumping by doing the following:

     int saved_mode = set_packet_list_mode (0);
     ...
     set_packet_list_mode (saved_mode);
*/
int set_packet_list_mode( int mode );

#if DEBUG_PARSE_PACKET
/* There are debug functions and should not be used directly.  */
int dbg_search_packet( iobuf_t inp, PACKET *pkt, off_t *retpos, int with_uid,
                       const char* file, int lineno  );
int dbg_parse_packet( iobuf_t inp, PACKET *ret_pkt,
                      const char* file, int lineno );
int dbg_copy_all_packets( iobuf_t inp, iobuf_t out,
                          const char* file, int lineno  );
int dbg_copy_some_packets( iobuf_t inp, iobuf_t out, off_t stopoff,
                           const char* file, int lineno  );
int dbg_skip_some_packets( iobuf_t inp, unsigned n,
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
/* Return the next valid OpenPGP packet in *PKT.  (This function will
   skip any packets whose type is 0.)

   Returns 0 on success, -1 if EOF is reached, and an error code
   otherwise.  In the case of an error, the packet in *PKT may be
   partially constructed.  As such, even if there is an error, it is
   necessary to free *PKT to avoid a resource leak.  To detect what
   has been allocated, clear *PKT before calling this function.  */
int parse_packet( iobuf_t inp, PACKET *pkt);

/* Return the first OpenPGP packet in *PKT that contains a key (either
   a public subkey, a public key, a secret subkey or a secret key) or,
   if WITH_UID is set, a user id.

   Saves the position in the pipeline of the start of the returned
   packet (according to iobuf_tell) in RETPOS, if it is not NULL.

   The return semantics are the same as parse_packet.  */
int search_packet( iobuf_t inp, PACKET *pkt, off_t *retpos, int with_uid );

/* Copy all packets (except invalid packets, i.e., those with a type
   of 0) from INP to OUT until either an error occurs or EOF is
   reached.

   Returns -1 when end of file is reached or an error code, if an
   error occurred.  (Note: this function never returns 0, because it
   effectively keeps going until it gets an EOF.)  */
int copy_all_packets( iobuf_t inp, iobuf_t out );

/* Like copy_all_packets, but stops at the first packet that starts at
   or after STOPOFF (as indicated by iobuf_tell).

   Example: if STOPOFF is 100, the first packet in INP goes from 0 to
   110 and the next packet starts at offset 111, then the packet
   starting at offset 0 will be completely processed (even though it
   extends beyond STOPOFF) and the packet starting at offset 111 will
   not be processed at all.  */
int copy_some_packets( iobuf_t inp, iobuf_t out, off_t stopoff );

/* Skips the next N packets from INP.

   If parsing a packet returns an error code, then the function stops
   immediately and returns the error code.  Note: in the case of an
   error, this function does not indicate how many packets were
   successfully processed.  */
int skip_some_packets( iobuf_t inp, unsigned n );
#endif

/* Parse a signature packet and store it in *SIG.

   The signature packet is read from INP.  The OpenPGP header (the tag
   and the packet's length) have already been read; the next byte read
   from INP should be the first byte of the packet's contents.  The
   packet's type (as extract from the tag) must be passed as PKTTYPE
   and the packet's length must be passed as PKTLEN.  This is used as
   the upper bound on the amount of data read from INP.  If the packet
   is shorter than PKTLEN, the data at the end will be silently
   skipped.  If an error occurs, an error code will be returned.  -1
   means the EOF was encountered.  0 means parsing was successful.  */
int parse_signature( iobuf_t inp, int pkttype, unsigned long pktlen,
		     PKT_signature *sig );

/* Given a subpacket area (typically either PKT_signature.hashed or
   PKT_signature.unhashed), either:

     - test whether there are any subpackets with the critical bit set
       that we don't understand,

     - list the subpackets, or,

     - find a subpacket with a specific type.

   REQTYPE indicates the type of operation.

   If REQTYPE is SIGSUBPKT_TEST_CRITICAL, then this function checks
   whether there are any subpackets that have the critical bit and
   which GnuPG cannot handle.  If GnuPG understands all subpackets
   whose critical bit is set, then this function returns simply
   returns SUBPKTS.  If there is a subpacket whose critical bit is set
   and which GnuPG does not understand, then this function returns
   NULL and, if START is not NULL, sets *START to the 1-based index of
   the subpacket that violates the constraint.

   If REQTYPE is SIGSUBPKT_LIST_HASHED or SIGSUBPKT_LIST_UNHASHED, the
   packets are dumped.  Note: if REQTYPE is SIGSUBPKT_LIST_HASHED,
   this function does not check whether the hash is correct; this is
   merely an indication of the section that the subpackets came from.

   If REQTYPE is anything else, then this function interprets the
   values as a subpacket type and looks for the first subpacket with
   that type.  If such a packet is found, *CRITICAL (if not NULL) is
   set if the critical bit was set, *RET_N is set to the offset of the
   subpacket's content within the SUBPKTS buffer, *START is set to the
   1-based index of the subpacket within the buffer, and returns
   &SUBPKTS[*RET_N].

   *START is the number of initial subpackets to not consider.  Thus,
   if *START is 2, then the first 2 subpackets are ignored.  */
const byte *enum_sig_subpkt ( const subpktarea_t *subpkts,
                              sigsubpkttype_t reqtype,
                              size_t *ret_n, int *start, int *critical );

/* Shorthand for:

     enum_sig_subpkt (buffer, reqtype, ret_n, NULL, NULL); */
const byte *parse_sig_subpkt ( const subpktarea_t *buffer,
                               sigsubpkttype_t reqtype,
                               size_t *ret_n );

/* This calls parse_sig_subpkt first on the hashed signature area in
   SIG and then, if that returns NULL, calls parse_sig_subpkt on the
   unhashed subpacket area in SIG.  */
const byte *parse_sig_subpkt2 ( PKT_signature *sig,
                                sigsubpkttype_t reqtype);

/* Returns whether the N byte large buffer BUFFER is sufficient to
   hold a subpacket of type TYPE.  Note: the buffer refers to the
   contents of the subpacket (not the header) and it must already be
   initialized: for some subpackets, it checks some internal
   constraints.

   Returns 0 if the size is acceptable.  Returns -2 if the buffer is
   definitely too short.  To check for an error, check whether the
   return value is less than 0.  */
int parse_one_sig_subpkt( const byte *buffer, size_t n, int type );

/* Looks for revocation key subpackets (see RFC 4880 5.2.3.15) in the
   hashed area of the signature packet.  Any that are found are added
   to SIG->REVKEY and SIG->NUMREVKEYS is updated appropriately.  */
void parse_revkeys(PKT_signature *sig);

/* Extract the attributes from the buffer at UID->ATTRIB_DATA and
   update UID->ATTRIBS and UID->NUMATTRIBS accordingly.  */
int parse_attribute_subpkts(PKT_user_id *uid);

/* Set the UID->NAME field according to the attributes.  MAX_NAMELEN
   must be at least 71.  */
void make_attribute_uidname(PKT_user_id *uid, size_t max_namelen);

/* Allocate and initialize a new GPG control packet.  DATA is the data
   to save in the packet.  */
PACKET *create_gpg_control ( ctrlpkttype_t type,
                             const byte *data,
                             size_t datalen );

/*-- build-packet.c --*/
int build_packet( iobuf_t inp, PACKET *pkt );
gpg_error_t gpg_mpi_write (iobuf_t out, gcry_mpi_t a);
gpg_error_t gpg_mpi_write_nohdr (iobuf_t out, gcry_mpi_t a);
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
void release_public_key_parts( PKT_public_key *pk );
void free_public_key( PKT_public_key *key );
void free_attributes(PKT_user_id *uid);
void free_user_id( PKT_user_id *uid );
void free_comment( PKT_comment *rem );
void free_packet( PACKET *pkt );
prefitem_t *copy_prefs (const prefitem_t *prefs);
PKT_public_key *copy_public_key( PKT_public_key *d, PKT_public_key *s );
PKT_signature *copy_signature( PKT_signature *d, PKT_signature *s );
PKT_user_id *scopy_user_id (PKT_user_id *sd );
int cmp_public_keys( PKT_public_key *a, PKT_public_key *b );
int cmp_signatures( PKT_signature *a, PKT_signature *b );
int cmp_user_ids( PKT_user_id *a, PKT_user_id *b );


/*-- sig-check.c --*/
/* Check a signature.  This is shorthand for check_signature2 with
   the unnamed arguments passed as NULL.  */
int check_signature (PKT_signature *sig, gcry_md_hd_t digest);

/* Check a signature.  Looks up the public key from the key db.  (If
   RET_PK is not NULL, it is returned in *RET_PK.)  DIGEST contains a
   valid hash context that already includes the signed data.  This
   function adds the relevant meta-data to the hash before finalizing
   it and verifying the signature.  */
int check_signature2 (PKT_signature *sig, gcry_md_hd_t digest,
		      u32 *r_expiredate, int *r_expired, int *r_revoked,
		      PKT_public_key *ret_pk);


/*-- pubkey-enc.c --*/
gpg_error_t get_session_key (ctrl_t ctrl, PKT_pubkey_enc *k, DEK *dek);
gpg_error_t get_override_session_key (DEK *dek, const char *string);

/*-- compress.c --*/
int handle_compressed (ctrl_t ctrl, void *ctx, PKT_compressed *cd,
		       int (*callback)(iobuf_t, void *), void *passthru );

/*-- encr-data.c --*/
int decrypt_data (ctrl_t ctrl, void *ctx, PKT_encrypted *ed, DEK *dek );

/*-- plaintext.c --*/
gpg_error_t get_output_file (const byte *embedded_name, int embedded_namelen,
                             iobuf_t data, char **fnamep, estream_t *fpp);
int handle_plaintext( PKT_plaintext *pt, md_filter_context_t *mfx,
					int nooutput, int clearsig );
int ask_for_detached_datafile( gcry_md_hd_t md, gcry_md_hd_t md2,
			       const char *inname, int textmode );

/*-- sign.c --*/
int make_keysig_packet( PKT_signature **ret_sig, PKT_public_key *pk,
			PKT_user_id *uid, PKT_public_key *subpk,
			PKT_public_key *pksk, int sigclass, int digest_algo,
			u32 timestamp, u32 duration,
			int (*mksubpkt)(PKT_signature *, void *),
			void *opaque,
                        const char *cache_nonce);
gpg_error_t update_keysig_packet (PKT_signature **ret_sig,
                      PKT_signature *orig_sig,
                      PKT_public_key *pk,
                      PKT_user_id *uid,
                      PKT_public_key *subpk,
                      PKT_public_key *pksk,
                      int (*mksubpkt)(PKT_signature *, void *),
                      void *opaque   );

/*-- keygen.c --*/
PKT_user_id *generate_user_id (kbnode_t keyblock, const char *uidstr);

#endif /*G10_PACKET_H*/
