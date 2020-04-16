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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef G10_PACKET_H
#define G10_PACKET_H

#include "../common/types.h"
#include "../common/iobuf.h"
#include "../common/strlist.h"
#include "dek.h"
#include "filter.h"
#include "../common/openpgpdefs.h"
#include "../common/userids.h"
#include "../common/util.h"

#define DEBUG_PARSE_PACKET 1

/* Maximum length of packets to avoid excessive memory allocation.  */
#define MAX_KEY_PACKET_LENGTH     (256 * 1024)
#define MAX_UID_PACKET_LENGTH     (  2 * 1024)
#define MAX_COMMENT_PACKET_LENGTH ( 64 * 1024)
#define MAX_ATTR_PACKET_LENGTH    ( 16 * 1024*1024)

/* Constants to allocate static MPI arrays.  */
#define PUBKEY_MAX_NPKEY  OPENPGP_MAX_NPKEY
#define PUBKEY_MAX_NSKEY  OPENPGP_MAX_NSKEY
#define PUBKEY_MAX_NSIG   OPENPGP_MAX_NSIG
#define PUBKEY_MAX_NENC   OPENPGP_MAX_NENC

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
    PREFTYPE_ZIP = 3,
    PREFTYPE_AEAD = 4
} preftype_t;

typedef struct {
    byte type;
    byte value;
} prefitem_t;

/* A string-to-key specifier as defined in RFC 4880, Section 3.7.  */
typedef struct
{
  int  mode;      /* Must be an integer due to the GNU modes 1001 et al.  */
  byte hash_algo;
  byte salt[8];
  /* The *coded* (i.e., the serialized version) iteration count.  */
  u32  count;
} STRING2KEY;

/* A symmetric-key encrypted session key packet as defined in RFC
   4880, Section 5.3.  All fields are serialized.  */
typedef struct {
  /* RFC 4880: this must be 4.  */
  byte version;
  /* The cipher algorithm used to encrypt the session key.  (This may
     be different from the algorithm that is used to encrypt the SED
     packet.)  */
  byte cipher_algo;
  /* The AEAD algorithm or 0 for CFB encryption.  */
  byte aead_algo;
  /* The string-to-key specifier.  */
  STRING2KEY s2k;
  /* The length of SESKEY in bytes or 0 if this packet does not
     encrypt a session key.  (In the latter case, the results of the
     S2K function on the password is the session key. See RFC 4880,
     Section 5.3.)  */
  byte seskeylen;
  /* The session key as encrypted by the S2K specifier.  For AEAD this
   * includes the nonce and the authentication tag.  */
  byte seskey[1];
} PKT_symkey_enc;

/* A public-key encrypted session key packet as defined in RFC 4880,
   Section 5.1.  All fields are serialized.  */
typedef struct {
  /* The 64-bit keyid.  */
  u32     keyid[2];
  /* The packet's version.  Currently, only version 3 is defined.  */
  byte    version;
  /* The algorithm used for the public key encryption scheme.  */
  byte    pubkey_algo;
  /* Whether to hide the key id.  This value is not directly
     serialized.  */
  byte    throw_keyid;
  /* The session key.  */
  gcry_mpi_t     data[PUBKEY_MAX_NENC];
} PKT_pubkey_enc;


/* A one-pass signature packet as defined in RFC 4880, Section
   5.4.  All fields are serialized.  */
typedef struct {
    u32     keyid[2];	    /* The 64-bit keyid */
    /* The signature's classification (RFC 4880, Section 5.2.1).  */
    byte    sig_class;
    byte    digest_algo;    /* algorithm used for digest */
    byte    pubkey_algo;    /* algorithm used for public key scheme */
    /* A message can be signed by multiple keys.  In this case, there
       are n one-pass signature packets before the message to sign and
       n signatures packets after the message.  It is conceivable that
       someone wants to not only sign the message, but all of the
       signatures.  Now we need to distinguish between signing the
       message and signing the message plus the surrounding
       signatures.  This is the point of this flag.  If set, it means:
       I sign all of the data starting at the next packet.  */
    byte    last;
} PKT_onepass_sig;


/* A v4 OpenPGP signature has a hashed and unhashed area containing
   co-called signature subpackets (RFC 4880, Section 5.2.3).  These
   areas are described by this data structure.  Use enum_sig_subpkt to
   parse this area.  */
typedef struct {
    size_t size;  /* allocated */
    size_t len;   /* used (serialized) */
    byte data[1]; /* the serialized subpackes (serialized) */
} subpktarea_t;

/* The in-memory representation of a designated revoker signature
   subpacket (RFC 4880, Section 5.2.3.15).  */
struct revocation_key {
  /* A bit field.  0x80 must be set.  0x40 means this information is
     sensitive (and should not be uploaded to a keyserver by
     default).  */
  byte class;
  /* The public-key algorithm ID.  */
  byte algid;
  /* The fingerprint of the authorized key.  */
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


/* A signature packet (RFC 4880, Section 5.2).  Only a subset of these
   fields are directly serialized (these are marked as such); the rest
   are read from the subpackets, which are not synthesized when
   serializing this data structure (i.e., when using build_packet()).
   Instead, the subpackets must be created by hand.  */
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
    unsigned key_block:1;   /* A key block subpacket is present.  */
    unsigned expired:1;
    unsigned pka_tried:1;   /* Set if we tried to retrieve the PKA record. */
  } flags;
  /* The key that allegedly generated this signature.  (Directly
     serialized in v3 sigs; for v4 sigs, this must be explicitly added
     as an issuer subpacket (5.2.3.5.)  */
  u32     keyid[2];
  /* When the signature was made (seconds since the Epoch).  (Directly
     serialized in v3 sigs; for v4 sigs, this must be explicitly added
     as a signature creation time subpacket (5.2.3.4).)  */
  u32     timestamp;
  u32     expiredate;     /* Expires at this date or 0 if not at all. */
  /* The serialization format used / to use.  If 0, then defaults to
     version 3.  (Serialized.)  */
  byte    version;
  /* The signature type. (See RFC 4880, Section 5.2.1.)  */
  byte    sig_class;
  /* Algorithm used for public key scheme (e.g., PUBKEY_ALGO_RSA).
     (Serialized.)  */
  byte    pubkey_algo;
  /* Algorithm used for digest (e.g., DIGEST_ALGO_SHA1).
     (Serialized.)  */
  byte    digest_algo;
  byte    trust_depth;
  byte    trust_value;
  const byte *trust_regexp;
  struct revocation_key *revkey;
  int numrevkeys;
  int help_counter;          /* Used internally bu some fucntions.  */
  pka_info_t *pka_info;      /* Malloced PKA data or NULL if not
                                available.  See also flags.pka_tried. */
  char *signers_uid;         /* Malloced value of the SIGNERS_UID
                              * subpacket or NULL.  This string has
                              * already been sanitized.  */
  subpktarea_t *hashed;      /* All subpackets with hashed data (v4 only). */
  subpktarea_t *unhashed;    /* Ditto for unhashed data. */
  /* First 2 bytes of the digest.  (Serialized.  Note: this is not
     automatically filled in when serializing a signature!)  */
  byte digest_start[2];
  /* The signature.  (Serialized.)  */
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


/* A user id (RFC 4880, Section 5.11) or a user attribute packet (RFC
   4880, Section 5.12).  Only a subset of these fields are directly
   serialized (these are marked as such); the rest are read from the
   self-signatures in merge_keys_and_selfsig()).  */
typedef struct
{
  int ref;              /* reference counter */
  /* The length of NAME.  */
  int len;
  struct user_attribute *attribs;
  int numattribs;
  /* If this is not NULL, the packet is a user attribute rather than a
     user id (See RFC 4880 5.12).  (Serialized.)  */
  byte *attrib_data;
  /* The length of ATTRIB_DATA.  */
  unsigned long attrib_len;
  byte *namehash;
  int help_key_usage;
  u32 help_key_expire;
  int help_full_count;
  int help_marginal_count;
  u32 expiredate;       /* expires at this date or 0 if not at all */
  prefitem_t *prefs;    /* list of preferences (may be NULL)*/
  u32 created;          /* according to the self-signature */
  u32 keyupdate;        /* From the ring trust packet.  */
  char *updateurl;      /* NULL or the URL of the last update origin.  */
  byte keyorg;          /* From the ring trust packet.  */
  byte selfsigversion;
  struct
  {
    unsigned int mdc:1;
    unsigned int aead:1;
    unsigned int ks_modify:1;
    unsigned int compacted:1;
    unsigned int primary:2; /* 2 if set via the primary flag, 1 if calculated */
    unsigned int revoked:1;
    unsigned int expired:1;
  } flags;

  char *mbox;   /* NULL or the result of mailbox_from_userid.  */

  /* The text contained in the user id packet, which is normally the
   * name and email address of the key holder (See RFC 4880 5.11).
   * (Serialized.). For convenience an extra Nul is always appended.  */
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
 * The in-memory representation of a public key (RFC 4880, Section
 * 5.5).  Note: this structure contains significantly more information
 * than is contained in an OpenPGP public key packet.  This
 * information is derived from the self-signed signatures (by
 * merge_keys_and_selfsig()) and is ignored when serializing the
 * packet.  The fields that are actually written out when serializing
 * this packet are marked as accordingly.
 *
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
  /* When the key was created.  (Serialized.)  */
  u32     timestamp;
  u32     expiredate;     /* expires at this date or 0 if not at all */
  u32     max_expiredate; /* must not expire past this date */
  struct revoke_info revoked;
  /* An OpenPGP packet consists of a header and a body.  This is the
     size of the header.  If this is 0, an appropriate size is
     automatically chosen based on the size of the body.
     (Serialized.)  */
  byte    hdrbytes;
  /* The serialization format.  If 0, the default version (4) is used
     when serializing.  (Serialized.)  */
  byte    version;
  byte    selfsigversion; /* highest version of all of the self-sigs */
  /* The public key algorithm.  (Serialized.)  */
  byte    pubkey_algo;
  byte    pubkey_usage;   /* for now only used to pass it to getkey() */
  byte    req_usage;      /* hack to pass a request to getkey() */
  u32     has_expired;    /* set to the expiration date if expired */
  /* keyid of the primary key.  Never access this value directly.
     Instead, use pk_main_keyid().  */
  u32     main_keyid[2];
  /* keyid of this key.  Never access this value directly!  Instead,
     use pk_keyid().  */
  u32     keyid[2];
  prefitem_t *prefs;      /* list of preferences (may be NULL) */
  struct
  {
    unsigned int mdc:1;           /* MDC feature set.  */
    unsigned int aead:1;          /* AEAD feature set.  */
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
  byte    keyorg;         /* From the ring trust packet.  */
  u32     keyupdate;      /* From the ring trust packet.  */
  char    *updateurl;     /* NULL or the URL of the last update origin.  */
  const byte *trust_regexp;
  char    *serialno;      /* Malloced hex string or NULL if it is
                             likely not on a card.  See also
                             flags.serialno_valid.  */
  /* If not NULL this malloced structure describes a secret key.
     (Serialized.)  */
  struct seckey_info *seckey_info;
  /* The public key.  Contains pubkey_get_npkey (pubkey_algo) +
     pubkey_get_nskey (pubkey_algo) MPIs.  (If pubkey_get_npkey
     returns 0, then the algorithm is not understood and the PKEY
     contains a single opaque MPI.)  (Serialized.)  */
  gcry_mpi_t  pkey[PUBKEY_MAX_NSKEY]; /* Right, NSKEY elements.  */
} PKT_public_key;

/* Evaluates as true if the pk is disabled, and false if it isn't.  If
   there is no disable value cached, fill one in. */
#define pk_is_disabled(a)                                       \
  (((a)->flags.disabled_valid)?                                 \
   ((a)->flags.disabled):(cache_disabled_value(ctrl,(a))))


typedef struct {
    int  len;		  /* length of data */
    char data[1];
} PKT_comment;

/* A compression packet (RFC 4880, Section 5.6).  */
typedef struct {
  /* Not used.  */
  u32 len;
  /* Whether the serialized version of the packet used / should use
     the new format.  */
  byte  new_ctb;
  /* The compression algorithm.  */
  byte  algorithm;
  /* An iobuf holding the data to be decompressed.  (This is not used
     for compression!)  */
  iobuf_t buf;
} PKT_compressed;

/* A symmetrically encrypted data packet (RFC 4880, Section 5.7) or a
   symmetrically encrypted integrity protected data packet (Section
   5.13) */
typedef struct {
  /* Remaining length of encrypted data. */
  u32  len;
  /* When encrypting in CFB mode, the first block size bytes of data
   * are random data and the following 2 bytes are copies of the last
   * two bytes of the random data (RFC 4880, Section 5.7).  This
   * provides a simple check that the key is correct.  EXTRALEN is the
   * size of this extra data or, in AEAD mode, the length of the
   * headers and the tags.  This is used by build_packet when writing
   * out the packet's header. */
  int  extralen;
  /* Whether the serialized version of the packet used / should use
     the new format.  */
  byte new_ctb;
  /* Whether the packet has an indeterminate length (old format) or
     was encoded using partial body length headers (new format).
     Note: this is ignored when encrypting.  */
  byte is_partial;
  /* If 0, MDC is disabled.  Otherwise, the MDC method that was used
     (currently, only DIGEST_ALGO_SHA1 is supported).  */
  byte mdc_method;
  /* If 0, AEAD is not used.  Otherwise, the used AEAD algorithm.
   * MDC_METHOD (above) shall be zero if AEAD is used.  */
  byte aead_algo;
  /* The cipher algo for/from the AEAD packet.  0 for other encryption
   * packets. */
  byte cipher_algo;
  /* The chunk byte from the AEAD packet.  */
  byte chunkbyte;

  /* An iobuf holding the data to be decrypted.  (This is not used for
     encryption!)  */
  iobuf_t buf;
} PKT_encrypted;

typedef struct {
    byte hash[20];
} PKT_mdc;


/* Subtypes for the ring trust packet.  */
#define RING_TRUST_SIG 0  /* The classical signature cache.  */
#define RING_TRUST_KEY 1  /* A KEYORG on a primary key.      */
#define RING_TRUST_UID 2  /* A KEYORG on a user id.          */

/* The local only ring trust packet which OpenPGP declares as
 * implementation defined.  GnuPG uses this to cache signature
 * verification status and since 2.1.18 also to convey information
 * about the origin of a key.  Note that this packet is not part
 * struct packet_struct because we use it only local in the packet
 * parser and builder. */
typedef struct {
  unsigned int trustval;
  unsigned int sigcache;
  unsigned char subtype; /* The subtype of this ring trust packet.   */
  unsigned char keyorg;  /* The origin of the key (KEYORG_*).        */
  u32 keyupdate;         /* The wall time the key was last updated.  */
  char *url;             /* NULL or the URL of the source.           */
} PKT_ring_trust;


/* A plaintext packet (see RFC 4880, 5.9).  */
typedef struct {
  /* The length of data in BUF or 0 if unknown.  */
  u32  len;
  /* A buffer containing the data stored in the packet's body.  */
  iobuf_t buf;
  byte new_ctb;
  byte is_partial;      /* partial length encoded */
  /* The data's formatting.  This is either 'b', 't', 'u', 'l' or '1'
     (however, the last two are deprecated).  */
  int mode;
  u32 timestamp;
  /* The name of the file.  This can be at most 255 characters long,
     since namelen is just a byte in the serialized format.  */
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
	PKT_plaintext	*plaintext;	/* PKT_PLAINTEXT */
        PKT_gpg_control *gpg_control;   /* PKT_GPG_CONTROL */
    } pkt;
};

#define init_packet(a) do { (a)->pkttype = 0;		\
			    (a)->pkt.generic = NULL;	\
		       } while(0)


/* A notation.  See RFC 4880, Section 5.2.3.16.  */
struct notation
{
  /* The notation's name.  */
  char *name;
  /* If the notation is human readable, then the value is stored here
     as a NUL-terminated string.  If it is not human readable a human
     readable approximation of the binary value _may_ be stored
     here.  */
  char *value;
  /* Sometimes we want to %-expand the value.  In these cases, we save
     that transformed value here.  */
  char *altvalue;
  /* If the notation is not human readable, then the value is stored
     here.  */
  unsigned char *bdat;
  /* The amount of data stored in BDAT.

     Note: if this is 0 and BDAT is NULL, this does not necessarily
     mean that the value is human readable.  It could be that we have
     a 0-length value.  To determine whether the notation is human
     readable, always check if VALUE is not NULL.  This works, because
     if a human-readable value has a length of 0, we will still
     allocate space for the NUL byte.  */
  size_t blen;
  struct
  {
    /* The notation is critical.  */
    unsigned int critical:1;
    /* The notation is human readable.  */
    unsigned int human:1;
    /* The notation should be deleted.  */
    unsigned int ignore:1;
  } flags;

  /* A field to facilitate creating a list of notations.  */
  struct notation *next;
};
typedef struct notation *notation_t;

/*-- mainproc.c --*/
void reset_literals_seen(void);
int proc_packets (ctrl_t ctrl, void *ctx, iobuf_t a );
int proc_signature_packets (ctrl_t ctrl, void *ctx, iobuf_t a,
			    strlist_t signedfiles, const char *sigfile );
int proc_signature_packets_by_fd (ctrl_t ctrl,
                                  void *anchor, IOBUF a, int signed_data_fd );
int proc_encryption_packets (ctrl_t ctrl, void *ctx, iobuf_t a);
int list_packets( iobuf_t a );

const byte *issuer_fpr_raw (PKT_signature *sig, size_t *r_len);
char *issuer_fpr_string (PKT_signature *sig);

/*-- parse-packet.c --*/


void register_known_notation (const char *string);

/* Sets the packet list mode to MODE (i.e., whether we are dumping a
   packet or not).  Returns the current mode.  This allows for
   temporarily suspending dumping by doing the following:

     int saved_mode = set_packet_list_mode (0);
     ...
     set_packet_list_mode (saved_mode);
*/
int set_packet_list_mode( int mode );


/* A context used with parse_packet.  */
struct parse_packet_ctx_s
{
  iobuf_t inp;       /* The input stream with the packets.  */
  struct packet_struct last_pkt; /* The last parsed packet.  */
  int free_last_pkt; /* Indicates that LAST_PKT must be freed.  */
  int skip_meta;     /* Skip ring trust packets.  */
  unsigned int n_parsed_packets;	/* Number of parsed packets.  */
};
typedef struct parse_packet_ctx_s *parse_packet_ctx_t;

#define init_parse_packet(a,i) do { \
    (a)->inp = (i);                 \
    (a)->last_pkt.pkttype = 0;      \
    (a)->last_pkt.pkt.generic= NULL;\
    (a)->free_last_pkt = 0;         \
    (a)->skip_meta = 0;             \
    (a)->n_parsed_packets = 0;      \
  } while (0)

#define deinit_parse_packet(a) do { \
    if ((a)->free_last_pkt)         \
      free_packet (NULL, (a));      \
  } while (0)


#if DEBUG_PARSE_PACKET
/* There are debug functions and should not be used directly.  */
int dbg_search_packet (parse_packet_ctx_t ctx, PACKET *pkt,
                       off_t *retpos, int with_uid,
                       const char* file, int lineno  );
int dbg_parse_packet (parse_packet_ctx_t ctx, PACKET *ret_pkt,
                      const char *file, int lineno);
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
 * skip any packets whose type is 0.)  CTX must have been setup prior to
 * calling this function.
 *
 * Returns 0 on success, -1 if EOF is reached, and an error code
 * otherwise.  In the case of an error, the packet in *PKT may be
 * partially constructed.  As such, even if there is an error, it is
 * necessary to free *PKT to avoid a resource leak.  To detect what
 * has been allocated, clear *PKT before calling this function.  */
int parse_packet (parse_packet_ctx_t ctx, PACKET *pkt);

/* Return the first OpenPGP packet in *PKT that contains a key (either
 * a public subkey, a public key, a secret subkey or a secret key) or,
 * if WITH_UID is set, a user id.
 *
 * Saves the position in the pipeline of the start of the returned
 * packet (according to iobuf_tell) in RETPOS, if it is not NULL.
 *
 * The return semantics are the same as parse_packet.  */
int search_packet (parse_packet_ctx_t ctx, PACKET *pkt,
                   off_t *retpos, int with_uid);

/* Copy all packets (except invalid packets, i.e., those with a type
 * of 0) from INP to OUT until either an error occurs or EOF is
 * reached.
 *
 * Returns -1 when end of file is reached or an error code, if an
 * error occurred.  (Note: this function never returns 0, because it
 * effectively keeps going until it gets an EOF.)  */
int copy_all_packets (iobuf_t inp, iobuf_t out );

/* Like copy_all_packets, but stops at the first packet that starts at
 * or after STOPOFF (as indicated by iobuf_tell).
 *
 * Example: if STOPOFF is 100, the first packet in INP goes from
 * 0 to 110 and the next packet starts at offset 111, then the packet
 * starting at offset 0 will be completely processed (even though it
 * extends beyond STOPOFF) and the packet starting at offset 111 will
 * not be processed at all.  */
int copy_some_packets (iobuf_t inp, iobuf_t out, off_t stopoff);

/* Skips the next N packets from INP.
 *
 * If parsing a packet returns an error code, then the function stops
 * immediately and returns the error code.  Note: in the case of an
 * error, this function does not indicate how many packets were
 * successfully processed.  */
int skip_some_packets (iobuf_t inp, unsigned int n);
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
int build_packet (iobuf_t out, PACKET *pkt);
gpg_error_t build_packet_and_meta (iobuf_t out, PACKET *pkt);
gpg_error_t gpg_mpi_write (iobuf_t out, gcry_mpi_t a);
gpg_error_t gpg_mpi_write_nohdr (iobuf_t out, gcry_mpi_t a);
u32 calc_packet_length( PACKET *pkt );
void build_sig_subpkt( PKT_signature *sig, sigsubpkttype_t type,
			const byte *buffer, size_t buflen );
void build_sig_subpkt_from_sig (PKT_signature *sig, PKT_public_key *pksk);
int  delete_sig_subpkt(subpktarea_t *buffer, sigsubpkttype_t type );
void build_attribute_subpkt(PKT_user_id *uid,byte type,
			    const void *buf,u32 buflen,
			    const void *header,u32 headerlen);
struct notation *string_to_notation(const char *string,int is_utf8);
struct notation *blob_to_notation(const char *name,
                                  const char *data, size_t len);
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
void free_packet (PACKET *pkt, parse_packet_ctx_t parsectx);
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
int check_signature (ctrl_t ctrl, PKT_signature *sig, gcry_md_hd_t digest);

/* Check a signature.  Looks up the public key from the key db.  (If
 * R_PK is not NULL, it is stored at RET_PK.)  DIGEST contains a
 * valid hash context that already includes the signed data.  This
 * function adds the relevant meta-data to the hash before finalizing
 * it and verifying the signature.  FOCRED_PK is usually NULL. */
gpg_error_t check_signature2 (ctrl_t ctrl,
                              PKT_signature *sig, gcry_md_hd_t digest,
                              PKT_public_key *forced_pk,
                              u32 *r_expiredate, int *r_expired, int *r_revoked,
                              PKT_public_key **r_pk);


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
int make_keysig_packet (ctrl_t ctrl,
                        PKT_signature **ret_sig, PKT_public_key *pk,
			PKT_user_id *uid, PKT_public_key *subpk,
			PKT_public_key *pksk, int sigclass, int digest_algo,
			u32 timestamp, u32 duration,
			int (*mksubpkt)(PKT_signature *, void *),
			void *opaque,
                        const char *cache_nonce);
gpg_error_t update_keysig_packet (ctrl_t ctrl,
                      PKT_signature **ret_sig,
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
