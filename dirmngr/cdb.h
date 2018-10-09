/* $Id: cdb.h 106 2003-12-12 17:36:49Z werner $
 * public cdb include file
 *
 * This file is a part of tinycdb package by Michael Tokarev, mjt@corpit.ru.
 * Public domain.
 *
 * Taken from tinycdb-0.73. By Werner Koch <wk@gnupg.org> 2003-12-12.
 */

#ifndef TINYCDB_VERSION
#define TINYCDB_VERSION 0.73

typedef unsigned int cdbi_t; /*XXX should be at least 32 bits long */

/* common routines */
cdbi_t cdb_hash(const void *buf, cdbi_t len);
cdbi_t cdb_unpack(const unsigned char buf[4]);
void cdb_pack(cdbi_t num, unsigned char buf[4]);

struct cdb {
  int cdb_fd;			/* file descriptor */
  /* private members */
#ifdef HAVE_W32_SYSTEM
  void *cdb_mapping;            /* Mapping handle.  */
#endif
  cdbi_t cdb_fsize;		/* datafile size */
  const unsigned char *cdb_mem; /* mmap'ed file memory */
  cdbi_t cdb_vpos, cdb_vlen;	/* found data */
  cdbi_t cdb_kpos, cdb_klen;    /* found key (only set if cdb_findinit
                                   was called with KEY set to NULL). */
};

#define cdb_datapos(c) ((c)->cdb_vpos)
#define cdb_datalen(c) ((c)->cdb_vlen)
#define cdb_keypos(c) ((c)->cdb_kpos)
#define cdb_keylen(c) ((c)->cdb_klen)
#define cdb_fileno(c) ((c)->cdb_fd)

int cdb_init(struct cdb *cdbp, int fd);
void cdb_free(struct cdb *cdbp);

int cdb_read(const struct cdb *cdbp,
	     void *buf, unsigned len, cdbi_t pos);
int cdb_find(struct cdb *cdbp, const void *key, unsigned klen);

struct cdb_find {
  struct cdb *cdb_cdbp;
  cdbi_t cdb_hval;
  const unsigned char *cdb_htp, *cdb_htab, *cdb_htend;
  cdbi_t cdb_httodo;
  const void *cdb_key;
  cdbi_t cdb_klen;
};

int cdb_findinit(struct cdb_find *cdbfp, struct cdb *cdbp,
		 const void *key, cdbi_t klen);
int cdb_findnext(struct cdb_find *cdbfp);

/* old simple interface */
/* open file using standard routine, then: */
int cdb_seek(int fd, const void *key, unsigned klen, cdbi_t *dlenp);
int cdb_bread(int fd, void *buf, int len);

/* cdb_make */

struct cdb_make {
  int cdb_fd;			/* file descriptor */
  /* private */
  cdbi_t cdb_dpos;		/* data position so far */
  cdbi_t cdb_rcnt;		/* record count so far */
  char cdb_buf[4096];		/* write buffer */
  char *cdb_bpos;		/* current buf position */
  struct cdb_rl *cdb_rec[256];	/* list of arrays of record infos */
};



int cdb_make_start(struct cdb_make *cdbmp, int fd);
int cdb_make_add(struct cdb_make *cdbmp,
		 const void *key, cdbi_t klen,
		 const void *val, cdbi_t vlen);
int cdb_make_exists(struct cdb_make *cdbmp,
		    const void *key, cdbi_t klen);
int cdb_make_put(struct cdb_make *cdbmp,
		 const void *key, cdbi_t klen,
		 const void *val, cdbi_t vlen,
		 int flag);
#define CDB_PUT_ADD	0	/* add unconditionally, like cdb_make_add() */
#define CDB_PUT_REPLACE	1	/* replace: do not place to index OLD record */
#define CDB_PUT_INSERT	2	/* add only if not already exists */
#define CDB_PUT_WARN	3	/* add unconditionally but ret. 1 if exists */
int cdb_make_finish(struct cdb_make *cdbmp);

#endif /* include guard */
