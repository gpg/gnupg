/* cdblib.c - all CDB library functions.
 *
 * This file is a part of tinycdb package by Michael Tokarev, mjt@corpit.ru.
 * Public domain.
 *
 * Taken from tinycdb-0.73 and merged into one file for easier
 * inclusion into Dirmngr.  By Werner Koch <wk@gnupg.org> 2003-12-12.
 */

/* A cdb database is a single file used to map 'keys' to 'values',
   having records of (key,value) pairs.  File consists of 3 parts: toc
   (table of contents), data and index (hash tables).

   Toc has fixed length of 2048 bytes, containing 256 pointers to hash
   tables inside index sections.  Every pointer consists of position
   of a hash table in bytes from the beginning of a file, and a size
   of a hash table in entries, both are 4-bytes (32 bits) unsigned
   integers in little-endian form.  Hash table length may have zero
   length, meaning that corresponding hash table is empty.

   Right after toc section, data section follows without any
   alignment.  It consists of series of records, each is a key length,
   value (data) length, key and value.  Again, key and value length
   are 4-byte unsigned integers.  Each next record follows previous
   without any special alignment.

   After data section, index (hash tables) section follows.  It should
   be looked to in conjunction with toc section, where each of max 256
   hash tables are defined.  Index section consists of series of hash
   tables, with starting position and length defined in toc section.
   Every hash table is a sequence of records each holds two numbers:
   key's hash value and record position inside data section (bytes
   from the beginning of a file to first byte of key length starting
   data record).  If record position is zero, then this is an empty
   hash table slot, pointed to nowhere.

   CDB hash function is
     hv = ((hv << 5) + hv) ^ c
   for every single c byte of a key, starting with hv = 5381.

   Toc section indexed by (hv % 256), i.e. hash value modulo 256
   (number of entries in toc section).

   In order to find a record, one should: first, compute the hash
   value (hv) of a key.  Second, look to hash table number hv modulo
   256.  If it is empty, then there is no such key exists.  If it is
   not empty, then third, loop by slots inside that hash table,
   starting from slot with number hv divided by 256 modulo length of
   that table, or ((hv / 256) % htlen), searching for this hv in hash
   table.  Stop search on empty slot (if record position is zero) or
   when all slots was probed (note cyclic search, jumping from end to
   beginning of a table).  When hash value in question is found in
   hash table, look to key of corresponding record, comparing it with
   key in question.  If them of the same length and equals to each
   other, then record is found, otherwise, repeat with next hash table
   slot.  Note that there may be several records with the same key.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef _WIN32
# include <windows.h>
#else
# include <sys/mman.h>
# ifndef MAP_FAILED
#  define MAP_FAILED ((void*)-1)
# endif
#endif
#include <sys/stat.h>

#include "dirmngr-err.h"
#include "cdb.h"

#ifndef EPROTO
# define EPROTO EINVAL
#endif
#ifndef SEEK_SET
# define SEEK_SET 0
#endif


struct cdb_rec {
  cdbi_t hval;
  cdbi_t rpos;
};

struct cdb_rl {
  struct cdb_rl *next;
  cdbi_t cnt;
  struct cdb_rec rec[254];
};

static int make_find(struct cdb_make *cdbmp,
		   const void *key, cdbi_t klen, cdbi_t hval,
		   struct cdb_rl **rlp);
static int make_write(struct cdb_make *cdbmp,
		    const char *ptr, cdbi_t len);



/* Initializes structure given by CDBP pointer and associates it with
   the open file descriptor FD.  Allocate memory for the structure
   itself if needed and file open operation should be done by
   application.  File FD should be opened at least read-only, and
   should be seekable.  Routine returns 0 on success or negative value
   on error. */
int
cdb_init(struct cdb *cdbp, int fd)
{
  struct stat st;
  unsigned char *mem;
#ifdef _WIN32
  HANDLE hFile, hMapping;
#else
  unsigned int fsize;
#endif

  /* get file size */
  if (fstat(fd, &st) < 0)
    return -1;
  /* trivial sanity check: at least toc should be here */
  if (st.st_size < 2048) {
    gpg_err_set_errno (EPROTO);
    return -1;
  }
  /* memory-map file */
#ifdef _WIN32
  hFile = (HANDLE) _get_osfhandle(fd);
  if (hFile == (HANDLE) -1)
    return -1;
  hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (!hMapping)
    return -1;
  mem = (unsigned char *)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
  if (!mem)
    return -1;
  cdbp->cdb_mapping = hMapping;
#else /*!_WIN32*/
  fsize = (unsigned int)(st.st_size & 0xffffffffu);
  mem = (unsigned char*)mmap(NULL, fsize, PROT_READ, MAP_SHARED, fd, 0);
  if (mem == MAP_FAILED)
    return -1;
#endif /*!_WIN32*/

  cdbp->cdb_fd = fd;
  cdbp->cdb_fsize = st.st_size;
  cdbp->cdb_mem = mem;

#if 0
  /* XXX don't know well about madvise syscall -- is it legal
     to set different options for parts of one mmap() region?
     There is also posix_madvise() exist, with POSIX_MADV_RANDOM etc...
  */
#ifdef MADV_RANDOM
  /* set madvise() parameters. Ignore errors for now if system
     doesn't support it */
  madvise(mem, 2048, MADV_WILLNEED);
  madvise(mem + 2048, cdbp->cdb_fsize - 2048, MADV_RANDOM);
#endif
#endif

  cdbp->cdb_vpos = cdbp->cdb_vlen = 0;

  return 0;
}


/* Frees the internal resources held by structure.  Note that this
   routine does not close the file. */
void
cdb_free(struct cdb *cdbp)
{
  if (cdbp->cdb_mem) {
#ifdef _WIN32
    UnmapViewOfFile ((void*) cdbp->cdb_mem);
    CloseHandle (cdbp->cdb_mapping);
    cdbp->cdb_mapping = NULL;
#else
    munmap((void*)cdbp->cdb_mem, cdbp->cdb_fsize);
#endif /* _WIN32 */
    cdbp->cdb_mem = NULL;
  }
  cdbp->cdb_fsize = 0;
}


/* Read data from cdb file, starting at position pos of length len,
   placing result to buf.  This routine may be used to get actual
   value found by cdb_find() or other routines that returns position
   and length of a data.  Returns 0 on success or negative value on
   error. */
int
cdb_read(const struct cdb *cdbp, void *buf, unsigned len, cdbi_t pos)
{
  if (pos > cdbp->cdb_fsize || cdbp->cdb_fsize - pos < len) {
    gpg_err_set_errno (EPROTO);
    return -1;
  }
  memcpy(buf, cdbp->cdb_mem + pos, len);
  return 0;
}


/* Attempts to find a key given by (key,klen) parameters.  If key
   exists in database, routine returns 1 and places position and
   length of value associated with this key to internal fields inside
   cdbp structure, to be accessible by cdb_datapos() and
   cdb_datalen().  If key is not in database, routines returns 0.  On
   error, negative value is returned.  Note that using cdb_find() it
   is possible to lookup only first record with a given key. */
int
cdb_find(struct cdb *cdbp, const void *key, cdbi_t klen)
{
  const unsigned char *htp;	/* hash table pointer */
  const unsigned char *htab;	/* hash table */
  const unsigned char *htend;	/* end of hash table */
  cdbi_t httodo;		/* ht bytes left to look */
  cdbi_t pos, n;

  cdbi_t hval;

  if (klen > cdbp->cdb_fsize)	/* if key size is larger than file */
    return 0;

  hval = cdb_hash(key, klen);

  /* find (pos,n) hash table to use */
  /* first 2048 bytes (toc) are always available */
  /* (hval % 256) * 8 */
  htp = cdbp->cdb_mem + ((hval << 3) & 2047); /* index in toc (256x8) */
  n = cdb_unpack(htp + 4);	/* table size */
  if (!n)			/* empty table */
    return 0;			/* not found */
  httodo = n << 3;		/* bytes of htab to lookup */
  pos = cdb_unpack(htp);	/* htab position */
  if (n > (cdbp->cdb_fsize >> 3) /* overflow of httodo ? */
      || pos > cdbp->cdb_fsize /* htab start within file ? */
      || httodo > cdbp->cdb_fsize - pos) /* htab entry within file ? */
  {
    gpg_err_set_errno (EPROTO);
    return -1;
  }

  htab = cdbp->cdb_mem + pos;	/* htab pointer */
  htend = htab + httodo;	/* after end of htab */
  /* htab starting position: rest of hval modulo htsize, 8bytes per elt */
  htp = htab + (((hval >> 8) % n) << 3);

  for(;;) {
    pos = cdb_unpack(htp + 4);	/* record position */
    if (!pos)
      return 0;
    if (cdb_unpack(htp) == hval) {
      if (pos > cdbp->cdb_fsize - 8) { /* key+val lengths */
	gpg_err_set_errno (EPROTO);
	return -1;
      }
      if (cdb_unpack(cdbp->cdb_mem + pos) == klen) {
	if (cdbp->cdb_fsize - klen < pos + 8) {
	  gpg_err_set_errno (EPROTO);
	  return -1;
	}
	if (memcmp(key, cdbp->cdb_mem + pos + 8, klen) == 0) {
	  n = cdb_unpack(cdbp->cdb_mem + pos + 4);
	  pos += 8 + klen;
	  if (cdbp->cdb_fsize < n || cdbp->cdb_fsize - n < pos) {
	    gpg_err_set_errno (EPROTO);
	    return -1;
	  }
	  cdbp->cdb_vpos = pos;
	  cdbp->cdb_vlen = n;
	  return 1;
	}
      }
    }
    httodo -= 8;
    if (!httodo)
      return 0;
    if ((htp += 8) >= htend)
      htp = htab;
  }

}



/* Sequential-find routines that used separate structure.  It is
   possible to have many than one record with the same key in a
   database, and these routines allow enumeration of all of them.
   cdb_findinit() initializes search structure pointed to by cdbfp.
   It will return negative value on error or 0 on success.
   cdb_findnext() attempts to find next matching key, setting value
   position and length in cdbfp structure.  It will return positive
   value if given key was found, 0 if there is no more such key(s), or
   negative value on error.  To access value position and length after
   successeful call to cdb_findnext() (when it returned positive
   result), use cdb_datapos() and cdb_datalen() macros with cdbp
   pointer.  It is error to use cdb_findnext() after it returned 0 or
   error condition.  These routines is a bit slower than cdb_find().

   Setting KEY to NULL will start a sequential search through the
   entire DB.
*/
int
cdb_findinit(struct cdb_find *cdbfp, struct cdb *cdbp,
             const void *key, cdbi_t klen)
{
  cdbi_t n, pos;

  cdbfp->cdb_cdbp = cdbp;
  cdbfp->cdb_key  = key;
  cdbfp->cdb_klen = klen;
  cdbfp->cdb_hval = key? cdb_hash(key, klen) : 0;

  if (key)
    {
      cdbfp->cdb_htp = cdbp->cdb_mem + ((cdbfp->cdb_hval << 3) & 2047);
      n = cdb_unpack(cdbfp->cdb_htp + 4);
      cdbfp->cdb_httodo = n << 3; /* Set to size of hash table. */
      if (!n)
        return 0; /* The hash table is empry. */
      pos = cdb_unpack(cdbfp->cdb_htp);
      if (n > (cdbp->cdb_fsize >> 3)
          || pos > cdbp->cdb_fsize
          || cdbfp->cdb_httodo > cdbp->cdb_fsize - pos)
        {
          gpg_err_set_errno (EPROTO);
          return -1;
        }

      cdbfp->cdb_htab = cdbp->cdb_mem + pos;
      cdbfp->cdb_htend = cdbfp->cdb_htab + cdbfp->cdb_httodo;
      cdbfp->cdb_htp = cdbfp->cdb_htab + (((cdbfp->cdb_hval >> 8) % n) << 3);
    }
  else /* Walk over all entries. */
    {
      cdbfp->cdb_hval = 0;
      /* Force stepping in findnext. */
      cdbfp->cdb_htp = cdbfp->cdb_htend = cdbp->cdb_mem;
    }
  return 0;
}


/* See cdb_findinit. */
int
cdb_findnext(struct cdb_find *cdbfp)
{
  cdbi_t pos, n;
  struct cdb *cdbp = cdbfp->cdb_cdbp;

  if (cdbfp->cdb_key)
    {
      while(cdbfp->cdb_httodo) {
        pos = cdb_unpack(cdbfp->cdb_htp + 4);
        if (!pos)
          return 0;
        n = cdb_unpack(cdbfp->cdb_htp) == cdbfp->cdb_hval;
        if ((cdbfp->cdb_htp += 8) >= cdbfp->cdb_htend)
          cdbfp->cdb_htp = cdbfp->cdb_htab;
        cdbfp->cdb_httodo -= 8;
        if (n) {
          if (pos > cdbp->cdb_fsize - 8) {
            gpg_err_set_errno (EPROTO);
            return -1;
          }
          if (cdb_unpack(cdbp->cdb_mem + pos) == cdbfp->cdb_klen) {
            if (cdbp->cdb_fsize - cdbfp->cdb_klen < pos + 8) {
              gpg_err_set_errno (EPROTO);
              return -1;
            }
            if (memcmp(cdbfp->cdb_key,
                       cdbp->cdb_mem + pos + 8, cdbfp->cdb_klen) == 0) {
              n = cdb_unpack(cdbp->cdb_mem + pos + 4);
              pos += 8 + cdbfp->cdb_klen;
              if (cdbp->cdb_fsize < n || cdbp->cdb_fsize - n < pos) {
                gpg_err_set_errno (EPROTO);
                return -1;
              }
              cdbp->cdb_vpos = pos;
              cdbp->cdb_vlen = n;
              return 1;
            }
          }
        }
      }
    }
  else /* Walk over all entries. */
    {
      do
        {
          while (cdbfp->cdb_htp >= cdbfp->cdb_htend)
            {
              if (cdbfp->cdb_hval > 255)
                return 0; /* No more items. */

              cdbfp->cdb_htp = cdbp->cdb_mem + cdbfp->cdb_hval * 8;
              cdbfp->cdb_hval++; /* Advance for next round. */
              pos = cdb_unpack (cdbfp->cdb_htp);     /* Offset of table. */
              n   = cdb_unpack (cdbfp->cdb_htp + 4); /* Number of entries. */
              cdbfp->cdb_httodo = n * 8;             /* Size of table. */
              if (n > (cdbp->cdb_fsize / 8)
                  || pos > cdbp->cdb_fsize
                  || cdbfp->cdb_httodo > cdbp->cdb_fsize - pos)
                {
                  gpg_err_set_errno (EPROTO);
                  return -1;
                }

              cdbfp->cdb_htab  = cdbp->cdb_mem + pos;
              cdbfp->cdb_htend = cdbfp->cdb_htab + cdbfp->cdb_httodo;
              cdbfp->cdb_htp   = cdbfp->cdb_htab;
            }

          pos = cdb_unpack (cdbfp->cdb_htp + 4); /* Offset of record. */
          cdbfp->cdb_htp += 8;
        }
      while (!pos);
      if (pos > cdbp->cdb_fsize - 8)
        {
          gpg_err_set_errno (EPROTO);
          return -1;
        }

      cdbp->cdb_kpos = pos + 8;
      cdbp->cdb_klen = cdb_unpack(cdbp->cdb_mem + pos);
      cdbp->cdb_vpos = pos + 8 + cdbp->cdb_klen;
      cdbp->cdb_vlen = cdb_unpack(cdbp->cdb_mem + pos + 4);
      n = 8 + cdbp->cdb_klen + cdbp->cdb_vlen;
      if ( pos > cdbp->cdb_fsize || pos > cdbp->cdb_fsize - n)
        {
          gpg_err_set_errno (EPROTO);
          return -1;
        }
      return 1; /* Found. */
    }
  return 0;
}

/* Read a chunk from file, ignoring interrupts (EINTR) */
int
cdb_bread(int fd, void *buf, int len)
{
  int l;
  while(len > 0) {
    do l = read(fd, buf, len);
    while(l < 0 && errno == EINTR);
    if (l <= 0) {
      if (!l)
        gpg_err_set_errno (EIO);
      return -1;
    }
    buf = (char*)buf + l;
    len -= l;
  }
  return 0;
}

/* Find a given key in cdb file, seek a file pointer to it's value and
   place data length to *dlenp. */
int
cdb_seek(int fd, const void *key, unsigned klen, cdbi_t *dlenp)
{
  cdbi_t htstart;		/* hash table start position */
  cdbi_t htsize;		/* number of elements in a hash table */
  cdbi_t httodo;		/* hash table elements left to look */
  cdbi_t hti;			/* hash table index */
  cdbi_t pos;			/* position in a file */
  cdbi_t hval;			/* key's hash value */
  unsigned char rbuf[64];	/* read buffer */
  int needseek = 1;		/* if we should seek to a hash slot */

  hval = cdb_hash(key, klen);
  pos = (hval & 0xff) << 3; /* position in TOC */
  /* read the hash table parameters */
  if (lseek(fd, pos, SEEK_SET) < 0 || cdb_bread(fd, rbuf, 8) < 0)
    return -1;
  if ((htsize = cdb_unpack(rbuf + 4)) == 0)
    return 0;
  hti = (hval >> 8) % htsize;	/* start position in hash table */
  httodo = htsize;
  htstart = cdb_unpack(rbuf);

  for(;;) {
    if (needseek && lseek(fd, htstart + (hti << 3), SEEK_SET) < 0)
      return -1;
    if (cdb_bread(fd, rbuf, 8) < 0)
      return -1;
    if ((pos = cdb_unpack(rbuf + 4)) == 0) /* not found */
      return 0;

    if (cdb_unpack(rbuf) != hval) /* hash value not matched */
      needseek = 0;
    else { /* hash value matched */
      if (lseek(fd, pos, SEEK_SET) < 0 || cdb_bread(fd, rbuf, 8) < 0)
	return -1;
      if (cdb_unpack(rbuf) == klen) { /* key length matches */
	/* read the key from file and compare with wanted */
	cdbi_t l = klen, c;
	const char *k = (const char*)key;
	if (*dlenp)
	  *dlenp = cdb_unpack(rbuf + 4); /* save value length */
	for(;;) {
	  if (!l) /* the whole key read and matches, return */
	    return 1;
	  c = l > sizeof(rbuf) ? sizeof(rbuf) : l;
	  if (cdb_bread(fd, rbuf, c) < 0)
	    return -1;
	  if (memcmp(rbuf, k, c) != 0) /* no, it differs, stop here */
	    break;
	  k += c; l -= c;
	}
      }
      needseek = 1; /* we're looked to other place, should seek back */
    }
    if (!--httodo)
      return 0;
    if (++hti == htsize) {
      hti = htstart;
      needseek = 1;
    }
  }
}

cdbi_t
cdb_unpack(const unsigned char buf[4])
{
  cdbi_t n = buf[3];
  n <<= 8; n |= buf[2];
  n <<= 8; n |= buf[1];
  n <<= 8; n |= buf[0];
  return n;
}

/* Add record with key (KEY,KLEN) and value (VAL,VLEN) to a database.
   Returns 0 on success or negative value on error.  Note that this
   routine does not checks if given key already exists, but cdb_find()
   will not see second record with the same key.  It is not possible
   to continue building a database if cdb_make_add() returned an error
   indicator. */
int
cdb_make_add(struct cdb_make *cdbmp,
	     const void *key, cdbi_t klen,
	     const void *val, cdbi_t vlen)
{
  unsigned char rlen[8];
  cdbi_t hval;
  struct cdb_rl *rl;
  if (klen > 0xffffffff - (cdbmp->cdb_dpos + 8) ||
      vlen > 0xffffffff - (cdbmp->cdb_dpos + klen + 8)) {
    gpg_err_set_errno (ENOMEM);
    return -1;
  }
  hval = cdb_hash(key, klen);
  rl = cdbmp->cdb_rec[hval&255];
  if (!rl || rl->cnt >= sizeof(rl->rec)/sizeof(rl->rec[0])) {
    rl = (struct cdb_rl*)malloc(sizeof(struct cdb_rl));
    if (!rl) {
      gpg_err_set_errno (ENOMEM);
      return -1;
    }
    rl->cnt = 0;
    rl->next = cdbmp->cdb_rec[hval&255];
    cdbmp->cdb_rec[hval&255] = rl;
  }
  rl->rec[rl->cnt].hval = hval;
  rl->rec[rl->cnt].rpos = cdbmp->cdb_dpos;
  ++rl->cnt;
  ++cdbmp->cdb_rcnt;
  cdb_pack(klen, rlen);
  cdb_pack(vlen, rlen + 4);
  if (make_write(cdbmp, rlen, 8) < 0 ||
      make_write(cdbmp, key, klen) < 0 ||
      make_write(cdbmp, val, vlen) < 0)
    return -1;
  return 0;
}

int
cdb_make_put(struct cdb_make *cdbmp,
	     const void *key, cdbi_t klen,
	     const void *val, cdbi_t vlen,
	     int flags)
{
  unsigned char rlen[8];
  cdbi_t hval = cdb_hash(key, klen);
  struct cdb_rl *rl;
  int c, r;

  switch(flags) {
    case CDB_PUT_REPLACE:
    case CDB_PUT_INSERT:
    case CDB_PUT_WARN:
      c = make_find(cdbmp, key, klen, hval, &rl);
      if (c < 0)
	return -1;
      if (c) {
	if (flags == CDB_PUT_INSERT) {
	  gpg_err_set_errno (EEXIST);
	  return 1;
	}
	else if (flags == CDB_PUT_REPLACE) {
	  --c;
	  r = 1;
	  break;
	}
	else
	  r = 1;
      }
      /* fall through */

    case CDB_PUT_ADD:
      rl = cdbmp->cdb_rec[hval&255];
      if (!rl || rl->cnt >= sizeof(rl->rec)/sizeof(rl->rec[0])) {
 	rl = (struct cdb_rl*)malloc(sizeof(struct cdb_rl));
	if (!rl) {
	  gpg_err_set_errno (ENOMEM);
	  return -1;
	}
	rl->cnt = 0;
	rl->next = cdbmp->cdb_rec[hval&255];
	cdbmp->cdb_rec[hval&255] = rl;
      }
      c = rl->cnt;
      r = 0;
      break;

    default:
      gpg_err_set_errno (EINVAL);
      return -1;
  }

  if (klen > 0xffffffff - (cdbmp->cdb_dpos + 8) ||
      vlen > 0xffffffff - (cdbmp->cdb_dpos + klen + 8)) {
    gpg_err_set_errno (ENOMEM);
    return -1;
  }
  rl->rec[c].hval = hval;
  rl->rec[c].rpos = cdbmp->cdb_dpos;
  if (c == rl->cnt) {
    ++rl->cnt;
    ++cdbmp->cdb_rcnt;
  }
  cdb_pack(klen, rlen);
  cdb_pack(vlen, rlen + 4);
  if (make_write(cdbmp, rlen, 8) < 0 ||
      make_write(cdbmp, key, klen) < 0 ||
      make_write(cdbmp, val, vlen) < 0)
    return -1;
  return r;
}


static int
match(int fd, cdbi_t pos, const char *key, cdbi_t klen)
{
  unsigned char buf[64]; /*XXX cdb_buf may be used here instead */
  if (lseek(fd, pos, SEEK_SET) < 0 || read(fd, buf, 8) != 8)
    return -1;
  if (cdb_unpack(buf) != klen)
    return 0;

  while(klen > sizeof(buf)) {
    if (read(fd, buf, sizeof(buf)) != sizeof(buf))
      return -1;
    if (memcmp(buf, key, sizeof(buf)) != 0)
      return 0;
    key += sizeof(buf);
    klen -= sizeof(buf);
  }
  if (klen) {
    if (read(fd, buf, klen) != klen)
      return -1;
    if (memcmp(buf, key, klen) != 0)
      return 0;
  }
  return 1;
}


static int
make_find (struct cdb_make *cdbmp,
           const void *key, cdbi_t klen, cdbi_t hval,
           struct cdb_rl **rlp)
{
  struct cdb_rl *rl = cdbmp->cdb_rec[hval&255];
  int r, i;
  int sought = 0;
  while(rl) {
    for(i = rl->cnt - 1; i >= 0; --i) { /* search backward */
      if (rl->rec[i].hval != hval)
	continue;
      /*XXX this explicit flush may be unnecessary having
       * smarter match() that looks to cdb_buf too, but
       * most of a time here spent in finding hash values
       * (above), not keys */
      if (cdbmp->cdb_bpos != cdbmp->cdb_buf) {
        if (write(cdbmp->cdb_fd, cdbmp->cdb_buf,
	          cdbmp->cdb_bpos - cdbmp->cdb_buf) < 0)
          return -1;
        cdbmp->cdb_bpos = cdbmp->cdb_buf;
      }
      sought = 1;
      r = match(cdbmp->cdb_fd, rl->rec[i].rpos, key, klen);
      if (!r)
	continue;
      if (r < 0)
	return -1;
      if (lseek(cdbmp->cdb_fd, cdbmp->cdb_dpos, SEEK_SET) < 0)
        return -1;
      if (rlp)
	*rlp = rl;
      return i + 1;
    }
    rl = rl->next;
  }
  if (sought && lseek(cdbmp->cdb_fd, cdbmp->cdb_dpos, SEEK_SET) < 0)
    return -1;
  return 0;
}

int
cdb_make_exists(struct cdb_make *cdbmp,
                const void *key, cdbi_t klen)
{
  return make_find(cdbmp, key, klen, cdb_hash(key, klen), NULL);
}


void
cdb_pack(cdbi_t num, unsigned char buf[4])
{
  buf[0] = num & 255; num >>= 8;
  buf[1] = num & 255; num >>= 8;
  buf[2] = num & 255;
  buf[3] = num >> 8;
}


/* Initializes structure to create a database.  File FD should be
   opened read-write and should be seekable.  Returns 0 on success or
   negative value on error. */
int
cdb_make_start(struct cdb_make *cdbmp, int fd)
{
  memset (cdbmp, 0, sizeof *cdbmp);
  cdbmp->cdb_fd = fd;
  cdbmp->cdb_dpos = 2048;
  cdbmp->cdb_bpos = cdbmp->cdb_buf + 2048;
  return 0;
}


static int
ewrite(int fd, const char *buf, int len)
{
  while(len) {
    int l = write(fd, buf, len);
    if (l < 0 && errno != EINTR)
      return -1;
    if (l > 0)
      {
        len -= l;
        buf += l;
      }
  }
  return 0;
}

static int
make_write(struct cdb_make *cdbmp, const char *ptr, cdbi_t len)
{
  cdbi_t l = sizeof(cdbmp->cdb_buf) - (cdbmp->cdb_bpos - cdbmp->cdb_buf);
  cdbmp->cdb_dpos += len;
  if (len > l) {
    memcpy(cdbmp->cdb_bpos, ptr, l);
    if (ewrite(cdbmp->cdb_fd, cdbmp->cdb_buf, sizeof(cdbmp->cdb_buf)) < 0)
      return -1;
    ptr += l; len -= l;
    l = len / sizeof(cdbmp->cdb_buf);
    if (l) {
      l *= sizeof(cdbmp->cdb_buf);
      if (ewrite(cdbmp->cdb_fd, ptr, l) < 0)
	return -1;
      ptr += l; len -= l;
    }
    cdbmp->cdb_bpos = cdbmp->cdb_buf;
  }
  if (len) {
    memcpy(cdbmp->cdb_bpos, ptr, len);
    cdbmp->cdb_bpos += len;
  }
  return 0;
}

static int
cdb_make_finish_internal(struct cdb_make *cdbmp)
{
  cdbi_t hcnt[256];		/* hash table counts */
  cdbi_t hpos[256];		/* hash table positions */
  struct cdb_rec *htab;
  unsigned char *p;
  struct cdb_rl *rl;
  cdbi_t hsize;
  unsigned t, i;

  if (((0xffffffff - cdbmp->cdb_dpos) >> 3) < cdbmp->cdb_rcnt) {
    gpg_err_set_errno (ENOMEM);
    return -1;
  }

  /* count htab sizes and reorder reclists */
  hsize = 0;
  for (t = 0; t < 256; ++t) {
    struct cdb_rl *rlt = NULL;
    i = 0;
    rl = cdbmp->cdb_rec[t];
    while(rl) {
      struct cdb_rl *rln = rl->next;
      rl->next = rlt;
      rlt = rl;
      i += rl->cnt;
      rl = rln;
    }
    cdbmp->cdb_rec[t] = rlt;
    if (hsize < (hcnt[t] = i << 1))
      hsize = hcnt[t];
  }

  /* allocate memory to hold max htable */
  htab = (struct cdb_rec*)malloc((hsize + 2) * sizeof(struct cdb_rec));
  if (!htab) {
    gpg_err_set_errno (ENOENT);
    return -1;
  }
  p = (unsigned char *)htab;
  htab += 2;

  /* build hash tables */
  for (t = 0; t < 256; ++t) {
    cdbi_t len, hi;
    hpos[t] = cdbmp->cdb_dpos;
    if ((len = hcnt[t]) == 0)
      continue;
    for (i = 0; i < len; ++i)
      htab[i].hval = htab[i].rpos = 0;
    for (rl = cdbmp->cdb_rec[t]; rl; rl = rl->next)
      for (i = 0; i < rl->cnt; ++i) {
	hi = (rl->rec[i].hval >> 8) % len;
	while(htab[hi].rpos)
	  if (++hi == len)
	    hi = 0;
	htab[hi] = rl->rec[i];
      }
    for (i = 0; i < len; ++i) {
      cdb_pack(htab[i].hval, p + (i << 3));
      cdb_pack(htab[i].rpos, p + (i << 3) + 4);
    }
    if (make_write(cdbmp, p, len << 3) < 0) {
      free(p);
      return -1;
    }
  }
  free(p);
  if (cdbmp->cdb_bpos != cdbmp->cdb_buf &&
      ewrite(cdbmp->cdb_fd, cdbmp->cdb_buf,
	     cdbmp->cdb_bpos - cdbmp->cdb_buf) != 0)
      return -1;
  p = cdbmp->cdb_buf;
  for (t = 0; t < 256; ++t) {
    cdb_pack(hpos[t], p + (t << 3));
    cdb_pack(hcnt[t], p + (t << 3) + 4);
  }
  if (lseek(cdbmp->cdb_fd, 0, 0) != 0 ||
      ewrite(cdbmp->cdb_fd, p, 2048) != 0)
    return -1;

  return 0;
}

static void
cdb_make_free(struct cdb_make *cdbmp)
{
  unsigned t;
  for(t = 0; t < 256; ++t) {
    struct cdb_rl *rl = cdbmp->cdb_rec[t];
    while(rl) {
      struct cdb_rl *tm = rl;
      rl = rl->next;
      free(tm);
    }
  }
}



/* Finalizes database file, constructing all needed indexes, and frees
   memory structures.  It does not close the file descriptor.  Returns
   0 on success or a negative value on error. */
int
cdb_make_finish(struct cdb_make *cdbmp)
{
  int r = cdb_make_finish_internal(cdbmp);
  cdb_make_free(cdbmp);
  return r;
}


cdbi_t
cdb_hash(const void *buf, cdbi_t len)
{
  register const unsigned char *p = (const unsigned char *)buf;
  register const unsigned char *end = p + len;
  register cdbi_t hash = 5381;	/* start value */
  while (p < end)
    hash = (hash + (hash << 5)) ^ *p++;
  return hash;
}
