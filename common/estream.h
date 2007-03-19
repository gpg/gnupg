/* estream.h - Extended stream I/O/ Library
 * Copyright (C) 2004 g10 Code GmbH
 *
 * This file is part of Libestream.
 *
 * Libestream is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Libestream is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Libestream; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#ifndef ESTREAM_H
#define ESTREAM_H

#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>


/* Forward declaration for the (opaque) internal type.  */
struct estream_internal;

/* The definition of this struct is entirely private.  You must not
   use it for anything.  It is only here so some functions can be
   implemented as macros.  */
struct es__stream
{
  /* The layout of this struct must never change.  It may be grown,
     but only if all functions which access the new members are
     versioned.  */

  /* A pointer to the stream buffer.  */
  unsigned char *buffer;

  /* The size of the buffer in bytes.  */
  size_t buffer_size;

  /* The length of the usable data in the buffer, only valid when in
     read mode (see flags).  */
  size_t data_len;

  /* The current position of the offset pointer, valid in read and
     write mode.  */
  size_t data_offset;

  size_t data_flushed;
  unsigned char *unread_buffer;
  size_t unread_buffer_size;

  /* The number of unread bytes.  */
  size_t unread_data_len;

  /* Various flags.  */
#define ES__FLAG_WRITING	(1 << 0)
  unsigned int flags;

  /* A pointer to our internal data for this stream.  */
  struct estream_internal *intern;
};

/* The opaque type for an estream.  */
typedef struct es__stream *estream_t;


typedef ssize_t (*es_cookie_read_function_t) (void *cookie,
					      void *buffer, size_t size);
typedef ssize_t (*es_cookie_write_function_t) (void *cookie,
					       const void *buffer,
					       size_t size);
typedef int (*es_cookie_seek_function_t) (void *cookie,
					  off_t *pos, int whence);
typedef int (*es_cookie_close_function_t) (void *cookie);

typedef struct es_cookie_io_functions
{
  es_cookie_read_function_t func_read;
  es_cookie_write_function_t func_write;
  es_cookie_seek_function_t func_seek;
  es_cookie_close_function_t func_close;
} es_cookie_io_functions_t;


#ifndef ES__RESTRICT
#  if defined __GNUC__ && defined __GNUC_MINOR__
#    if  (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 92))
#      define ES__RESTRICT __restrict__
#    endif
#  endif
#endif
#ifndef ES__RESTRICT
#  define ES__RESTRICT
#endif

int es_init (void);

estream_t es_fopen (const char *ES__RESTRICT path,
		    const char *ES__RESTRICT mode);
estream_t es_mopen (unsigned char *ES__RESTRICT data,
		    size_t data_n, size_t data_len,
		    unsigned int grow,
		    void *(*func_realloc) (void *mem, size_t size),
		    void (*func_free) (void *mem),
		    const char *ES__RESTRICT mode);
estream_t es_open_memstream (char **ptr, size_t *size);
estream_t es_fdopen (int filedes, const char *mode);
estream_t es_freopen (const char *ES__RESTRICT path,
		      const char *ES__RESTRICT mode,
		      estream_t ES__RESTRICT stream);
estream_t es_fopencookie (void *ES__RESTRICT cookie,
			  const char *ES__RESTRICT mode,
			  es_cookie_io_functions_t functions);
int es_fclose (estream_t stream);
int es_fileno (estream_t stream);
int es_fileno_unlocked (estream_t stream);

void es_flockfile (estream_t stream);
int es_ftrylockfile (estream_t stream);
void es_funlockfile (estream_t stream);

int es_feof (estream_t stream);
int es_feof_unlocked (estream_t stream);
int es_ferror (estream_t stream);
int es_ferror_unlocked (estream_t stream);
void es_clearerr (estream_t stream);
void es_clearerr_unlocked (estream_t stream);

int es_fflush (estream_t stream);
int es_fseek (estream_t stream, long int offset, int whence);
int es_fseeko (estream_t stream, off_t offset, int whence);
long int es_ftell (estream_t stream);
off_t es_ftello (estream_t stream);
void es_rewind (estream_t stream);

int es_fgetc (estream_t stream);
int es_fputc (int c, estream_t stream);

int _es_getc_underflow (estream_t stream);
int _es_putc_overflow (int c, estream_t stream);

#define es_getc_unlocked(stream)				\
  (((! ((stream)->flags & 1))					\
    && ((stream)->data_offset < (stream)->data_len)		\
    && (! (stream)->unread_data_len))				\
  ? ((int) (stream)->buffer[((stream)->data_offset)++])		\
  : _es_getc_underflow ((stream)))

#define es_putc_unlocked(c, stream)				\
  ((((stream)->flags & 1)					\
    && ((stream)->data_offset < (stream)->buffer_size)		\
    && (c != '\n'))						\
  ? ((int) ((stream)->buffer[((stream)->data_offset)++] = (c)))	\
  : _es_putc_overflow ((c), (stream)))

#define es_getc(stream)    es_fgetc (stream)
#define es_putc(c, stream) es_fputc (c, stream)

int es_ungetc (int c, estream_t stream);

int es_read (estream_t ES__RESTRICT stream,
	     void *ES__RESTRICT buffer, size_t bytes_to_read,
	     size_t *ES__RESTRICT bytes_read);
int es_write (estream_t ES__RESTRICT stream,
	      const void *ES__RESTRICT buffer, size_t bytes_to_write,
	      size_t *ES__RESTRICT bytes_written);
int es_write_sanitized (estream_t ES__RESTRICT stream,
                        const void *ES__RESTRICT buffer, size_t length,
                        const char *delimiters,
                        size_t *ES__RESTRICT bytes_written);
int es_write_hexstring (estream_t ES__RESTRICT stream,
                        const void *ES__RESTRICT buffer, size_t length,
                        int reserved, size_t *ES__RESTRICT bytes_written);

size_t es_fread (void *ES__RESTRICT ptr, size_t size, size_t nitems,
		 estream_t ES__RESTRICT stream);
size_t es_fwrite (const void *ES__RESTRICT ptr, size_t size, size_t memb,
		  estream_t ES__RESTRICT stream);

char *es_fgets (char *ES__RESTRICT s, int n, estream_t ES__RESTRICT stream);
int es_fputs (const char *ES__RESTRICT s, estream_t ES__RESTRICT stream);

ssize_t es_getline (char *ES__RESTRICT *ES__RESTRICT lineptr,
		    size_t *ES__RESTRICT n,
		    estream_t stream);
ssize_t es_read_line (estream_t stream, 
                      char **addr_of_buffer, size_t *length_of_buffer,
                      size_t *max_length);
void es_free (void *a);

int es_fprintf (estream_t ES__RESTRICT stream,
		const char *ES__RESTRICT format, ...);
int es_vfprintf (estream_t ES__RESTRICT stream,
		 const char *ES__RESTRICT format, va_list ap);

int es_setvbuf (estream_t ES__RESTRICT stream,
		char *ES__RESTRICT buf, int mode, size_t size);
void es_setbuf (estream_t ES__RESTRICT stream, char *ES__RESTRICT buf);

estream_t es_tmpfile (void);

void es_opaque_set (estream_t ES__RESTRICT stream, void *ES__RESTRICT opaque);
void *es_opaque_get (estream_t stream);



#ifdef GNUPG_MAJOR_VERSION
int es_write_sanitized_utf8_buffer (estream_t stream,
                                    const void *buffer, size_t length, 
                                    const char *delimiters,
                                    size_t *bytes_written);
#endif /*GNUPG_MAJOR_VERSION*/


#endif /*ESTREAM_H*/

