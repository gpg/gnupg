/* estream.h - Extended stream I/O/ Library
   Copyright (C) 2004 g10 Code GmbH

   This file is part of Libestream.
 
   Libestream is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published
   by the Free Software Foundation; either version 2 of the License,
   or (at your option) any later version.
 
   Libestream is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with Libestream; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef ESTREAM_H
#define ESTREAM_H

#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>



typedef struct estream_public *estream_t;
typedef struct estream_internal *estream_internal_t;

/* This struct is entirely private - use it and you will shoot
   yourself in the foot.  */
struct estream_public
{
  estream_internal_t internal;
  unsigned char *buffer;
  size_t buffer_size;
  size_t data_size;
  off_t data_offset;
  size_t data_flushed;
  unsigned char *unread_buffer;
  size_t unread_buffer_size;
  off_t unread_data_offset;
  unsigned int dirty: 1;
};

typedef ssize_t (*es_cookie_read_function_t) (void *cookie,
					      char *buffer, size_t size);
typedef ssize_t (*es_cookie_write_function_t) (void *cookie,
					       const char *buffer, size_t size);
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

#define restrict

int es_init (void);

estream_t es_fopen (const char * restrict path, const char * restrict mode);
estream_t es_mopen (unsigned char *data, size_t data_n, size_t data_size,
		    unsigned int grow,
		    void *(*func_realloc) (void *mem, size_t size),
		    void (*func_free) (void *mem),
		    const char * restrict mode);
estream_t es_open_memstream (char **ptr, size_t *size);
estream_t es_fdopen (int filedes, const char *mode);
estream_t es_freopen (const char *path, const char *mode, estream_t stream);
estream_t es_fopencookie (void *cookie,
			  const char * restrict mode, es_cookie_io_functions_t functions);
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

#define es_getc_unlocked(stream)                                         \
  (((! (stream)->dirty)                                               \
    && ((stream)->data_offset < (stream)->data_size)               \
    && (! (stream)->unread_data_offset)) ?                              \
   ((int) (unsigned char)                                                \
    (stream)->buffer[((stream)->data_offset)++]) :                    \
   _es_getc_underflow ((stream)))

#define es_putc_unlocked(c, stream) \
  (((stream)->dirty \
    && ((stream)->data_offset < (stream)->buffer_size)   \
    && (c != '\n')) ?                                                        \
   ((int) (unsigned char)                                                    \
    (stream)->buffer[((stream)->data_offset)++] = (c)) : \
   _es_putc_overflow ((c), (stream)))

#define es_getc(stream)    \
  es_fgetc (stream)
#define es_putc(c, stream) \
  es_fputc (c, stream)

int es_ungetc (int c, estream_t stream);

int es_read (estream_t stream,
	     char *buffer, size_t bytes_to_read, size_t *bytes_read);
int es_write (estream_t stream,
	      const char *buffer, size_t bytes_to_write, size_t *bytes_written);

size_t es_fread (void * restrict ptr, size_t size, size_t nitems,
		 estream_t  restrict stream);
size_t es_fwrite (const void * restrict ptr, size_t size, size_t memb,
		  estream_t  restrict stream);

char *es_fgets (char * restrict s, int n, estream_t restrict stream);
int es_fputs (const char * restrict s, estream_t restrict stream);

ssize_t es_getline (char **lineptr, size_t *n, estream_t stream);

int es_fprintf (estream_t restrict stream, const char * restrict format, ...);
int es_vfprintf (estream_t restrict stream, const char *restrict format,
		 va_list ap);

int es_setvbuf (estream_t restrict stream,
		char * restrict buf, int mode, size_t size);
void es_setbuf (estream_t restrict stream, char * restrict buf);

estream_t es_tmpfile (void);

void es_opaque_set (estream_t stream, void *opaque);
void *es_opaque_get (estream_t stream);

#endif
