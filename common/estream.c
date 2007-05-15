/* estream.c - Extended Stream I/O Library
 * Copyright (C) 2004, 2005, 2006, 2007 g10 Code GmbH
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
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Libestream; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#ifdef USE_ESTREAM_SUPPORT_H
# include <estream-support.h>
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <assert.h>

#ifdef WITHOUT_GNU_PTH /* Give the Makefile a chance to build without Pth.  */
#undef HAVE_PTH
#undef USE_GNU_PTH
#endif

#ifdef HAVE_PTH
# include <pth.h>
#endif

/* This is for the special hack to use estream.c in GnuPG.  */
#ifdef GNUPG_MAJOR_VERSION
#include "../common/util.h"
#endif

#ifndef HAVE_MKSTEMP
int mkstemp (char *template);
#endif

#ifndef HAVE_MEMRCHR
void *memrchr (const void *block, int c, size_t size);
#endif

#include <estream.h>
#include <estream-printf.h>



/* Generally used types.  */

typedef void *(*func_realloc_t) (void *mem, size_t size);
typedef void (*func_free_t) (void *mem);

#ifdef HAVE_FOPENCOOKIE
typedef ssize_t my_funopen_hook_ret_t;
#else
typedef int     my_funopen_hook_ret_t;
#endif




/* Buffer management layer.  */

#define BUFFER_BLOCK_SIZE  BUFSIZ
#define BUFFER_UNREAD_SIZE 16



/* Macros.  */

#define BUFFER_ROUND_TO_BLOCK(size, block_size) \
  (((size) + (block_size - 1)) / block_size)



/* Locking.  */

#ifdef HAVE_PTH

typedef pth_mutex_t estream_mutex_t;
# define ESTREAM_MUTEX_INITIALIZER PTH_MUTEX_INIT
# define ESTREAM_MUTEX_LOCK(mutex)        \
  pth_mutex_acquire (&(mutex), 0, NULL)
# define ESTREAM_MUTEX_UNLOCK(mutex)      \
  pth_mutex_release (&(mutex))
# define ESTREAM_MUTEX_TRYLOCK(mutex)     \
  ((pth_mutex_acquire (&(mutex), 1, NULL) == TRUE) ? 0 : -1)
# define ESTREAM_MUTEX_INITIALIZE(mutex)  \
  pth_mutex_init    (&(mutex))
# define ESTREAM_THREADING_INIT() ((pth_init () == TRUE) ? 0 : -1)

#else

typedef void *estream_mutex_t;
# define ESTREAM_MUTEX_INITIALIZER NULL
# define ESTREAM_MUTEX_LOCK(mutex) (void) 0
# define ESTREAM_MUTEX_UNLOCK(mutex) (void) 0
# define ESTREAM_MUTEX_TRYLOCK(mutex) 0
# define ESTREAM_MUTEX_INITIALIZE(mutex) (void) 0
# define ESTREAM_THREADING_INIT() 0

#endif

/* Memory allocator functions.  */

#define MEM_ALLOC   malloc
#define MEM_REALLOC realloc
#define MEM_FREE    free

/* Primitive system I/O.  */

#ifdef HAVE_PTH
# define ESTREAM_SYS_READ  pth_read
# define ESTREAM_SYS_WRITE pth_write
#else
# define ESTREAM_SYS_READ  read
# define ESTREAM_SYS_WRITE write
#endif

/* Misc definitions.  */

#define ES_DEFAULT_OPEN_MODE (S_IRUSR | S_IWUSR)

#define ES_FLAG_WRITING ES__FLAG_WRITING

/* An internal stream object.  */

struct estream_internal
{
  unsigned char buffer[BUFFER_BLOCK_SIZE];
  unsigned char unread_buffer[BUFFER_UNREAD_SIZE];
  estream_mutex_t lock;		 /* Lock. */
  void *cookie;			 /* Cookie.               */
  void *opaque;			 /* Opaque data.          */
  unsigned int flags;		 /* Flags.                */
  off_t offset;
  es_cookie_read_function_t func_read;
  es_cookie_write_function_t func_write;
  es_cookie_seek_function_t func_seek;
  es_cookie_close_function_t func_close;
  int strategy;
  int fd;
  struct
  {
    unsigned int err: 1;
    unsigned int eof: 1;
  } indicators;
  unsigned int deallocate_buffer: 1;
  unsigned int print_err: 1;     /* Error in print_fun_writer.  */
  int print_errno;               /* Errno from print_fun_writer.  */
  size_t print_ntotal;           /* Bytes written from in print_fun_writer. */
  FILE *print_fp;                /* Stdio stream used by print_fun_writer.  */
};


typedef struct estream_internal *estream_internal_t;

#define ESTREAM_LOCK(stream) ESTREAM_MUTEX_LOCK (stream->intern->lock)
#define ESTREAM_UNLOCK(stream) ESTREAM_MUTEX_UNLOCK (stream->intern->lock)
#define ESTREAM_TRYLOCK(stream) ESTREAM_MUTEX_TRYLOCK (stream->intern->lock)

/* Stream list.  */

typedef struct estream_list *estream_list_t;

struct estream_list
{
  estream_t car;
  estream_list_t cdr;
  estream_list_t *prev_cdr;
};

static estream_list_t estream_list;
#ifdef HAVE_PTH
static estream_mutex_t estream_list_lock = ESTREAM_MUTEX_INITIALIZER;
#endif

#define ESTREAM_LIST_LOCK   ESTREAM_MUTEX_LOCK   (estream_list_lock)
#define ESTREAM_LIST_UNLOCK ESTREAM_MUTEX_UNLOCK (estream_list_lock)

#ifndef EOPNOTSUPP
# define EOPNOTSUPP ENOSYS
#endif




/* Macros.  */

/* Calculate array dimension.  */
#ifndef DIM
#define DIM(array) (sizeof (array) / sizeof (*array))
#endif

/* Evaluate EXPRESSION, setting VARIABLE to the return code, if
   VARIABLE is zero.  */
#define SET_UNLESS_NONZERO(variable, tmp_variable, expression) \
  do                                                           \
    {                                                          \
      tmp_variable = expression;                               \
      if ((! variable) && tmp_variable)                        \
        variable = tmp_variable;                               \
    }                                                          \
  while (0)

/*
 * List manipulation.
 */

/* Add STREAM to the list of registered stream objects.  */
static int
es_list_add (estream_t stream)
{
  estream_list_t list_obj;
  int ret;

  list_obj = MEM_ALLOC (sizeof (*list_obj));
  if (! list_obj)
    ret = -1;
  else
    {
      ESTREAM_LIST_LOCK;
      list_obj->car = stream;
      list_obj->cdr = estream_list;
      list_obj->prev_cdr = &estream_list;
      if (estream_list)
	estream_list->prev_cdr = &list_obj->cdr;
      estream_list = list_obj;
      ESTREAM_LIST_UNLOCK;
      ret = 0;
    }

  return ret;
}

/* Remove STREAM from the list of registered stream objects.  */
static void
es_list_remove (estream_t stream)
{
  estream_list_t list_obj;
  
  ESTREAM_LIST_LOCK;
  for (list_obj = estream_list; list_obj; list_obj = list_obj->cdr)
    if (list_obj->car == stream)
      {
	*list_obj->prev_cdr = list_obj->cdr;
	if (list_obj->cdr)
	  list_obj->cdr->prev_cdr = list_obj->prev_cdr;
	MEM_FREE (list_obj);
	break;
      }
  ESTREAM_LIST_UNLOCK;
}

/* Type of an stream-iterator-function.  */
typedef int (*estream_iterator_t) (estream_t stream);

/* Iterate over list of registered streams, calling ITERATOR for each
   of them.  */
static int
es_list_iterate (estream_iterator_t iterator)
{
  estream_list_t list_obj;
  int ret = 0;

  ESTREAM_LIST_LOCK;
  for (list_obj = estream_list; list_obj; list_obj = list_obj->cdr)
    ret |= (*iterator) (list_obj->car);
  ESTREAM_LIST_UNLOCK;

  return ret;
}



/*
 * Initialization.
 */

static int
es_init_do (void)
{
  int err;

  err = ESTREAM_THREADING_INIT ();

  return err;
}



/*
 * I/O methods.
 */

/* Implementation of Memory I/O.  */

/* Cookie for memory objects.  */
typedef struct estream_cookie_mem
{
  unsigned int flags;		/* Open flags.  */
  unsigned char *memory;	/* Data.  */
  size_t memory_size;		/* Size of MEMORY.  */
  size_t offset;		/* Current offset in MEMORY.  */
  size_t data_len;		/* Length of data in MEMORY.  */
  size_t block_size;		/* Block size.  */
  unsigned int grow: 1;		/* MEMORY is allowed to grow.  */
  unsigned int append_zero: 1;	/* Append zero after data.  */
  unsigned int dont_free: 1;	/* Append zero after data.  */
  char **ptr;
  size_t *size;
  func_realloc_t func_realloc;
  func_free_t func_free;
} *estream_cookie_mem_t;

/* Create function for memory objects.  */
static int
es_func_mem_create (void *ES__RESTRICT *ES__RESTRICT cookie,
		    unsigned char *ES__RESTRICT data, size_t data_n,
		    size_t data_len,
		    size_t block_size, unsigned int grow,
		    unsigned int append_zero, unsigned int dont_free,
		    char **ptr, size_t *size,
		    func_realloc_t func_realloc, func_free_t func_free,
		    unsigned int flags)
{
  estream_cookie_mem_t mem_cookie;
  int err;

  mem_cookie = MEM_ALLOC (sizeof (*mem_cookie));
  if (! mem_cookie)
    err = -1;
  else
    {
      mem_cookie->flags = flags;
      mem_cookie->memory = data;
      mem_cookie->memory_size = data_n;
      mem_cookie->offset = 0;
      mem_cookie->data_len = data_len;
      mem_cookie->block_size = block_size;
      mem_cookie->grow = grow ? 1 : 0;
      mem_cookie->append_zero = append_zero ? 1 : 0;
      mem_cookie->dont_free = dont_free ? 1 : 0;
      mem_cookie->ptr = ptr;
      mem_cookie->size = size;
      mem_cookie->func_realloc = func_realloc ? func_realloc : MEM_REALLOC;
      mem_cookie->func_free = func_free ? func_free : MEM_FREE;
      mem_cookie->offset = 0;
      *cookie = mem_cookie;
      err = 0;
    }

  return err;
}

/* Read function for memory objects.  */
static ssize_t
es_func_mem_read (void *cookie, void *buffer, size_t size)
{
  estream_cookie_mem_t mem_cookie = cookie;
  ssize_t ret;

  if (size > mem_cookie->data_len - mem_cookie->offset)
    size = mem_cookie->data_len - mem_cookie->offset;

  if (size)
    {
      memcpy (buffer, mem_cookie->memory + mem_cookie->offset, size);
      mem_cookie->offset += size;
    }
  
  ret = size;

  return ret;
}

/* Write function for memory objects.  */
static ssize_t
es_func_mem_write (void *cookie, const void *buffer, size_t size)
{
  estream_cookie_mem_t mem_cookie = cookie;
  func_realloc_t func_realloc = mem_cookie->func_realloc;
  unsigned char *memory_new;
  size_t newsize;
  ssize_t ret;
  int err;

  if (size)
    {
      /* Regular write.  */

      if (mem_cookie->flags & O_APPEND)
	/* Append to data.  */
	mem_cookie->offset = mem_cookie->data_len;
	  
      if (! mem_cookie->grow)
	if (size > mem_cookie->memory_size - mem_cookie->offset)
	  size = mem_cookie->memory_size - mem_cookie->offset;

      err = 0;

      while (size > (mem_cookie->memory_size - mem_cookie->offset))
	{
	  memory_new = (*func_realloc) (mem_cookie->memory,
					mem_cookie->memory_size
					+ mem_cookie->block_size);
	  if (! memory_new)
	    {
	      err = -1;
	      break;
	    }
	  else
	    {
	      if (mem_cookie->memory != memory_new)
		mem_cookie->memory = memory_new;
	      mem_cookie->memory_size += mem_cookie->block_size;
	    }
	}
      if (err)
	goto out;

      if (size)
	{
	  memcpy (mem_cookie->memory + mem_cookie->offset, buffer, size);
	  if (mem_cookie->offset + size > mem_cookie->data_len)
	    mem_cookie->data_len = mem_cookie->offset + size;
	  mem_cookie->offset += size;
	}
    }
  else
    {
      /* Flush.  */

      err = 0;
      if (mem_cookie->append_zero)
	{
	  if (mem_cookie->data_len >= mem_cookie->memory_size)
	    {
	      newsize = BUFFER_ROUND_TO_BLOCK (mem_cookie->data_len + 1,
					       mem_cookie->block_size)
		* mem_cookie->block_size;
	  
	      memory_new = (*func_realloc) (mem_cookie->memory, newsize);
	      if (! memory_new)
		{
		  err = -1;
		  goto out;
		}

	      if (mem_cookie->memory != memory_new)
		mem_cookie->memory = memory_new;
	      mem_cookie->memory_size = newsize;
	    }

	  mem_cookie->memory[mem_cookie->data_len + 1] = 0;
	}

      /* Return information to user if necessary.  */
      if (mem_cookie->ptr)
	*mem_cookie->ptr = (char *) mem_cookie->memory;
      if (mem_cookie->size)
	*mem_cookie->size = mem_cookie->data_len;
    }

 out:

  if (err)
    ret = -1;
  else
    ret = size;

  return ret;
}

/* Seek function for memory objects.  */
static int
es_func_mem_seek (void *cookie, off_t *offset, int whence)
{
  estream_cookie_mem_t mem_cookie = cookie;
  off_t pos_new;
  int err = 0;

  switch (whence)
    {
    case SEEK_SET:
      pos_new = *offset;
      break;

    case SEEK_CUR:
      pos_new = mem_cookie->offset += *offset;
      break;

    case SEEK_END:
      pos_new = mem_cookie->data_len += *offset;
      break;

    default:
      /* Never reached.  */
      pos_new = 0;
    }

  if (pos_new > mem_cookie->memory_size)
    {
      /* Grow buffer if possible.  */

      if (mem_cookie->grow)
	{
	  func_realloc_t func_realloc = mem_cookie->func_realloc;
	  size_t newsize;
	  void *p;

	  newsize = BUFFER_ROUND_TO_BLOCK (pos_new, mem_cookie->block_size);
	  p = (*func_realloc) (mem_cookie->memory, newsize);
	  if (! p)
	    {
	      err = -1;
	      goto out;
	    }
	  else
	    {
	      if (mem_cookie->memory != p)
		mem_cookie->memory = p;
	      mem_cookie->memory_size = newsize;
	    }
	}
      else
	{
	  errno = EINVAL;
	  err = -1;
	  goto out;
	}
    }

  if (pos_new > mem_cookie->data_len)
    /* Fill spare space with zeroes.  */
    memset (mem_cookie->memory + mem_cookie->data_len,
	    0, pos_new - mem_cookie->data_len);

  mem_cookie->offset = pos_new;
  *offset = pos_new;

 out:

  return err;
}

/* Destroy function for memory objects.  */
static int
es_func_mem_destroy (void *cookie)
{
  estream_cookie_mem_t mem_cookie = cookie;
  func_free_t func_free = mem_cookie->func_free;

  if (! mem_cookie->dont_free)
    (*func_free) (mem_cookie->memory);
  MEM_FREE (mem_cookie);

  return 0;
}

static es_cookie_io_functions_t estream_functions_mem =
  {
    es_func_mem_read,
    es_func_mem_write,
    es_func_mem_seek,
    es_func_mem_destroy
  };

/* Implementation of fd I/O.  */

/* Cookie for fd objects.  */
typedef struct estream_cookie_fd
{
  int fd;
} *estream_cookie_fd_t;

/* Create function for fd objects.  */
static int
es_func_fd_create (void **cookie, int fd, unsigned int flags)
{
  estream_cookie_fd_t fd_cookie;
  int err;

  fd_cookie = MEM_ALLOC (sizeof (*fd_cookie));
  if (! fd_cookie)
    err = -1;
  else
    {
      fd_cookie->fd = fd;
      *cookie = fd_cookie;
      err = 0;
    }
  
  return err;
}

/* Read function for fd objects.  */
static ssize_t
es_func_fd_read (void *cookie, void *buffer, size_t size)

{
  estream_cookie_fd_t file_cookie = cookie;
  ssize_t bytes_read;

  do 
    bytes_read = ESTREAM_SYS_READ (file_cookie->fd, buffer, size);
  while (bytes_read == -1 && errno == EINTR);

  return bytes_read;
}

/* Write function for fd objects.  */
static ssize_t
es_func_fd_write (void *cookie, const void *buffer, size_t size)
			   
{
  estream_cookie_fd_t file_cookie = cookie;
  ssize_t bytes_written;

  do
    bytes_written = ESTREAM_SYS_WRITE (file_cookie->fd, buffer, size);
  while (bytes_written == -1 && errno == EINTR);

  return bytes_written;
}

/* Seek function for fd objects.  */
static int
es_func_fd_seek (void *cookie, off_t *offset, int whence)
{
  estream_cookie_fd_t file_cookie = cookie;
  off_t offset_new;
  int err;

  offset_new = lseek (file_cookie->fd, *offset, whence);
  if (offset_new == -1)
    err = -1;
  else
    {
      *offset = offset_new;
      err = 0;
    }

  return err;
}

/* Destroy function for fd objects.  */
static int
es_func_fd_destroy (void *cookie)
{
  estream_cookie_fd_t fd_cookie = cookie;
  int err;

  if (fd_cookie)
    {
      err = close (fd_cookie->fd);
      MEM_FREE (fd_cookie);
    }
  else
    err = 0;

  return err;
}

static es_cookie_io_functions_t estream_functions_fd =
  {
    es_func_fd_read,
    es_func_fd_write,
    es_func_fd_seek,
    es_func_fd_destroy
  };

/* Implementation of file I/O.  */

/* Create function for file objects.  */
static int
es_func_file_create (void **cookie, int *filedes,
		     const char *path, unsigned int flags)
{
  estream_cookie_fd_t file_cookie;
  int err;
  int fd;

  err = 0;
  fd = -1;

  file_cookie = MEM_ALLOC (sizeof (*file_cookie));
  if (! file_cookie)
    {
      err = -1;
      goto out;
    }

  fd = open (path, flags, ES_DEFAULT_OPEN_MODE);
  if (fd == -1)
    {
      err = -1;
      goto out;
    }

  file_cookie->fd = fd;
  *cookie = file_cookie;
  *filedes = fd;

 out:

  if (err)
    MEM_FREE (file_cookie);

  return err;
}

static es_cookie_io_functions_t estream_functions_file =
  {
    es_func_fd_read,
    es_func_fd_write,
    es_func_fd_seek,
    es_func_fd_destroy
  };



/* Stream primitives.  */

static int
es_convert_mode (const char *mode, unsigned int *flags)
{

  /* FIXME: We need to allow all mode flags permutations and for
     binary mode we need to do a

     #ifdef HAVE_DOSISH_SYSTEM
       setmode (fd, O_BINARY);
     #endif
  */
  struct
  {
    const char *mode;
    unsigned int flags;
  } mode_flags[] = { { "r",
		       O_RDONLY },
		     { "rb",
		       O_RDONLY },
		     { "w",
		       O_WRONLY | O_TRUNC | O_CREAT },
		     { "wb",
		       O_WRONLY | O_TRUNC | O_CREAT },
		     { "a",
		       O_WRONLY | O_APPEND | O_CREAT },
		     { "ab",
		       O_WRONLY | O_APPEND | O_CREAT },
		     { "r+",
		       O_RDWR },
		     { "rb+",
		       O_RDWR },
		     { "r+b",
		       O_RDONLY | O_WRONLY },
		     { "w+",
		       O_RDWR | O_TRUNC | O_CREAT },
		     { "wb+",
		       O_RDWR | O_TRUNC | O_CREAT },
		     { "w+b",
		       O_RDWR | O_TRUNC | O_CREAT },
		     { "a+",
		       O_RDWR | O_CREAT | O_APPEND },
		     { "ab+",
		       O_RDWR | O_CREAT | O_APPEND },
		     { "a+b",
		       O_RDWR | O_CREAT | O_APPEND } };
  unsigned int i;
  int err; 

  for (i = 0; i < DIM (mode_flags); i++)
    if (! strcmp (mode_flags[i].mode, mode))
      break;
  if (i == DIM (mode_flags))
    {
      errno = EINVAL;
      err = -1;
    }
  else
    {
      err = 0;
      *flags = mode_flags[i].flags;
    }

  return err;
}



/*
 * Low level stream functionality.
 */

static int
es_fill (estream_t stream)
{
  size_t bytes_read = 0;
  int err;

  if (!stream->intern->func_read)
    {
      errno = EOPNOTSUPP;
      err = -1;
    }
  else
    {
      es_cookie_read_function_t func_read = stream->intern->func_read;
      ssize_t ret;

      ret = (*func_read) (stream->intern->cookie,
			  stream->buffer, stream->buffer_size);
      if (ret == -1)
	{
	  bytes_read = 0;
	  err = -1;
	}
      else
	{
	  bytes_read = ret;
	  err = 0;
	}
    }

  if (err)
    stream->intern->indicators.err = 1;
  else if (!bytes_read)
    stream->intern->indicators.eof = 1;

  stream->intern->offset += stream->data_len;
  stream->data_len = bytes_read;
  stream->data_offset = 0;

  return err;
}

static int
es_flush (estream_t stream)
{
  es_cookie_write_function_t func_write = stream->intern->func_write;
  int err;

  assert (stream->flags & ES_FLAG_WRITING);

  if (stream->data_offset)
    {
      size_t bytes_written;
      size_t data_flushed;
      ssize_t ret;

      if (! func_write)
	{
	  err = EOPNOTSUPP;
	  goto out;
	}

      /* Note: to prevent an endless loop caused by user-provided
	 write-functions that pretend to have written more bytes than
	 they were asked to write, we have to check for
	 "(stream->data_offset - data_flushed) > 0" instead of
	 "stream->data_offset - data_flushed".  */
      
      data_flushed = 0;
      err = 0;
      
      while ((((ssize_t) (stream->data_offset - data_flushed)) > 0) && (! err))
	{
	  ret = (*func_write) (stream->intern->cookie,
			       stream->buffer + data_flushed,
			       stream->data_offset - data_flushed);
	  if (ret == -1)
	    {
	      bytes_written = 0;
	      err = -1;
	    }
	  else
	    bytes_written = ret;

	  data_flushed += bytes_written;
	  if (err)
	    break;
	}

      stream->data_flushed += data_flushed;
      if (stream->data_offset == data_flushed)
	{
	  stream->intern->offset += stream->data_offset;
	  stream->data_offset = 0;
	  stream->data_flushed = 0;

	  /* Propagate flush event.  */
	  (*func_write) (stream->intern->cookie, NULL, 0);
	}
    }
  else
    err = 0;

 out:
    
  if (err)
    stream->intern->indicators.err = 1;

  return err;
}

/* Discard buffered data for STREAM.  */
static void
es_empty (estream_t stream)
{
  assert (! (stream->flags & ES_FLAG_WRITING));
  stream->data_len = 0;
  stream->data_offset = 0;
  stream->unread_data_len = 0;
}

/* Initialize STREAM.  */
static void
es_initialize (estream_t stream,
	       void *cookie, int fd, es_cookie_io_functions_t functions)
{
  stream->intern->cookie = cookie;
  stream->intern->opaque = NULL;
  stream->intern->offset = 0;
  stream->intern->func_read = functions.func_read;
  stream->intern->func_write = functions.func_write;
  stream->intern->func_seek = functions.func_seek;
  stream->intern->func_close = functions.func_close;
  stream->intern->strategy = _IOFBF;
  stream->intern->fd = fd;
  stream->intern->print_err = 0;
  stream->intern->print_errno = 0;
  stream->intern->print_ntotal = 0;
  stream->intern->print_fp = NULL;
  stream->intern->indicators.err = 0;
  stream->intern->indicators.eof = 0;
  stream->intern->deallocate_buffer = 0;

  stream->data_len = 0;
  stream->data_offset = 0;
  stream->data_flushed = 0;
  stream->unread_data_len = 0;
  stream->flags = 0;
}

/* Deinitialize STREAM.  */
static int
es_deinitialize (estream_t stream)
{
  es_cookie_close_function_t func_close;
  int err, tmp_err;

  if (stream->intern->print_fp)
    {
      int save_errno = errno;
      fclose (stream->intern->print_fp);
      stream->intern->print_fp = NULL;
      errno = save_errno;
    }

  func_close = stream->intern->func_close;

  err = 0;
  if (stream->flags & ES_FLAG_WRITING)
    SET_UNLESS_NONZERO (err, tmp_err, es_flush (stream));
  if (func_close)
    SET_UNLESS_NONZERO (err, tmp_err, (*func_close) (stream->intern->cookie));

  
  return err;
}

/* Create a new stream object, initialize it.  */
static int
es_create (estream_t *stream, void *cookie, int fd,
	   es_cookie_io_functions_t functions)
{
  estream_internal_t stream_internal_new;
  estream_t stream_new;
  int err;

  stream_new = NULL;
  stream_internal_new = NULL;

  stream_new = MEM_ALLOC (sizeof (*stream_new));
  if (! stream_new)
    {
      err = -1;
      goto out;
    }

  stream_internal_new = MEM_ALLOC (sizeof (*stream_internal_new));
  if (! stream_internal_new)
    {
      err = -1;
      goto out;
    }

  stream_new->buffer = stream_internal_new->buffer;
  stream_new->buffer_size = sizeof (stream_internal_new->buffer);
  stream_new->unread_buffer = stream_internal_new->unread_buffer;
  stream_new->unread_buffer_size = sizeof (stream_internal_new->unread_buffer);
  stream_new->intern = stream_internal_new;

  ESTREAM_MUTEX_INITIALIZE (stream_new->intern->lock);
  es_initialize (stream_new, cookie, fd, functions);

  err = es_list_add (stream_new);
  if (err)
    goto out;

  *stream = stream_new;

 out:

  if (err)
    {
      if (stream_new)
	{
	  es_deinitialize (stream_new);
	  MEM_FREE (stream_new);
	}
    }

  return err;
}

/* Deinitialize a stream object and destroy it.  */
static int
es_destroy (estream_t stream)
{
  int err = 0;

  if (stream)
    {
      es_list_remove (stream);
      err = es_deinitialize (stream);
      MEM_FREE (stream->intern);
      MEM_FREE (stream);
    }

  return err;
}

/* Try to read BYTES_TO_READ bytes FROM STREAM into BUFFER in
   unbuffered-mode, storing the amount of bytes read in
   *BYTES_READ.  */
static int
es_read_nbf (estream_t ES__RESTRICT stream,
	     unsigned char *ES__RESTRICT buffer,
	     size_t bytes_to_read, size_t *ES__RESTRICT bytes_read)
{
  es_cookie_read_function_t func_read = stream->intern->func_read;
  size_t data_read;
  ssize_t ret;
  int err;

  data_read = 0;
  err = 0;

  while (bytes_to_read - data_read)
    {
      ret = (*func_read) (stream->intern->cookie,
			  buffer + data_read, bytes_to_read - data_read);
      if (ret == -1)
	{
	  err = -1;
	  break;
	}
      else if (ret)
	data_read += ret;
      else
	break;
    }

  stream->intern->offset += data_read;
  *bytes_read = data_read;

  return err;
}

/* Try to read BYTES_TO_READ bytes FROM STREAM into BUFFER in
   fully-buffered-mode, storing the amount of bytes read in
   *BYTES_READ.  */
static int
es_read_fbf (estream_t ES__RESTRICT stream,
	     unsigned char *ES__RESTRICT buffer,
	     size_t bytes_to_read, size_t *ES__RESTRICT bytes_read)
{
  size_t data_available;
  size_t data_to_read;
  size_t data_read;
  int err;

  data_read = 0;
  err = 0;

  while ((bytes_to_read - data_read) && (! err))
    {
      if (stream->data_offset == stream->data_len)
	{
	  /* Nothing more to read in current container, try to
	     fill container with new data.  */
	  err = es_fill (stream);
	  if (! err)
	    if (! stream->data_len)
	      /* Filling did not result in any data read.  */
	      break;
	}

      if (! err)
	{
	  /* Filling resulted in some new data.  */

	  data_to_read = bytes_to_read - data_read;
	  data_available = stream->data_len - stream->data_offset;
	  if (data_to_read > data_available)
	    data_to_read = data_available;

	  memcpy (buffer + data_read,
		  stream->buffer + stream->data_offset, data_to_read);
	  stream->data_offset += data_to_read;
	  data_read += data_to_read;
	}
    }

  *bytes_read = data_read;

  return err;
}

/* Try to read BYTES_TO_READ bytes FROM STREAM into BUFFER in
   line-buffered-mode, storing the amount of bytes read in
   *BYTES_READ.  */
static int
es_read_lbf (estream_t ES__RESTRICT stream,
	     unsigned char *ES__RESTRICT buffer,
	     size_t bytes_to_read, size_t *ES__RESTRICT bytes_read)
{
  int err;

  err = es_read_fbf (stream, buffer, bytes_to_read, bytes_read);

  return err;
}

/* Try to read BYTES_TO_READ bytes FROM STREAM into BUFFER, storing
   *the amount of bytes read in BYTES_READ.  */
static int
es_readn (estream_t ES__RESTRICT stream,
	  void *ES__RESTRICT buffer_arg,
	  size_t bytes_to_read, size_t *ES__RESTRICT bytes_read)
{
  unsigned char *buffer = (unsigned char *)buffer_arg;
  size_t data_read_unread, data_read;
  int err;

  data_read_unread = 0;
  data_read = 0;
  err = 0;

  if (stream->flags & ES_FLAG_WRITING)
    {
      /* Switching to reading mode -> flush output.  */
      err = es_flush (stream);
      if (err)
	goto out;
      stream->flags &= ~ES_FLAG_WRITING;
    }  

  /* Read unread data first.  */
  while ((bytes_to_read - data_read_unread) && stream->unread_data_len)
    {
      buffer[data_read_unread]
	= stream->unread_buffer[stream->unread_data_len - 1];
      stream->unread_data_len--;
      data_read_unread++;
    }

  switch (stream->intern->strategy)
    {
    case _IONBF:
      err = es_read_nbf (stream,
			 buffer + data_read_unread,
			 bytes_to_read - data_read_unread, &data_read);
      break;
    case _IOLBF:
      err = es_read_lbf (stream,
			 buffer + data_read_unread,
			 bytes_to_read - data_read_unread, &data_read);
      break;
    case _IOFBF:
      err = es_read_fbf (stream,
			 buffer + data_read_unread,
			 bytes_to_read - data_read_unread, &data_read);
      break;
    }

 out:

  if (bytes_read)
    *bytes_read = data_read_unread + data_read;

  return err;
}

/* Try to unread DATA_N bytes from DATA into STREAM, storing the
   amount of bytes succesfully unread in *BYTES_UNREAD.  */
static void
es_unreadn (estream_t ES__RESTRICT stream,
	    const unsigned char *ES__RESTRICT data, size_t data_n,
	    size_t *ES__RESTRICT bytes_unread)
{
  size_t space_left;

  space_left = stream->unread_buffer_size - stream->unread_data_len;

  if (data_n > space_left)
    data_n = space_left;

  if (! data_n)
    goto out;

  memcpy (stream->unread_buffer + stream->unread_data_len, data, data_n);
  stream->unread_data_len += data_n;
  stream->intern->indicators.eof = 0;

 out:

  if (bytes_unread)
    *bytes_unread = data_n;
}

/* Seek in STREAM.  */
static int
es_seek (estream_t ES__RESTRICT stream, off_t offset, int whence,
	 off_t *ES__RESTRICT offset_new)
{
  es_cookie_seek_function_t func_seek = stream->intern->func_seek;
  int err, ret;
  off_t off;

  if (! func_seek)
    {
      errno = EOPNOTSUPP;
      err = -1;
      goto out;
    }

  if (stream->flags & ES_FLAG_WRITING)
    {
      /* Flush data first in order to prevent flushing it to the wrong
	 offset.  */
      err = es_flush (stream);
      if (err)
	goto out;
      stream->flags &= ~ES_FLAG_WRITING;
    }

  off = offset;
  if (whence == SEEK_CUR)
    {
      off = off - stream->data_len + stream->data_offset;
      off -= stream->unread_data_len;
    }
  
  ret = (*func_seek) (stream->intern->cookie, &off, whence);
  if (ret == -1)
    {
      err = -1;
      goto out;
    }

  err = 0;
  es_empty (stream);

  if (offset_new)
    *offset_new = off;

  stream->intern->indicators.eof = 0;
  stream->intern->offset = off;

 out:
  
  if (err)
    stream->intern->indicators.err = 1;

  return err;
}

/* Write BYTES_TO_WRITE bytes from BUFFER into STREAM in
   unbuffered-mode, storing the amount of bytes written in
   *BYTES_WRITTEN.  */
static int
es_write_nbf (estream_t ES__RESTRICT stream,
	      const unsigned char *ES__RESTRICT buffer,
	      size_t bytes_to_write, size_t *ES__RESTRICT bytes_written)
{
  es_cookie_write_function_t func_write = stream->intern->func_write;
  size_t data_written;
  ssize_t ret;
  int err;

  if (bytes_to_write && (! func_write))
    {
      err = EOPNOTSUPP;
      goto out;
    }  

  data_written = 0;
  err = 0;
  
  while (bytes_to_write - data_written)
    {
      ret = (*func_write) (stream->intern->cookie,
			   buffer + data_written,
			   bytes_to_write - data_written);
      if (ret == -1)
	{
	  err = -1;
	  break;
	}
      else
	data_written += ret;
    }

  stream->intern->offset += data_written;
  *bytes_written = data_written;

 out:

  return err;
}

/* Write BYTES_TO_WRITE bytes from BUFFER into STREAM in
   fully-buffered-mode, storing the amount of bytes written in
   *BYTES_WRITTEN.  */
static int
es_write_fbf (estream_t ES__RESTRICT stream,
	      const unsigned char *ES__RESTRICT buffer,
	      size_t bytes_to_write, size_t *ES__RESTRICT bytes_written)
{
  size_t space_available;
  size_t data_to_write;
  size_t data_written;
  int err;

  data_written = 0;
  err = 0;

  while ((bytes_to_write - data_written) && (! err))
    {
      if (stream->data_offset == stream->buffer_size)
	/* Container full, flush buffer.  */
	err = es_flush (stream);

      if (! err)
	{
	  /* Flushing resulted in empty container.  */
	  
	  data_to_write = bytes_to_write - data_written;
	  space_available = stream->buffer_size - stream->data_offset;
	  if (data_to_write > space_available)
	    data_to_write = space_available;
	      
	  memcpy (stream->buffer + stream->data_offset,
		  buffer + data_written, data_to_write);
	  stream->data_offset += data_to_write;
	  data_written += data_to_write;
	}
    }

  *bytes_written = data_written;

  return err;
}


/* Write BYTES_TO_WRITE bytes from BUFFER into STREAM in
   line-buffered-mode, storing the amount of bytes written in
   *BYTES_WRITTEN.  */
static int
es_write_lbf (estream_t ES__RESTRICT stream,
	      const unsigned char *ES__RESTRICT buffer,
	      size_t bytes_to_write, size_t *ES__RESTRICT bytes_written)
{
  size_t data_flushed = 0;
  size_t data_buffered = 0;
  unsigned char *nlp;
  int err = 0;

  nlp = memrchr (buffer, '\n', bytes_to_write);
  if (nlp)
    {
      /* Found a newline, directly write up to (including) this
	 character.  */
      err = es_flush (stream);
      if (!err)
	err = es_write_nbf (stream, buffer, nlp - buffer + 1, &data_flushed);
    }

  if (!err)
    {
      /* Write remaining data fully buffered.  */
      err = es_write_fbf (stream, buffer + data_flushed,
			  bytes_to_write - data_flushed, &data_buffered);
    }

  *bytes_written = data_flushed + data_buffered;
  return err;
}


/* Write BYTES_TO_WRITE bytes from BUFFER into STREAM in, storing the
   amount of bytes written in BYTES_WRITTEN.  */
static int
es_writen (estream_t ES__RESTRICT stream,
	   const void *ES__RESTRICT buffer,
	   size_t bytes_to_write, size_t *ES__RESTRICT bytes_written)
{
  size_t data_written;
  int err;

  data_written = 0;
  err = 0;
  
  if (! (stream->flags & ES_FLAG_WRITING))
    {
      /* Switching to writing mode -> discard input data and seek to
	 position at which reading has stopped.  We can do this only
	 if a seek function has been registered. */
      if (stream->intern->func_seek)
        {
          err = es_seek (stream, 0, SEEK_CUR, NULL);
          if (err)
            {
              if (errno == ESPIPE)
                err = 0;
              else
                goto out;
            }
        }
    }

  switch (stream->intern->strategy)
    {
    case _IONBF:
      err = es_write_nbf (stream, buffer, bytes_to_write, &data_written);
      break;

    case _IOLBF:
      err = es_write_lbf (stream, buffer, bytes_to_write, &data_written);
      break;

    case _IOFBF:
      err = es_write_fbf (stream, buffer, bytes_to_write, &data_written);
      break;
    }

 out:
    
  if (bytes_written)
    *bytes_written = data_written;
  if (data_written)
    if (! (stream->flags & ES_FLAG_WRITING))
      stream->flags |= ES_FLAG_WRITING;

  return err;
}


static int
es_peek (estream_t ES__RESTRICT stream, unsigned char **ES__RESTRICT data,
	 size_t *ES__RESTRICT data_len)
{
  int err;

  if (stream->flags & ES_FLAG_WRITING)
    {
      /* Switching to reading mode -> flush output.  */
      err = es_flush (stream);
      if (err)
	goto out;
      stream->flags &= ~ES_FLAG_WRITING;
    }  

  if (stream->data_offset == stream->data_len)
    {
      /* Refill container.  */
      err = es_fill (stream);
      if (err)
	goto out;
    }
  
  if (data)
    *data = stream->buffer + stream->data_offset;
  if (data_len)
    *data_len = stream->data_len - stream->data_offset;
  err = 0;

 out:

  return err;
}


/* Skip SIZE bytes of input data contained in buffer.  */
static int
es_skip (estream_t stream, size_t size)
{
  int err;

  if (stream->data_offset + size > stream->data_len)
    {
      errno = EINVAL;
      err = -1;
    }
  else
    {
      stream->data_offset += size;
      err = 0;
    }

  return err;
}


static int
doreadline (estream_t ES__RESTRICT stream, size_t max_length,
             char *ES__RESTRICT *ES__RESTRICT line,
             size_t *ES__RESTRICT line_length)
{
  size_t space_left;
  size_t line_size;
  estream_t line_stream;
  char *line_new;
  void *line_stream_cookie;
  char *newline;
  unsigned char *data;
  size_t data_len;
  int err;

  line_new = NULL;
  line_stream = NULL;
  line_stream_cookie = NULL;

  err = es_func_mem_create (&line_stream_cookie, NULL, 0, 0, BUFFER_BLOCK_SIZE,
			    1, 0, 0, NULL, 0, MEM_REALLOC, MEM_FREE, O_RDWR);
  if (err)
    goto out;

  err = es_create (&line_stream, line_stream_cookie, -1,
		   estream_functions_mem);
  if (err)
    goto out;

  space_left = max_length;
  line_size = 0;
  while (1)
    {
      if (max_length && (space_left == 1))
	break;

      err = es_peek (stream, &data, &data_len);
      if (err || (! data_len))
	break;

      if (data_len > (space_left - 1))
	data_len = space_left - 1;

      newline = memchr (data, '\n', data_len);
      if (newline)
	{
	  data_len = (newline - (char *) data) + 1;
	  err = es_write (line_stream, data, data_len, NULL);
	  if (! err)
	    {
	      space_left -= data_len;
	      line_size += data_len;
	      es_skip (stream, data_len);
	      break;
	    }
	}
      else
	{
	  err = es_write (line_stream, data, data_len, NULL);
	  if (! err)
	    {
	      space_left -= data_len;
	      line_size += data_len;
	      es_skip (stream, data_len);
	    }
	}
      if (err)
	break;
    }
  if (err)
    goto out;

  /* Complete line has been written to line_stream.  */
  
  if ((max_length > 1) && (! line_size))
    {
      stream->intern->indicators.eof = 1;
      goto out;
    }

  err = es_seek (line_stream, 0, SEEK_SET, NULL);
  if (err)
    goto out;

  if (! *line)
    {
      line_new = MEM_ALLOC (line_size + 1);
      if (! line_new)
	{
	  err = -1;
	  goto out;
	}
    }
  else
    line_new = *line;

  err = es_read (line_stream, line_new, line_size, NULL);
  if (err)
    goto out;

  line_new[line_size] = '\0';

  if (! *line)
    *line = line_new;
  if (line_length)
    *line_length = line_size;

 out:

  if (line_stream)
    es_destroy (line_stream);
  else if (line_stream_cookie)
    es_func_mem_destroy (line_stream_cookie);

  if (err)
    {
      if (! *line)
	MEM_FREE (line_new);
      stream->intern->indicators.err = 1;
    }

  return err;
}


/* Output fucntion used for estream_format.  */
static int
print_writer (void *outfncarg, const char *buf, size_t buflen)
{
  estream_t stream = outfncarg;
  size_t nwritten;
  int rc;

  nwritten = 0;
  rc = es_writen (stream, buf, buflen, &nwritten);
  stream->intern->print_ntotal += nwritten;
  return rc;
}


/* The core of our printf function.  This is called in locked state. */
static int
es_print (estream_t ES__RESTRICT stream,
	  const char *ES__RESTRICT format, va_list ap)
{
  int rc;

  stream->intern->print_ntotal = 0;
  rc = estream_format (print_writer, stream, format, ap);
  if (rc)
    return -1;
  return (int)stream->intern->print_ntotal;
}


static void
es_set_indicators (estream_t stream, int ind_err, int ind_eof)
{
  if (ind_err != -1)
    stream->intern->indicators.err = ind_err ? 1 : 0;
  if (ind_eof != -1)
    stream->intern->indicators.eof = ind_eof ? 1 : 0;
}


static int
es_get_indicator (estream_t stream, int ind_err, int ind_eof)
{
  int ret = 0;
  
  if (ind_err)
    ret = stream->intern->indicators.err;
  else if (ind_eof)
    ret = stream->intern->indicators.eof;

  return ret;
}


static int
es_set_buffering (estream_t ES__RESTRICT stream,
		  char *ES__RESTRICT buffer, int mode, size_t size)
{
  int err;

  /* Flush or empty buffer depending on mode.  */
  if (stream->flags & ES_FLAG_WRITING)
    {
      err = es_flush (stream);
      if (err)
	goto out;
    }
  else
    es_empty (stream);

  es_set_indicators (stream, -1, 0);
  
  /* Free old buffer in case that was allocated by this function.  */
  if (stream->intern->deallocate_buffer)
    {
      stream->intern->deallocate_buffer = 0;
      MEM_FREE (stream->buffer);
      stream->buffer = NULL;
    }

  if (mode == _IONBF)
    stream->buffer_size = 0;
  else
    {
      void *buffer_new;
      
      if (buffer)
	buffer_new = buffer;
      else
	{
	  buffer_new = MEM_ALLOC (size);
	  if (! buffer_new)
	    {
	      err = -1;
	      goto out;
	    }
	}

      stream->buffer = buffer_new;
      stream->buffer_size = size;
      if (! buffer)
	stream->intern->deallocate_buffer = 1;
    }
  stream->intern->strategy = mode;
  err = 0;

 out:

  return err;
}


static off_t
es_offset_calculate (estream_t stream)
{
  off_t offset;

  offset = stream->intern->offset + stream->data_offset;
  if (offset < stream->unread_data_len)
    /* Offset undefined.  */
    offset = 0;
  else
    offset -= stream->unread_data_len;

  return offset;
}


static void
es_opaque_ctrl (estream_t ES__RESTRICT stream, void *ES__RESTRICT opaque_new,
		void **ES__RESTRICT opaque_old)
{
  if (opaque_old)
    *opaque_old = stream->intern->opaque;
  if (opaque_new)
    stream->intern->opaque = opaque_new;
}


static int
es_get_fd (estream_t stream)
{
  return stream->intern->fd;
}



/* API.  */

int
es_init (void)
{
  int err;

  err = es_init_do ();

  return err;
}

estream_t
es_fopen (const char *ES__RESTRICT path, const char *ES__RESTRICT mode)
{
  unsigned int flags;
  int create_called;
  estream_t stream;
  void *cookie;
  int err;
  int fd;

  stream = NULL;
  cookie = NULL;
  create_called = 0;

  err = es_convert_mode (mode, &flags);
  if (err)
    goto out;
  
  err = es_func_file_create (&cookie, &fd, path, flags);
  if (err)
    goto out;

  create_called = 1;
  err = es_create (&stream, cookie, fd, estream_functions_file);
  if (err)
    goto out;

 out:
  
  if (err && create_called)
    (*estream_functions_file.func_close) (cookie);

  return stream;
}


estream_t
es_mopen (unsigned char *ES__RESTRICT data, size_t data_n, size_t data_len,
	  unsigned int grow,
	  func_realloc_t func_realloc, func_free_t func_free,
	  const char *ES__RESTRICT mode)
{
  unsigned int flags;
  int create_called;
  estream_t stream;
  void *cookie;
  int err;

  cookie = 0;
  stream = NULL;
  create_called = 0;
  
  err = es_convert_mode (mode, &flags);
  if (err)
    goto out;

  err = es_func_mem_create (&cookie, data, data_n, data_len,
			    BUFFER_BLOCK_SIZE, grow, 0, 0,
			    NULL, 0, func_realloc, func_free, flags);
  if (err)
    goto out;
  
  create_called = 1;
  err = es_create (&stream, cookie, -1, estream_functions_mem);

 out:

  if (err && create_called)
    (*estream_functions_mem.func_close) (cookie);

  return stream;
}


estream_t
es_open_memstream (char **ptr, size_t *size)
{
  unsigned int flags;
  int create_called;
  estream_t stream;
  void *cookie;
  int err;

  flags = O_RDWR;
  create_called = 0;
  stream = NULL;
  cookie = 0;
  
  err = es_func_mem_create (&cookie, NULL, 0, 0,
			    BUFFER_BLOCK_SIZE, 1, 1, 1,
			    ptr, size, MEM_REALLOC, MEM_FREE, flags);
  if (err)
    goto out;
  
  create_called = 1;
  err = es_create (&stream, cookie, -1, estream_functions_mem);

 out:

  if (err && create_called)
    (*estream_functions_mem.func_close) (cookie);

  return stream;
}


estream_t
es_fopencookie (void *ES__RESTRICT cookie,
		const char *ES__RESTRICT mode,
		es_cookie_io_functions_t functions)
{
  unsigned int flags;
  estream_t stream;
  int err;

  stream = NULL;
  flags = 0;
  
  err = es_convert_mode (mode, &flags);
  if (err)
    goto out;

  err = es_create (&stream, cookie, -1, functions);
  if (err)
    goto out;

 out:

  return stream;
}


estream_t
es_fdopen (int filedes, const char *mode)
{
  unsigned int flags;
  int create_called;
  estream_t stream;
  void *cookie;
  int err;

  stream = NULL;
  cookie = NULL;
  create_called = 0;

  err = es_convert_mode (mode, &flags);
  if (err)
    goto out;

  err = es_func_fd_create (&cookie, filedes, flags);
  if (err)
    goto out;

  create_called = 1;
  err = es_create (&stream, cookie, filedes, estream_functions_fd);

 out:

  if (err && create_called)
    (*estream_functions_fd.func_close) (cookie);

  return stream;
}
  

estream_t
es_freopen (const char *ES__RESTRICT path, const char *ES__RESTRICT mode,
	    estream_t ES__RESTRICT stream)
{
  int err;

  if (path)
    {
      unsigned int flags;
      int create_called;
      void *cookie;
      int fd;

      cookie = NULL;
      create_called = 0;
      
      ESTREAM_LOCK (stream);

      es_deinitialize (stream);

      err = es_convert_mode (mode, &flags);
      if (err)
	goto leave;
      
      err = es_func_file_create (&cookie, &fd, path, flags);
      if (err)
	goto leave;

      create_called = 1;
      es_initialize (stream, cookie, fd, estream_functions_file);

    leave:

      if (err)
	{
	  if (create_called)
	    es_func_fd_destroy (cookie);
      
	  es_destroy (stream);
	  stream = NULL;
	}
      else
	ESTREAM_UNLOCK (stream);
    }
  else
    {
      /* FIXME?  We don't support re-opening at the moment.  */
      errno = EINVAL;
      es_deinitialize (stream);
      es_destroy (stream);
      stream = NULL;
    }

  return stream;
}


int
es_fclose (estream_t stream)
{
  int err;

  err = es_destroy (stream);

  return err;
}

int
es_fileno_unlocked (estream_t stream)
{
  return es_get_fd (stream);
}


void
es_flockfile (estream_t stream)
{
  ESTREAM_LOCK (stream);
}


int
es_ftrylockfile (estream_t stream)
{
  return ESTREAM_TRYLOCK (stream);
}


void
es_funlockfile (estream_t stream)
{
  ESTREAM_UNLOCK (stream);
}


int
es_fileno (estream_t stream)
{
  int ret;

  ESTREAM_LOCK (stream);
  ret = es_fileno_unlocked (stream);
  ESTREAM_UNLOCK (stream);

  return ret;
}


int
es_feof_unlocked (estream_t stream)
{
  return es_get_indicator (stream, 0, 1);
}


int
es_feof (estream_t stream)
{
  int ret;

  ESTREAM_LOCK (stream);
  ret = es_feof_unlocked (stream);
  ESTREAM_UNLOCK (stream);

  return ret;
}


int
es_ferror_unlocked (estream_t stream)
{
  return es_get_indicator (stream, 1, 0);
}


int
es_ferror (estream_t stream)
{
  int ret;

  ESTREAM_LOCK (stream);
  ret = es_ferror_unlocked (stream);
  ESTREAM_UNLOCK (stream);

  return ret;
}


void
es_clearerr_unlocked (estream_t stream)
{
  es_set_indicators (stream, 0, 0);
}


void
es_clearerr (estream_t stream)
{
  ESTREAM_LOCK (stream);
  es_clearerr_unlocked (stream);
  ESTREAM_UNLOCK (stream);
}


int
es_fflush (estream_t stream)
{
  int err;
  
  if (stream)
    {
      ESTREAM_LOCK (stream);
      if (stream->flags & ES_FLAG_WRITING)
	err = es_flush (stream);
      else
	{
	  es_empty (stream);
	  err = 0;
	}
      ESTREAM_UNLOCK (stream);
    }
  else
    err = es_list_iterate (es_fflush);

  return err ? EOF : 0;
}


int
es_fseek (estream_t stream, long int offset, int whence)
{
  int err;

  ESTREAM_LOCK (stream);
  err = es_seek (stream, offset, whence, NULL);
  ESTREAM_UNLOCK (stream);

  return err;
}


int
es_fseeko (estream_t stream, off_t offset, int whence)
{
  int err;
  
  ESTREAM_LOCK (stream);
  err = es_seek (stream, offset, whence, NULL);
  ESTREAM_UNLOCK (stream);

  return err;
}


long int
es_ftell (estream_t stream)
{
  long int ret;
  
  ESTREAM_LOCK (stream);
  ret = es_offset_calculate (stream);
  ESTREAM_UNLOCK (stream);

  return ret;
}


off_t
es_ftello (estream_t stream)
{
  off_t ret = -1;

  ESTREAM_LOCK (stream);
  ret = es_offset_calculate (stream);
  ESTREAM_UNLOCK (stream);

  return ret;
}


void
es_rewind (estream_t stream)
{
  ESTREAM_LOCK (stream);
  es_seek (stream, 0L, SEEK_SET, NULL);
  es_set_indicators (stream, 0, -1);
  ESTREAM_UNLOCK (stream);
}


int
_es_getc_underflow (estream_t stream)
{
  int err;
  unsigned char c;
  size_t bytes_read;

  err = es_readn (stream, &c, 1, &bytes_read);

  return (err || (! bytes_read)) ? EOF : c;
}


int
_es_putc_overflow (int c, estream_t stream)
{
  unsigned char d = c;
  int err;

  err = es_writen (stream, &d, 1, NULL);

  return err ? EOF : c;
}


int
es_fgetc (estream_t stream)
{
  int ret;
  
  ESTREAM_LOCK (stream);
  ret = es_getc_unlocked (stream);
  ESTREAM_UNLOCK (stream);

  return ret;
}


int
es_fputc (int c, estream_t stream)
{
  int ret;
  
  ESTREAM_LOCK (stream);
  ret = es_putc_unlocked (c, stream);
  ESTREAM_UNLOCK (stream);

  return ret;
}


int
es_ungetc (int c, estream_t stream)
{
  unsigned char data = (unsigned char) c;
  size_t data_unread;

  ESTREAM_LOCK (stream);
  es_unreadn (stream, &data, 1, &data_unread);
  ESTREAM_UNLOCK (stream);

  return data_unread ? c : EOF;
}


int
es_read (estream_t ES__RESTRICT stream,
	 void *ES__RESTRICT buffer, size_t bytes_to_read,
	 size_t *ES__RESTRICT bytes_read)
{
  int err;

  if (bytes_to_read)
    {
      ESTREAM_LOCK (stream);
      err = es_readn (stream, buffer, bytes_to_read, bytes_read);
      ESTREAM_UNLOCK (stream);
    }
  else
    err = 0;

  return err;
}


int
es_write (estream_t ES__RESTRICT stream,
	  const void *ES__RESTRICT buffer, size_t bytes_to_write,
	  size_t *ES__RESTRICT bytes_written)
{
  int err;

  if (bytes_to_write)
    {
      ESTREAM_LOCK (stream);
      err = es_writen (stream, buffer, bytes_to_write, bytes_written);
      ESTREAM_UNLOCK (stream);
    }
  else
    err = 0;

  return err;
}


size_t
es_fread (void *ES__RESTRICT ptr, size_t size, size_t nitems,
	  estream_t ES__RESTRICT stream)
{
  size_t ret, bytes;
  int err;

  if (size * nitems)
    {
      ESTREAM_LOCK (stream);
      err = es_readn (stream, ptr, size * nitems, &bytes);
      ESTREAM_UNLOCK (stream);

      ret = bytes / size;
    }
  else
    ret = 0;

  return ret;
}


size_t
es_fwrite (const void *ES__RESTRICT ptr, size_t size, size_t nitems,
	   estream_t ES__RESTRICT stream)
{
  size_t ret, bytes;
  int err;

  if (size * nitems)
    {
      ESTREAM_LOCK (stream);
      err = es_writen (stream, ptr, size * nitems, &bytes);
      ESTREAM_UNLOCK (stream);

      ret = bytes / size;
    }
  else
    ret = 0;

  return ret;
}


char *
es_fgets (char *ES__RESTRICT s, int n, estream_t ES__RESTRICT stream)
{
  char *ret = NULL;
  
  if (n)
    {
      int err;
      
      ESTREAM_LOCK (stream);
      err = doreadline (stream, n, &s, NULL);
      ESTREAM_UNLOCK (stream);
      if (! err)
	ret = s;
    }
  
  return ret;
}


int
es_fputs (const char *ES__RESTRICT s, estream_t ES__RESTRICT stream)
{
  size_t length;
  int err;

  length = strlen (s);
  ESTREAM_LOCK (stream);
  err = es_writen (stream, s, length, NULL);
  ESTREAM_UNLOCK (stream);

  return err ? EOF : 0;
}


ssize_t
es_getline (char *ES__RESTRICT *ES__RESTRICT lineptr, size_t *ES__RESTRICT n,
	    estream_t ES__RESTRICT stream)
{
  char *line = NULL;
  size_t line_n = 0;
  int err;

  ESTREAM_LOCK (stream);
  err = doreadline (stream, 0, &line, &line_n);
  ESTREAM_UNLOCK (stream);
  if (err)
    goto out;

  if (*n)
    {
      /* Caller wants us to use his buffer.  */
      
      if (*n < (line_n + 1))
	{
	  /* Provided buffer is too small -> resize.  */

	  void *p;

	  p = MEM_REALLOC (*lineptr, line_n + 1);
	  if (! p)
	    err = -1;
	  else
	    {
	      if (*lineptr != p)
		*lineptr = p;
	    }
	}

      if (! err)
	{
	  memcpy (*lineptr, line, line_n + 1);
	  if (*n != line_n)
	    *n = line_n;
	}
      MEM_FREE (line);
    }
  else
    {
      /* Caller wants new buffers.  */
      *lineptr = line;
      *n = line_n;
    }

 out:

  return err ? err : line_n;
}



/* Same as fgets() but if the provided buffer is too short a larger
   one will be allocated.  This is similar to getline. A line is
   considered a byte stream ending in a LF.

   If MAX_LENGTH is not NULL, it shall point to a value with the
   maximum allowed allocation.  

   Returns the length of the line. EOF is indicated by a line of
   length zero. A truncated line is indicated my setting the value at
   MAX_LENGTH to 0.  If the returned value is less then 0 not enough
   memory was enable or another error occurred; ERRNO is then set
   accordingly.

   If a line has been truncated, the file pointer is moved forward to
   the end of the line so that the next read starts with the next
   line.  Note that MAX_LENGTH must be re-initialzied in this case.

   The caller initially needs to provide the address of a variable,
   initialized to NULL, at ADDR_OF_BUFFER and don't change this value
   anymore with the following invocations.  LENGTH_OF_BUFFER should be
   the address of a variable, initialized to 0, which is also
   maintained by this function.  Thus, both paramaters should be
   considered the state of this function.

   Note: The returned buffer is allocated with enough extra space to
   allow the caller to append a CR,LF,Nul.  The buffer should be
   released using es_free.
 */
ssize_t
es_read_line (estream_t stream, 
              char **addr_of_buffer, size_t *length_of_buffer,
              size_t *max_length)
{
  int c;
  char  *buffer = *addr_of_buffer;
  size_t length = *length_of_buffer;
  size_t nbytes = 0;
  size_t maxlen = max_length? *max_length : 0;
  char *p;

  if (!buffer)
    { 
      /* No buffer given - allocate a new one. */
      length = 256;
      buffer = MEM_ALLOC (length);
      *addr_of_buffer = buffer;
      if (!buffer)
        {
          *length_of_buffer = 0;
          if (max_length)
            *max_length = 0;
          return -1;
        }
      *length_of_buffer = length;
    }

  if (length < 4)
    {
      /* This should never happen. If it does, the fucntion has been
         called with wrong arguments. */
      errno = EINVAL;
      return -1;
    }
  length -= 3; /* Reserve 3 bytes for CR,LF,EOL. */

  ESTREAM_LOCK (stream);
  p = buffer;
  while  ((c = es_getc_unlocked (stream)) != EOF)
    {
      if (nbytes == length)
        { 
          /* Enlarge the buffer. */
          if (maxlen && length > maxlen) 
            {
              /* We are beyond our limit: Skip the rest of the line. */
              while (c != '\n' && (c=es_getc_unlocked (stream)) != EOF)
                ;
              *p++ = '\n'; /* Always append a LF (we reserved some space). */
              nbytes++;
              if (max_length)
                *max_length = 0; /* Indicate truncation. */
              break; /* the while loop. */
            }
          length += 3; /* Adjust for the reserved bytes. */
          length += length < 1024? 256 : 1024;
          *addr_of_buffer = MEM_REALLOC (buffer, length);
          if (!*addr_of_buffer)
            {
              int save_errno = errno;
              MEM_FREE (buffer); 
              *length_of_buffer = *max_length = 0;
              ESTREAM_UNLOCK (stream);
              errno = save_errno;
              return -1;
            }
          buffer = *addr_of_buffer;
          *length_of_buffer = length;
          length -= 3; 
          p = buffer + nbytes;
	}
      *p++ = c;
      nbytes++;
      if (c == '\n')
        break;
    }
  *p = 0; /* Make sure the line is a string. */
  ESTREAM_UNLOCK (stream);

  return nbytes;
}

/* Wrapper around free() to match the memory allocation system used
   by estream.  Should be used for all buffers returned to the caller
   by libestream. */
void
es_free (void *a)
{
  if (a)
    MEM_FREE (a);
}


int
es_vfprintf (estream_t ES__RESTRICT stream, const char *ES__RESTRICT format,
	     va_list ap)
{
  int ret;
  
  ESTREAM_LOCK (stream);
  ret = es_print (stream, format, ap);
  ESTREAM_UNLOCK (stream);

  return ret;
}


static int
es_fprintf_unlocked (estream_t ES__RESTRICT stream,
           const char *ES__RESTRICT format, ...)
{
  int ret;
  
  va_list ap;
  va_start (ap, format);
  ret = es_print (stream, format, ap);
  va_end (ap);

  return ret;
}


int
es_fprintf (estream_t ES__RESTRICT stream,
	    const char *ES__RESTRICT format, ...)
{
  int ret;
  
  va_list ap;
  va_start (ap, format);
  ESTREAM_LOCK (stream);
  ret = es_print (stream, format, ap);
  ESTREAM_UNLOCK (stream);
  va_end (ap);

  return ret;
}

static int
tmpfd (void)
{
  FILE *fp;
  int fp_fd;
  int fd;

  fp = NULL;
  fd = -1;
  
  fp = tmpfile ();
  if (! fp)
    goto out;

  fp_fd = fileno (fp);
  fd = dup (fp_fd);

 out:

  if (fp)
    fclose (fp);

  return fd;
}

estream_t
es_tmpfile (void)
{
  unsigned int flags;
  int create_called;
  estream_t stream;
  void *cookie;
  int err;
  int fd;

  create_called = 0;
  stream = NULL;
  flags = O_RDWR | O_TRUNC | O_CREAT;
  cookie = NULL;
  
  fd = tmpfd ();
  if (fd == -1)
    {
      err = -1;
      goto out;
    }

  err = es_func_fd_create (&cookie, fd, flags);
  if (err)
    goto out;

  create_called = 1;
  err = es_create (&stream, cookie, fd, estream_functions_fd);

 out:

  if (err)
    {
      if (create_called)
	es_func_fd_destroy (cookie);
      else if (fd != -1)
	close (fd);
      stream = NULL;
    }
  
  return stream;
}


int
es_setvbuf (estream_t ES__RESTRICT stream,
	    char *ES__RESTRICT buf, int type, size_t size)
{
  int err;
  
  if (((type == _IOFBF) || (type == _IOLBF) || (type == _IONBF))
      && (! ((! size) && (type != _IONBF))))
    {
      ESTREAM_LOCK (stream);
      err = es_set_buffering (stream, buf, type, size);
      ESTREAM_UNLOCK (stream);
    }
  else
    {
      errno = EINVAL;
      err = -1;
    }

  return err;
}


void
es_setbuf (estream_t ES__RESTRICT stream, char *ES__RESTRICT buf)
{
  ESTREAM_LOCK (stream);
  es_set_buffering (stream, buf, buf ? _IOFBF : _IONBF, BUFSIZ);
  ESTREAM_UNLOCK (stream);
}

void
es_opaque_set (estream_t stream, void *opaque)
{
  ESTREAM_LOCK (stream);
  es_opaque_ctrl (stream, opaque, NULL);
  ESTREAM_UNLOCK (stream);
}


void *
es_opaque_get (estream_t stream)
{
  void *opaque;
  
  ESTREAM_LOCK (stream);
  es_opaque_ctrl (stream, NULL, &opaque);
  ESTREAM_UNLOCK (stream);

  return opaque;
}

/* Print a BUFFER to STREAM while replacing all control characters and
   the characters in DELIMITERS by standard C escape sequences.
   Returns 0 on success or -1 on error.  If BYTES_WRITTEN is not NULL
   the number of bytes actually written are stored at this
   address.  */
int 
es_write_sanitized (estream_t ES__RESTRICT stream,
                    const void * ES__RESTRICT buffer, size_t length,
                    const char * delimiters, 
                    size_t * ES__RESTRICT bytes_written)
{
  const unsigned char *p = buffer;
  size_t count = 0;
  int ret;

  ESTREAM_LOCK (stream);
  for (; length; length--, p++, count++)
    {
      if (*p < 0x20 
          || (*p >= 0x7f && *p < 0xa0)
          || (delimiters 
              && (strchr (delimiters, *p) || *p == '\\')))
        {
          es_putc_unlocked ('\\', stream);
          count++;
          if (*p == '\n')
            {
              es_putc_unlocked ('n', stream);
              count++;
            }
          else if (*p == '\r')
            {
              es_putc_unlocked ('r', stream);
              count++;
            }
          else if (*p == '\f')
            {
              es_putc_unlocked ('f', stream);
              count++;
            }
          else if (*p == '\v')
            {
              es_putc_unlocked ('v', stream);
              count++;
            }
          else if (*p == '\b')
            {
              es_putc_unlocked ('b', stream);
              count++;
            }
          else if (!*p)
            {
              es_putc_unlocked('0', stream);
              count++;
            }
          else
            {
              es_fprintf_unlocked (stream, "x%02x", *p);
              count += 3;
            }
	}
      else
        {
          es_putc_unlocked (*p, stream);
          count++;
        }
    }

  if (bytes_written)
    *bytes_written = count;
  ret =  es_ferror_unlocked (stream)? -1 : 0;
  ESTREAM_UNLOCK (stream);

  return ret;
}


/* Write LENGTH bytes of BUFFER to STREAM as a hex encoded string.
   RESERVED must be 0.  Returns 0 on success or -1 on error.  If
   BYTES_WRITTEN is not NULL the number of bytes actually written are
   stored at this address.  */
int
es_write_hexstring (estream_t ES__RESTRICT stream,
                    const void *ES__RESTRICT buffer, size_t length,
                    int reserved, size_t *ES__RESTRICT bytes_written )
{
  int ret;
  const unsigned char *s;
  size_t count = 0;

#define tohex(n) ((n) < 10 ? ((n) + '0') : (((n) - 10) + 'A'))

  if (!length)
    return 0;

  ESTREAM_LOCK (stream);

  for (s = buffer; length; s++, length--)
    {
      es_putc_unlocked ( tohex ((*s>>4)&15), stream);
      es_putc_unlocked ( tohex (*s&15), stream);
      count += 2;
    }

  if (bytes_written)
    *bytes_written = count;
  ret = es_ferror_unlocked (stream)? -1 : 0;

  ESTREAM_UNLOCK (stream);

  return ret;

#undef tohex
}



#ifdef GNUPG_MAJOR_VERSION
/* Special estream function to print an UTF8 string in the native
   encoding.  The interface is the same as es_write_sanitized, however
   only one delimiter may be supported. 

   THIS IS NOT A STANDARD ESTREAM FUNCTION AND ONLY USED BY GNUPG!. */
int
es_write_sanitized_utf8_buffer (estream_t stream,
                                const void *buffer, size_t length, 
                                const char *delimiters, size_t *bytes_written)
{
  const char *p = buffer;
  size_t i;

  /* We can handle plain ascii simpler, so check for it first. */
  for (i=0; i < length; i++ ) 
    {
      if ( (p[i] & 0x80) )
        break;
    }
  if (i < length)
    {
      int delim = delimiters? *delimiters : 0;
      char *buf;
      int ret;

      /*(utf8 conversion already does the control character quoting). */
      buf = utf8_to_native (p, length, delim);
      if (bytes_written)
        *bytes_written = strlen (buf);
      ret = es_fputs (buf, stream);
      xfree (buf);
      return i;
    }
  else
    return es_write_sanitized (stream, p, length, delimiters, bytes_written);
}
#endif /*GNUPG_MAJOR_VERSION*/
