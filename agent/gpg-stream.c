/* stream.c - Stream I/O/ layer
   Copyright (C) 2004 g10 Code GmbH

   This file is part of libgpg-stream.
 
   libgpg-stream is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
 
   libgpg-stream is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with libgpg-stream; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#include <gpg-error.h>

#include "gpg-stream.h"
#include "gpg-stream-config.h"



/* Buffer management layer.  */

#define BUFFER_BLOCK_SIZE 1024



typedef struct buffer *buffer_t;

/* Callbacks, necessary for filling/flushing/seeking.  */
typedef gpg_error_t (*buffer_func_read_t) (void *handle,
					   char *buffer,
					   size_t bytes_to_read,
					   size_t *bytes_read);
typedef gpg_error_t (*buffer_func_write_t) (void *handle,
					    const char *buffer,
					    size_t bytes_to_write,
					    size_t *bytes_written);
typedef gpg_error_t (*buffer_func_seek_t) (void *handle,
					   off_t offset,
					   int whence);

typedef gpg_error_t (*buffer_func_stat_t) (void *handle,
					   size_t *size);

typedef struct buffer_functions
{
  buffer_func_read_t  func_read;  /* Read callback.   */
  buffer_func_write_t func_write; /* Write callback.  */
  buffer_func_seek_t  func_seek;  /* Seek callback.   */
  buffer_func_stat_t  func_stat;  /* Stat callback.   */
} buffer_functions_t;

/* Buffer context.  */
struct buffer
{
  void *handle;			/* Handle, passed to callbacks.     */
  buffer_functions_t functions;	/* Callback functions.              */
  unsigned int flags;		/* General flags.                   */
  struct buffer_in
  {
    char *container;		/* Container holding data.          */
    size_t container_size;	/* Size of CONTAINER.               */
    size_t data_size;		/* Size of data in CONTAINER.       */
    off_t data_offset;		/* Offset inside of CONTAINER.      */
  } buffer_in;
  struct buffer_out
  {
    char *container;		/* Container holding data.          */
    size_t container_size;	/* Size of CONTAINER.               */
    size_t data_size;		/* Size of data in CONTAINER.       */
    off_t data_offset;		/* Offset inside of CONTAINER.      */
    size_t data_flushed;	/* Amount of data already flushed.  */
  } buffer_out;
};



/* Buffer contains unflushed data.  */
#define BUFFER_FLAG_DIRTY (1 << 0)



/* Fill buffer.  */
static gpg_error_t
buffer_fill_do (buffer_t buffer)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  size_t bytes_read = 0;

  if (! buffer->functions.func_read)
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else
    {
      buffer_func_read_t func_read = buffer->functions.func_read;
      
      err = (*func_read) (buffer->handle,
			  buffer->buffer_in.container,
			  buffer->buffer_in.container_size,
			  &bytes_read);
    }

  buffer->buffer_in.data_offset = 0;
  buffer->buffer_in.data_size = bytes_read;

  return err;
}

/* Empty buffer input.  */
static gpg_error_t
buffer_empty (buffer_t buffer)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  buffer->buffer_in.data_size = 0;
  buffer->buffer_in.data_offset = 0;

  return err;
}

/* Flush data contained in buffer.  */
static gpg_error_t
buffer_flush_do (buffer_t buffer)
{
  buffer_func_write_t func_write = buffer->functions.func_write;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  size_t bytes_written = 0;

  if (! func_write)
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else if (buffer->flags & BUFFER_FLAG_DIRTY)
    while ((buffer->buffer_out.data_size
	    - buffer->buffer_out.data_flushed) && (! err))
      {
	
	err = (*func_write) (buffer->handle,
			     buffer->buffer_out.container
			     + buffer->buffer_out.data_flushed,
			     buffer->buffer_out.data_size
			     - buffer->buffer_out.data_flushed,
			     &bytes_written);
	if (! err)
	  {
	    buffer->buffer_out.data_size = 0;
	    buffer->buffer_out.data_offset = 0;
	    buffer->buffer_out.data_flushed = 0;
	    buffer->flags &= ~BUFFER_FLAG_DIRTY;
	  }
	else
	  buffer->buffer_out.data_flushed += bytes_written;
      }
  
  return err;
}

static gpg_error_t
buffer_stat_do (buffer_t buffer,
		size_t *size)
{
  buffer_func_stat_t func_stat = buffer->functions.func_stat;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = (*func_stat) (buffer->handle, size);

  return err;
}



/* Read from a buffer.  */
gpg_error_t
buffer_read (buffer_t buffer,
	     char *data,
	     size_t bytes_to_read,
	     size_t *bytes_read)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  size_t data_read = 0;
  size_t data_to_copy = 0;

  if (! (buffer->flags & BUFFER_FLAG_DIRTY))
    err = buffer_flush_do (buffer);

  while ((bytes_to_read - data_read) && (! err))
    {
      if (buffer->buffer_in.data_offset == buffer->buffer_in.data_size)
	{
	  /* Nothing more to read in current container, try to
	     fill container with new data.  */
	  err = buffer_fill_do (buffer);
	  if (! err)
	    if (! buffer->buffer_in.data_size)
	      /* Filling did not result in any data read.  */
	      break;
	}

      if (! err)
	{
	  if ((bytes_to_read
	       - data_read) > (buffer->buffer_in.data_size
			       - buffer->buffer_in.data_offset))
	    data_to_copy = (buffer->buffer_in.data_size
			    - buffer->buffer_in.data_offset);
	  else
	    data_to_copy = bytes_to_read - data_read;

	  memcpy (data + data_read,
		  buffer->buffer_in.container + buffer->buffer_in.data_offset,
		  data_to_copy);
	  buffer->buffer_in.data_offset += data_to_copy;
	  data_read += data_to_copy;
	}
    }

  if (bytes_read)
    *bytes_read = data_read;

  return err;
}

/* Write to a buffer.  */
gpg_error_t
buffer_write (buffer_t buffer,
	      const char *data,
	      size_t bytes_to_write,
	      size_t *bytes_written)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  size_t data_written = 0;
  size_t data_to_copy = 0;
      
  while ((bytes_to_write - data_written) && (! err))
    {
      if (buffer->buffer_out.data_offset == buffer->buffer_out.container_size)
	/* Container full, flush buffer.  */
	err = buffer_flush_do (buffer);

      if (! err)
	{
	  if ((bytes_to_write
	       - data_written) > (buffer->buffer_out.container_size
				  - buffer->buffer_out.data_offset))
	    data_to_copy = (buffer->buffer_out.container_size
			    - buffer->buffer_out.data_offset);
	  else
	    data_to_copy = bytes_to_write - data_written;

	  memcpy (buffer->buffer_out.container
		  + buffer->buffer_out.data_offset,
		  data + data_written,
		  data_to_copy);
	  if ((buffer->buffer_out.data_offset
	       + data_to_copy) > buffer->buffer_out.data_size)
	    buffer->buffer_out.data_size = (buffer->buffer_out.data_offset
					    + data_to_copy);
	  buffer->buffer_out.data_offset += data_to_copy;
	  data_written += data_to_copy;

	  if (data_written)
	    if (! (buffer->flags & BUFFER_FLAG_DIRTY))
	      buffer->flags |= BUFFER_FLAG_DIRTY;
	}
    }

  if (bytes_written)
    *bytes_written = data_written;

  return err;
}

/* Seek in a buffer.  */
gpg_error_t
buffer_seek (buffer_t buffer,
	     off_t offset,
	     int whence)
{
  buffer_func_seek_t func_seek = buffer->functions.func_seek;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (! func_seek)
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else
    {
      if (buffer->flags & BUFFER_FLAG_DIRTY)
	/* Flush data first in order to prevent flushing it to the
	   wrong offset.  */
	err = buffer_flush_do (buffer);
      
      if (! err)
	err = (*func_seek) (buffer->handle, offset, whence);

      if (! err)
	err = buffer_empty (buffer);
    }

  return err;
}

/* Return the unread data contained in a buffer.  */
gpg_error_t
buffer_peek (buffer_t buffer,
	     char **data,
	     size_t *data_size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (buffer->buffer_in.data_offset == buffer->buffer_in.data_size)
    /* Refill container.  */
    err = buffer_fill_do (buffer);

  if (! err)
    {
      if (data)
	*data = buffer->buffer_in.container + buffer->buffer_in.data_offset;
      if (data_size)
	*data_size = buffer->buffer_in.data_size - buffer->buffer_in.data_offset;
    }
  
  return err;
}

/* Skip SIZE bytes of input data contained in buffer.  */
gpg_error_t
buffer_skip (buffer_t buffer,
	     size_t size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (buffer->buffer_in.data_offset + size > buffer->buffer_in.data_size)
    err = gpg_error (GPG_ERR_INV_ARG);
  else
    buffer->buffer_in.data_offset += size;

  return err;
}



/* Create a new buffer.  */
gpg_error_t
buffer_create (buffer_t *buffer,
	       void *handle,
	       buffer_functions_t functions)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  /* Allocate memory, initialize.  */
      
  buffer_t buffer_new = NULL;
  char *container_in_new = NULL;
  char *container_out_new = NULL;

  buffer_new = malloc (sizeof (*buffer_new));
  if (! buffer_new)
    err = gpg_error_from_errno (errno);

  if (! err)
    {
      container_in_new = malloc (BUFFER_BLOCK_SIZE);
      if (! container_in_new)
	err = gpg_error_from_errno (errno);
    }
  if (! err)
    {
      container_out_new = malloc (BUFFER_BLOCK_SIZE);
      if (! container_out_new)
	err = gpg_error_from_errno (errno);
    }

  if (! err)
    {
      buffer_new->handle = handle;
      buffer_new->flags = 0;
      buffer_new->functions = functions;
      buffer_new->buffer_in.container = container_in_new;
      buffer_new->buffer_in.container_size = BUFFER_BLOCK_SIZE;
      buffer_new->buffer_in.data_size = 0;
      buffer_new->buffer_in.data_offset = 0;
      buffer_new->buffer_out.container = container_out_new;
      buffer_new->buffer_out.container_size = BUFFER_BLOCK_SIZE;
      buffer_new->buffer_out.data_size = 0;
      buffer_new->buffer_out.data_offset = 0;
      buffer_new->buffer_out.data_flushed = 0;
      *buffer = buffer_new;
    }
  else
    {
      if (container_in_new)
	free (container_in_new);
      if (container_out_new)
	free (container_out_new);
      if (buffer_new)
	free (buffer_new);
    }
  
  return err;
}

/* Destroy a buffer.  */
gpg_error_t
buffer_destroy (buffer_t buffer)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  
  if (buffer)
    {
      err = buffer_flush_do (buffer);
      free (buffer->buffer_in.container);
      free (buffer->buffer_out.container);
      free (buffer);
    }

  return err;
}

/* Write out unwritten data contained in buffer.  */
gpg_error_t
buffer_flush (buffer_t buffer)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = buffer_flush_do (buffer);

  return err;
}

/* Stat buffer.  */
gpg_error_t
buffer_stat (buffer_t buffer,
	     size_t *size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = buffer_stat_do (buffer, size);

  return err;
}



/* Stream layer.  */

/* A Stream Context.  */
struct gpg_stream
{
  void *handle;			    /* Handle.               */
  unsigned int flags;		    /* Flags.                */
  buffer_t buffer;		    /* Buffer used for I/O.  */
  gpg_stream_functions_t functions; /* Callbacks.            */
};



/* Macros.  */

/* Standard permissions used for creating new files.  */
#define GPG_STREAM_FILE_PERMISSIONS 0600

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

/* Implementation of Memory I/O.  */

typedef void *(*mem_func_realloc_t) (void *mem, size_t size);
typedef void (*mem_func_free_t) (void *mem);

typedef struct gpg_stream_handle_mem
{
  char *memory;			/* Data.                       */
  size_t memory_size;		/* Size of MEMORY.             */
  size_t data_size;		/* Size of data in MEMORY.     */
  unsigned int grow: 1;		/* MEMORY is allowed to grow.  */
  size_t offset;		/* Current offset in MEMORY.   */
  mem_func_realloc_t func_realloc;
  mem_func_free_t func_free;
} *gpg_stream_handle_mem_t;

static gpg_error_t
gpg_stream_func_mem_create (void **handle,
			    void *spec,
			    unsigned int flags)
{
  gpg_stream_handle_mem_t mem_handle = NULL;
  gpg_stream_spec_mem_t *mem_spec = spec;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  mem_handle = malloc (sizeof (*mem_handle));
  if (! mem_handle)
    err = gpg_error_from_errno (errno);
  else
    {
      mem_handle->memory = mem_spec ? mem_spec->memory : 0;
      mem_handle->memory_size = mem_spec ? mem_spec->memory_size : 0;
      mem_handle->data_size = 0;
      mem_handle->grow = mem_spec ? mem_spec->grow : 1;
      mem_handle->offset = 0;
      mem_handle->func_realloc = ((mem_spec && mem_spec->func_realloc)
				  ? mem_spec->func_realloc : realloc);
      mem_handle->func_free = ((mem_spec && mem_spec->func_free)
			       ? mem_spec->func_free : free);
      *handle = mem_handle;
    }

  return err;
}

static gpg_error_t
gpg_stream_func_mem_read (void *handle,
			  char *buffer,
			  size_t bytes_to_read,
			  size_t *bytes_read)
{
  gpg_stream_handle_mem_t mem_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (bytes_to_read > mem_handle->data_size - mem_handle->offset)
    bytes_to_read = mem_handle->data_size - mem_handle->offset;

  memcpy (buffer, mem_handle->memory + mem_handle->offset,
	  bytes_to_read);
  mem_handle->offset += bytes_to_read;
  *bytes_read = bytes_to_read;

  return err;
}

static gpg_error_t
gpg_stream_func_mem_write (void *handle,
			   const char *buffer,
			   size_t bytes_to_write,
			   size_t *bytes_written)
{
  gpg_stream_handle_mem_t mem_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  char *memory_new = NULL;

  if (! mem_handle->grow)
    if (bytes_to_write > mem_handle->memory_size - mem_handle->offset)
      bytes_to_write = mem_handle->memory_size - mem_handle->offset;

  while (bytes_to_write > mem_handle->memory_size - mem_handle->offset)
    {
      memory_new = (*mem_handle->func_realloc)
	(mem_handle->memory,
	 mem_handle->memory_size + BUFFER_BLOCK_SIZE);
      if (! memory_new)
	err = gpg_error_from_errno (errno);
      else
	{
	  if (mem_handle->memory != memory_new)
	    mem_handle->memory = memory_new;
	  mem_handle->memory_size += BUFFER_BLOCK_SIZE;
	}
    }

  if (! err)
    {
      memcpy (mem_handle->memory + mem_handle->offset, buffer,
	      bytes_to_write);
      if (mem_handle->offset + bytes_to_write > mem_handle->data_size)
	mem_handle->data_size = mem_handle->offset + bytes_to_write;
      mem_handle->offset += bytes_to_write;
    }
  *bytes_written = bytes_to_write;

  return err;
}

gpg_error_t
gpg_stream_func_mem_seek (void *handle,
			  off_t offset,
			  int whence)
{
  gpg_stream_handle_mem_t mem_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  switch (whence)
    {
    case SEEK_SET:
      if ((offset < 0) || (offset > mem_handle->data_size))
	err = gpg_error (GPG_ERR_INV_ARG);
      else
	mem_handle->offset = offset;
      break;

    case SEEK_CUR:
      if ((mem_handle->offset + offset < 0)
	  || (mem_handle->offset + offset > mem_handle->data_size))
	err = gpg_error (GPG_ERR_INV_ARG);
      else
	mem_handle->offset += offset;
      break;

    case SEEK_END:
      if ((mem_handle->data_size + offset < 0)
	  || (mem_handle->data_size + offset > mem_handle->data_size))
	err = gpg_error (GPG_ERR_INV_ARG);
      else
	mem_handle->offset += offset;
    }

  return err;
}

static gpg_error_t
gpg_stream_func_mem_stat (void *handle,
			  size_t *size)
{
  gpg_stream_handle_mem_t mem_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  *size = mem_handle->data_size;

  return err;
}

static gpg_error_t
gpg_stream_func_mem_destroy (void *handle)
{
  gpg_stream_handle_mem_t mem_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (mem_handle->memory)
    (*mem_handle->func_free) (mem_handle->memory);
  free (mem_handle);

  return err;
}

gpg_stream_functions_t gpg_stream_functions_mem =
  {
    gpg_stream_func_mem_create,
    gpg_stream_func_mem_read,
    gpg_stream_func_mem_write,
    gpg_stream_func_mem_seek,
    gpg_stream_func_mem_stat,
    gpg_stream_func_mem_destroy
  };

/* Implementation of FD I/O.  */

typedef struct gpg_stream_handle_fd
{
  int fd;
} *gpg_stream_handle_fd_t;

static gpg_error_t
gpg_stream_func_fd_create (void **handle,
			   void *spec,
			   unsigned int flags)
{
  gpg_stream_handle_fd_t fd_handle = NULL;
  gpg_stream_spec_fd_t *fd_spec = spec;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  fd_handle = malloc (sizeof (*fd_handle));
  if (! fd_handle)
    err = gpg_error_from_errno (errno);
  else
    {
      fd_handle->fd = fd_spec->fd;
      *handle = fd_handle;
    }
  
  return err;
}

static gpg_error_t
gpg_stream_func_fd_read (void *handle,
			 char *buffer,
			 size_t bytes_to_read,
			 size_t *bytes_read)

{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  ssize_t ret = -1;

  ret = READ (file_handle->fd, buffer, bytes_to_read);
  if (ret == -1)
    err = gpg_error_from_errno (errno);
  else
    *bytes_read = ret;

  return err;
}

static gpg_error_t
gpg_stream_func_fd_write (void *handle,
			  const char *buffer,
			  size_t bytes_to_write,
			  size_t *bytes_written)
			   
{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  ssize_t ret = -1;

  ret = WRITE (file_handle->fd, buffer, bytes_to_write);
  if (ret == -1)
    err = gpg_error_from_errno (errno);
  else
    *bytes_written = ret;

  return err;
}

static gpg_error_t
gpg_stream_func_fd_seek (void *handle,
			 off_t pos,
			 int whence)
{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  off_t ret = -1;

  ret = lseek (file_handle->fd, pos, whence);
  if (ret == -1)
    err = gpg_error_from_errno (errno);

  return err;
}

static gpg_error_t
gpg_stream_func_fd_stat (void *handle,
			 size_t *size)
{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  struct stat statbuf;
  int ret = 0;

  ret = fstat (file_handle->fd, &statbuf);
  if (ret == -1)
    err = gpg_error_from_errno (errno);
  else
    *size = statbuf.st_size;

  return err;
}

static gpg_error_t
gpg_stream_func_fd_destroy (void *handle)
{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  free (file_handle);

  return err;
}

gpg_stream_functions_t gpg_stream_functions_fd =
  {
    gpg_stream_func_fd_create,
    gpg_stream_func_fd_read,
    gpg_stream_func_fd_write,
    gpg_stream_func_fd_seek,
    gpg_stream_func_fd_stat,
    gpg_stream_func_fd_destroy
  };


/* Implementation of File I/O.  */

static gpg_error_t
gpg_stream_func_file_create (void **handle,
			     void *spec,
			     unsigned int flags)
{
  gpg_stream_handle_fd_t file_handle = NULL;
  gpg_stream_spec_file_t *file_spec = spec;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  int open_flags = 0;
  int fd = -1;

  file_handle = malloc (sizeof (*file_handle));
  if (! file_handle)
    err = gpg_error_from_errno (errno);

  if (! err)
    {
      struct flag_mapping
      {
	unsigned int gpg_stream;
	unsigned int sys;
      } flag_mappings[] = { { GPG_STREAM_FLAG_READ,
			      O_RDONLY },
			    { GPG_STREAM_FLAG_WRITE,
			      O_WRONLY },
			    { GPG_STREAM_FLAG_EXCLUSIVE,
			      O_EXCL },
			    { GPG_STREAM_FLAG_APPEND,
			      O_APPEND },
			    { GPG_STREAM_FLAG_CREATE,
			      O_CREAT },
			    { GPG_STREAM_FLAG_NONBLOCK,
			      O_NONBLOCK },
			    { GPG_STREAM_FLAG_TRUNCATE,
			      O_TRUNC } };
      unsigned int i = 0;

      for (i = 0; i < (sizeof (flag_mappings) / sizeof (*flag_mappings)); i++)
	if (flags & flag_mappings[i].gpg_stream)
	  open_flags |= flag_mappings[i].sys;

      fd = open (file_spec->filename, open_flags, file_spec->mode);
      if (fd == -1)
	err = gpg_error_from_errno (errno);
    }

  if (! err)
    {
      file_handle->fd = fd;
      *handle = file_handle;
    }
  else
    {
      if (file_handle)
	free (file_handle);
      if (fd != -1)
	close (fd);
    }

  return err;
}

static gpg_error_t
gpg_stream_func_file_destroy (void *handle)
{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  int ret = 0;

  if (file_handle)
    {
      ret = close (file_handle->fd);
      if (ret == -1)
	err = gpg_error_from_errno (errno);
      free (file_handle);
    }

  return err;
}

gpg_stream_functions_t gpg_stream_functions_file =
  {
    gpg_stream_func_file_create,
    gpg_stream_func_fd_read,
    gpg_stream_func_fd_write,
    gpg_stream_func_fd_seek,
    gpg_stream_func_fd_stat,
    gpg_stream_func_file_destroy
  };



static gpg_error_t
gpg_stream_create_do (gpg_stream_t *stream,
		      void *spec,
		      unsigned int flags,
		      gpg_stream_functions_t functions)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (! (1
	 && (0
	     || ((flags & GPG_STREAM_FLAG_READ) && functions.func_read)
	     || ((flags & GPG_STREAM_FLAG_WRITE) && functions.func_write))))
    err = gpg_error (GPG_ERR_INV_ARG);
  else
    {
      buffer_functions_t buffer_fncs = { functions.func_read,
					 functions.func_write,
					 functions.func_seek,
					 functions.func_stat };
      gpg_stream_t stream_new = NULL;
      buffer_t buffer = NULL;
      void *handle = NULL;
  
      stream_new = malloc (sizeof (*stream_new));
      if (! stream_new)
	err = gpg_error_from_errno (errno);

      if (! err)
	if (functions.func_create)
	  err = (*functions.func_create) (&handle, spec, flags);
      
      if (! err)
	err = buffer_create (&buffer, handle, buffer_fncs);

      if (! err)
	{
	  stream_new->handle = handle;
	  stream_new->flags = flags;
	  stream_new->buffer = buffer;
	  stream_new->functions = functions;
	  *stream = stream_new;
	}
      else
	{
	  if (functions.func_destroy)
	    (*functions.func_destroy) (handle);
	  if (buffer)
	    buffer_destroy (buffer);
	}
    }

  return err;
}

gpg_error_t
gpg_stream_create (gpg_stream_t *stream,
		   void *spec,
		   unsigned int flags,
		   gpg_stream_functions_t functions)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_create_do (stream, spec, flags, functions);

  return err;
}

gpg_error_t
gpg_stream_create_file (gpg_stream_t *stream,
			const char *filename,
			unsigned int flags)
{
  gpg_stream_spec_file_t spec = { filename, GPG_STREAM_FILE_PERMISSIONS };
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_create_do (stream, &spec, flags, gpg_stream_functions_file);

  return err;
}

gpg_error_t
gpg_stream_create_fd (gpg_stream_t *stream,
		      int fd,
		      unsigned int flags)
{
  gpg_stream_spec_fd_t spec = { fd };
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_create_do (stream, &spec, flags, gpg_stream_functions_fd);

  return err;
}


gpg_error_t
gpg_stream_destroy (gpg_stream_t stream)
{
  gpg_error_t err = GPG_ERR_NO_ERROR, tmp_err = GPG_ERR_NO_ERROR;

  if (stream)
    {
      SET_UNLESS_NONZERO (err, tmp_err, buffer_destroy (stream->buffer));
      if (stream->functions.func_destroy)
	SET_UNLESS_NONZERO (err, tmp_err, \
			    (*stream->functions.func_destroy) (stream->handle));
      free (stream);
    }

  return err;
}

static gpg_error_t
gpg_stream_read_do (gpg_stream_t stream,
		    char *buffer,
		    size_t bytes_to_read,
		    size_t *bytes_read)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (! (stream->flags & GPG_STREAM_FLAG_READ))
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else
    err = buffer_read (stream->buffer,
		       buffer, bytes_to_read, bytes_read);

  return err;
}

gpg_error_t
gpg_stream_read (gpg_stream_t stream,
		 char *buffer,
		 size_t bytes_to_read,
		 size_t *bytes_read)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_read_do (stream, buffer, bytes_to_read, bytes_read);

  return err;
}

static gpg_error_t
gpg_stream_write_do (gpg_stream_t stream,
		     const char *buffer,
		     size_t bytes_to_write,
		     size_t *bytes_written)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (! (stream->flags & GPG_STREAM_FLAG_WRITE))
    err = GPG_ERR_NOT_SUPPORTED;
  else
    err = buffer_write (stream->buffer,
			buffer, bytes_to_write, bytes_written);

  return err;
}

gpg_error_t
gpg_stream_write (gpg_stream_t stream,
		  const char *buffer,
		  size_t bytes_to_write,
		  size_t *bytes_written)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_write_do (stream, buffer, bytes_to_write, bytes_written);

  return err;
}

static gpg_error_t
gpg_stream_read_line_do (gpg_stream_t stream,
			 char **line,
			 size_t *line_length)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (! (stream->flags & GPG_STREAM_FLAG_READ))
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else
    {
      buffer_functions_t buffer_fncs_mem = { gpg_stream_func_mem_read,
					     gpg_stream_func_mem_write,
					     gpg_stream_func_mem_seek };
      void *handle = NULL;
      char *line_new = NULL;
      buffer_t line_buffer = NULL;
      char *newline = NULL;
      size_t data_size = 0;
      char *data = NULL;
      size_t line_size = 0;

      err = gpg_stream_func_mem_create (&handle, NULL, 0);
      if (! err)
	err = buffer_create (&line_buffer, handle, buffer_fncs_mem);
      if (! err)
	do
	  {
	    err = buffer_peek (stream->buffer, &data, &data_size);
	    if (! err)
	      {
		size_t bytes_written = 0;

		newline = memchr (data, '\n', data_size);
		if (newline)
		  {
		    /* Write until newline.  */
		    line_size += newline - data + 1;
		    err = buffer_write (line_buffer, data, newline - data + 1,
					&bytes_written);
		    if (! err)
		      err = buffer_skip (stream->buffer, bytes_written);
		    break;
		  }
		else
		  {
		    /* Write whole block.  */
		    line_size += data_size;
		    err = buffer_write (line_buffer, data, data_size,
					&bytes_written);
		    if (! err)
		      err = buffer_skip (stream->buffer, bytes_written);
		  }
	      }
	  }
	while ((! err) && data_size);

      if (! err)
	{
	  /* Complete line has been written to line_buffer.  */
	  if (line_size)
	    {
	      err = buffer_seek (line_buffer, 0, SEEK_SET);
	      if (! err)
		{
		  line_new = malloc (line_size + 1);
		  if (! line_new)
		    err = gpg_error_from_errno (errno);
		}
	      if (! err)
		{
		  size_t bytes_written = 0, written = 0;
		  
		  while ((bytes_written < line_size) && (! err))
		    {
		      err = buffer_read (line_buffer, line_new + bytes_written,
					 line_size - bytes_written, &written);
		      bytes_written += written;
		    }
		  if (! err)
		    line_new[line_size] = 0;
		}
	    }
	}
	  
      if (line_buffer)
	buffer_destroy (line_buffer);
      if (handle)
	gpg_stream_func_mem_destroy (handle);

      if (! err)
	{
	  *line = line_new;
	  if (line_length)
	    *line_length = line_size;
	}
      else
	{
	  if (line_new)
	    free (line_new);
	}
    }

  return err;
}

gpg_error_t
gpg_stream_read_line (gpg_stream_t stream,
		      char **line,
		      size_t *line_length)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_read_line_do (stream, line, line_length);

  return err;
}

static gpg_error_t
gpg_stream_print_va_do (gpg_stream_t stream,
			const char *format,
			va_list ap)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  FILE *tmp_stream = NULL;
  int ret = 0;

  if (! (stream->flags & GPG_STREAM_FLAG_WRITE))
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else
    {
      tmp_stream = tmpfile ();
      if (! tmp_stream)
	err = gpg_error_from_errno (errno);

      if (! err)
	{
	  ret = vfprintf (tmp_stream, format, ap);
	  if (ret == -1)
	    err = gpg_error_from_errno (errno);
	}

      if (! err)
	{
	  ret = fseek (tmp_stream, 0, SEEK_SET);
	  if (ret == -1)
	    err = gpg_error_from_errno (errno);
	}

      if (! err)
	{
	  size_t bytes_read = 0, bytes_written = 0;
	  char data[BUFFER_BLOCK_SIZE];

	  while (! err)
	    {
	      bytes_read = fread (data, 1, sizeof (data), tmp_stream);
	      if (ferror (tmp_stream))
		err = gpg_error_from_errno (errno);
	      if (! err)
		err = gpg_stream_write_do (stream, data,
					   bytes_read, &bytes_written);
	      if (! err)
		if (feof (tmp_stream))
		  break;
	    }
	}

      if (tmp_stream)
	fclose (tmp_stream);
    }

  return err;
}

gpg_error_t
gpg_stream_print_va (gpg_stream_t stream,
		     const char *format,
		     va_list ap)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  
  err = gpg_stream_print_va_do (stream, format, ap);

  return err;
}

gpg_error_t
gpg_stream_print (gpg_stream_t stream,
		  const char *format,
		  ...)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  va_list ap;

  va_start (ap, format);
  err = gpg_stream_print_va (stream, format, ap);
  va_end (ap);

  return err;
}

static gpg_error_t
gpg_stream_flush_do (gpg_stream_t stream)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = buffer_flush (stream->buffer);

  return err;
}

gpg_error_t
gpg_stream_flush (gpg_stream_t stream)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_flush_do (stream);

  return err;
}

static gpg_error_t
gpg_stream_peek_do (gpg_stream_t stream,
		    char **buffer,
		    size_t *size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = buffer_peek (stream->buffer, buffer, size);

  return err;
}

gpg_error_t
gpg_stream_peek (gpg_stream_t stream,
		 char **buffer,
		 size_t *size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_peek_do (stream, buffer, size);

  return err;
}

static gpg_error_t
gpg_stream_seek_do (gpg_stream_t stream,
		    off_t offset,
		    int whence)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = buffer_seek (stream->buffer, offset, whence);

  return err;
}

gpg_error_t
gpg_stream_seek (gpg_stream_t stream,
		 off_t offset,
		 int whence)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_seek_do (stream, offset, whence);

  return err;
}

static gpg_error_t
gpg_stream_stat_do (gpg_stream_t stream,
		    size_t *size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = buffer_stat (stream->buffer, size);

  return err;
}

gpg_error_t
gpg_stream_stat (gpg_stream_t stream,
		 size_t *size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_stat_do (stream, size);

  return err;
}


static gpg_error_t
gpg_stream_copy_do (gpg_stream_t dst,
		    gpg_stream_t src)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  unsigned char buffer[STREAM_BLOCK_SIZE];
  size_t bytes_read = 0;

  while (1)
    {
      err = gpg_stream_read (src, buffer, sizeof (buffer), &bytes_read);
      if (err || (! bytes_read))
	break;

      err = gpg_stream_write (dst, buffer, bytes_read, NULL);
      if (err)
	break;
    }

  return err;
}

gpg_error_t
gpg_stream_copy (gpg_stream_t dst,
		 gpg_stream_t src)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_copy_do (dst, src);

  return err;
}
