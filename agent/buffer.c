/* buffer.c - Buffer management layer
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <gpg-error.h>

#include "buffer.h"



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
