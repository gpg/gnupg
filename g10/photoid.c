/* photoid.c - photo ID handling code
 * Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "packet.h"
#include "status.h"
#include "exec.h"
#include "keydb.h"
#include "util.h"
#include "i18n.h"
#include "iobuf.h"
#include "memory.h"
#include "options.h"
#include "main.h"
#include "photoid.h"

#define DEFAULT_PHOTO_COMMAND "xloadimage -fork -quiet -title 'KeyID 0x%k' stdin"

/* Generate a new photo id packet, or return NULL if canceled */
PKT_user_id *generate_photo_id(PKT_public_key *pk)
{
  PKT_user_id *uid;
  int error=1,i;
  unsigned int len;
  char *filename=NULL;
  byte *photo=NULL;
  byte header[16];
  IOBUF file;

  header[0]=0x10; /* little side of photo header length */
  header[1]=0;    /* big side of photo header length */
  header[2]=1;    /* 1 == version of photo header */
  header[3]=1;    /* 1 == JPEG */

  for(i=4;i<16;i++) /* The reserved bytes */
    header[i]=0;

  uid=m_alloc_clear(sizeof(*uid)+50);

  printf(_("\nPick an image to use for your photo ID.  "
	   "The image must be a JPEG file.\n"
	   "Remember that the image is stored within your public key.  "
	   "If you use a\n"
	   "very large picture, your key will become very large as well!\n"
	   "Keeping the image close to 240x288 is a good size to use.\n"));

  while(photo==NULL)
    {
      printf("\n");

      m_free(filename);

      filename=cpr_get("photoid.jpeg.add",
		       _("Enter JPEG filename for photo ID: "));

      if(strlen(filename)==0)
	goto scram;

      file=iobuf_open(filename);
      if(!file)
	{
	  log_error(_("Unable to open photo \"%s\": %s\n"),
		    filename,strerror(errno));
	  continue;
	}

      len=iobuf_get_filelength(file);
      if(len>6144)
	{
	  printf("This JPEG is really large (%d bytes) !\n",len);
	  if(!cpr_get_answer_is_yes("photoid.jpeg.size",
			    _("Are you sure you want to use it (y/N)? ")))
	  {
	    iobuf_close(file);
	    continue;
	  }
	}

      photo=m_alloc(len);
      iobuf_read(file,photo,len);
      iobuf_close(file);

      /* Is it a JPEG? */
      if(photo[0]!=0xFF || photo[1]!=0xD8 ||
	 photo[6]!='J' || photo[7]!='F' || photo[8]!='I' || photo[9]!='F')
	{
	  log_error(_("\"%s\" is not a JPEG file\n"),filename);
	  m_free(photo);
	  photo=NULL;
	  continue;
	}

      /* Build the packet */
      build_attribute_subpkt(uid,1,photo,len,header,16);
      parse_attribute_subpkts(uid);
      make_attribute_uidname(uid);

      show_photo(uid->attribs,pk);
      switch(cpr_get_answer_yes_no_quit("photoid.jpeg.okay",
					_("Is this photo correct (y/N/q)? ")))
	{
	case -1:
	  goto scram;
	case 0:
	  free_attributes(uid);
	  m_free(photo);
	  photo=NULL;
	  continue;
	}
    }

  error=0;
  uid->ref=1;

 scram:
  m_free(filename);
  m_free(photo);

  if(error)
    {
      free_attributes(uid);
      m_free(uid);
      return NULL;
    }

  return uid;
}

void show_photo(const struct user_attribute *attr,PKT_public_key *pk)
{
  char *command;
  struct exec_info *spawn;

  /* make command grow */
  command=
    pct_expando(opt.photo_viewer?opt.photo_viewer:DEFAULT_PHOTO_COMMAND,pk);

  if(!command)
    goto fail;

  if(exec_write(&spawn,NULL,command,1,1)!=0)
    goto fail;

  fwrite(attr->data,attr->len,1,spawn->tochild);

  if(exec_read(spawn)!=0)
    {
      exec_finish(spawn);
      goto fail;
    }

  if(exec_finish(spawn)!=0)
    goto fail;

  return;

 fail:
  log_error("unable to display photo ID!\n");
}
