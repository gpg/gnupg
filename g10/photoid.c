/* photoid.c - photo ID handling code
 * Copyright (C) 2001, 2002 Free Software Foundation, Inc.
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

      show_photos(uid->attribs,uid->numattribs,pk);
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

/* Returns 0 for error, 1 for valid */
int parse_image_header(const struct user_attribute *attr,byte *type,u32 *len)
{
  int headerlen;

  if(attr->len<3)
    return 0;

  /* For historical reasons (i.e. "oops!"), the header length is
     little endian. */
  headerlen=(attr->data[1]<<8) | attr->data[0];

  if(headerlen>attr->len)
    return 0;

  if(type && attr->len>=4)
    {
      if(attr->data[2]==1) /* header version 1 */
	*type=attr->data[3];
      else
	*type=0;
    }

  *len=attr->len-headerlen;

  if(*len==0)
    return 0;

  return 1;
}

/* style==0 for extension, 1 for name, 2 for MIME type.  Remember that
   the "name" style string could be used in a user ID name field, so
   make sure it is not too big (see
   parse-packet.c:parse_attribute). */
char *image_type_to_string(byte type,int style)
{
  char *string;

  switch(type)
    {
    case 1: /* jpeg */
      if(style==0)
	string="jpg";
      else if(style==1)
	string="jpeg";
      else
	string="image/jpeg";
      break;

    default:
      if(style==0)
	string="bin";
      else if(style==1)
	string="unknown";
      else
	string="image/x-unknown";
      break;
    }

  return string;
}

void show_photos(const struct user_attribute *attrs,
		 int count,PKT_public_key *pk)
{
  int i;
  struct expando_args args;
  u32 len;

  memset(&args,0,sizeof(args));
  args.pk=pk;

  for(i=0;i<count;i++)
    if(attrs[i].type==ATTRIB_IMAGE &&
       parse_image_header(&attrs[i],&args.imagetype,&len))
      {
	char *command;
	struct exec_info *spawn;
	int offset=attrs[i].len-len;

	/* Notice we are not using the byte for image encoding type
           for more than cosmetics.  Most external image viewers can
           handle a multitude of types, and even if one cannot
           understand a partcular type, we have no way to know which.
           The spec specifically permits this, by the way. -dms */

	/* make command grow */
	command=pct_expando(opt.photo_viewer?
			    opt.photo_viewer:DEFAULT_PHOTO_COMMAND,&args);
	if(!command)
	  goto fail;

	if(exec_write(&spawn,NULL,command,1,1)!=0)
	  goto fail;

	fwrite(&attrs[i].data[offset],attrs[i].len-offset,1,spawn->tochild);

	if(exec_read(spawn)!=0)
	  {
	    exec_finish(spawn);
	    goto fail;
	  }

	if(exec_finish(spawn)!=0)
	  goto fail;
      }

  return;

 fail:
  log_error("unable to display photo ID!\n");
}
