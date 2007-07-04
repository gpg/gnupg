/* make-dns-cert.c - An OpenPGP-to-DNS CERT conversion tool
 * Copyright (C) 2006 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <unistd.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* We use TYPE37 instead of CERT since not all nameservers can handle
   CERT yet... */

static int
cert_key(const char *name,const char *keyfile)
{
  int fd,ret=1,err,i;
  struct stat statbuf;

  fd=open(keyfile,O_RDONLY);
  if(fd==-1)
    {
      fprintf(stderr,"Cannot open key file %s: %s\n",keyfile,strerror(errno));
      return 1;
    }

  err=fstat(fd,&statbuf);
  if(err==-1)
    {
      fprintf(stderr,"Unable to stat key file %s: %s\n",
	      keyfile,strerror(errno));
      goto fail;
    }

  if(statbuf.st_size>65536)
    {
      fprintf(stderr,"Key %s too large for CERT encoding\n",keyfile);
      goto fail;
    }

  if(statbuf.st_size>16384)
    fprintf(stderr,"Warning: key file %s is larger than the default"
	    " GnuPG max-cert-size\n",keyfile);

  printf("%s\tTYPE37\t\\# %u 0003 0000 00 ",
	 name,(unsigned int)statbuf.st_size+5);

  err=1;
  while(err!=0)
    {
      unsigned char buffer[1024];

      err=read(fd,buffer,1024);
      if(err==-1)
	{
	  fprintf(stderr,"Unable to read key file %s: %s\n",
		  keyfile,strerror(errno));
	  goto fail;
	}

      for(i=0;i<err;i++)
	printf("%02X",buffer[i]);
    }

  printf("\n");

  ret=0;

 fail:
  close(fd);

  return ret;
}

static int
url_key(const char *name,const char *fpr,const char *url)
{
  int len=6,fprlen=0;

  if(fpr)
    {
      const char *tmp = fpr;
      while (*tmp)
	{
	  if ((*tmp >= 'A' && *tmp <= 'F') ||
	      (*tmp >= 'a' && *tmp <= 'f') ||
	      (*tmp >= '0' && *tmp <= '9'))
	    {
	      fprlen++;
	    }
	  else if (*tmp != ' ' && *tmp != '\t')
	    {
	      fprintf(stderr,"Fingerprint must consist of only hex digits"
		      " and whitespace\n");
	      return 1;
	    }

	  tmp++;
	}

      if(fprlen%2)
	{
	  fprintf(stderr,"Fingerprint must be an even number of characters\n");
	  return 1;
	}

      fprlen/=2;
      len+=fprlen;
    }

  if(url)
    len+=strlen(url);

  if(!fpr && !url)
    {
      fprintf(stderr,
	      "Cannot generate a CERT without either a fingerprint or URL\n");
      return 1;
    }

  printf("%s\tTYPE37\t\\# %d 0006 0000 00 %02X",name,len,fprlen);

  if(fpr)
    printf(" %s",fpr);

  if(url)
    {
      const char *c;
      printf(" ");
      for(c=url;*c;c++)
	printf("%02X",*c);
    }

  printf("\n");

  return 0;
}

static void
usage(FILE *stream)
{
  fprintf(stream,"make-dns-cert\n");
  fprintf(stream,"\t-f\tfingerprint\n");
  fprintf(stream,"\t-u\tURL\n");
  fprintf(stream,"\t-k\tkey file\n");
  fprintf(stream,"\t-n\tDNS name\n");
}

int
main(int argc,char *argv[])
{
  int arg,err=1;
  char *fpr=NULL,*url=NULL,*keyfile=NULL,*name=NULL;

  if(argc==1)
    {
      usage(stderr);
      return 1;
    }
  else if(argc>1 && strcmp(argv[1],"--version")==0)
    {
      printf("make-dns-cert (GnuPG) " VERSION "\n");
      return 0;
    }
  else if(argc>1 && strcmp(argv[1],"--help")==0)
    {
      usage(stdout);
      return 0;
    }

  while((arg=getopt(argc,argv,"hf:u:k:n:"))!=-1)
    switch(arg)
      {
      default:
      case 'h':
	usage(stdout);
	exit(0);

      case 'f':
	fpr=optarg;
	break;

      case 'u':
	url=optarg;
	break;

      case 'k':
	keyfile=optarg;
	break;

      case 'n':
	name=optarg;
	break;
      }

  if(!name)
    {
      fprintf(stderr,"No name provided\n");
      return 1;
    }

  if(keyfile && (fpr || url))
    {
      fprintf(stderr,"Cannot generate a CERT record with both a keyfile and"
	      " a fingerprint or URL\n");
      return 1;
    }

  if(keyfile)
    err=cert_key(name,keyfile);
  else
    err=url_key(name,fpr,url);

  return err;
}
