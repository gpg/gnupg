/* cert.c - DNS CERT code
 * Copyright (C) 2005, 2006, 2007 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <sys/types.h>
#ifdef USE_DNS_CERT
#ifdef _WIN32
#include <windows.h>
#else
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#endif
#include <string.h>
#include "memory.h"
#endif
#include "iobuf.h"
#include "util.h"

/* Not every installation has gotten around to supporting CERTs
   yet... */
#ifndef T_CERT
#define T_CERT 37
#endif

#ifdef USE_DNS_CERT

/* Returns -1 on error, 0 for no answer, 1 for PGP provided and 2 for
   IPGP provided. */
int
get_cert(const char *name,size_t max_size,IOBUF *iobuf,
	 unsigned char **fpr,size_t *fpr_len,char **url)
{
  unsigned char *answer;
  int r,ret=-1;
  u16 count;

  if(fpr)
    *fpr=NULL;

  if(url)
    *url=NULL;

  answer=xmalloc(max_size);

  r=res_query(name,C_IN,T_CERT,answer,max_size);
  /* Not too big, not too small, no errors and at least 1 answer. */
  if(r>=sizeof(HEADER) && r<=max_size
     && (((HEADER *)answer)->rcode)==NOERROR
     && (count=ntohs(((HEADER *)answer)->ancount)))
    {
      int rc;
      unsigned char *pt,*emsg;

      emsg=&answer[r];

      pt=&answer[sizeof(HEADER)];

      /* Skip over the query */

      rc=dn_skipname(pt,emsg);
      if(rc==-1)
	goto fail;

      pt+=rc+QFIXEDSZ;

      /* There are several possible response types for a CERT request.
	 We're interested in the PGP (a key) and IPGP (a URI) types.
	 Skip all others.  TODO: A key is better than a URI since
	 we've gone through all this bother to fetch it, so favor that
	 if we have both PGP and IPGP? */

      while(count-->0 && pt<emsg)
	{
	  u16 type,class,dlen,ctype;

	  rc=dn_skipname(pt,emsg); /* the name we just queried for */
	  if(rc==-1)
	    break;

	  pt+=rc;

	  /* Truncated message? 15 bytes takes us to the point where
	     we start looking at the ctype. */
	  if((emsg-pt)<15)
	    break;

	  type=*pt++ << 8;
	  type|=*pt++;

	  class=*pt++ << 8;
	  class|=*pt++;
	  /* We asked for IN and got something else !? */
	  if(class!=C_IN)
	    break;

	  /* ttl */
	  pt+=4;

	  /* data length */
	  dlen=*pt++ << 8;
	  dlen|=*pt++;

	  /* We asked for CERT and got something else - might be a
	     CNAME, so loop around again. */
	  if(type!=T_CERT)
	    {
	      pt+=dlen;
	      continue;
	    }

	  /* The CERT type */
	  ctype=*pt++ << 8;
	  ctype|=*pt++;

	  /* Skip the CERT key tag and algo which we don't need. */
	  pt+=3;

	  dlen-=5;

	  /* 15 bytes takes us to here */

	  if(ctype==3 && iobuf && dlen)
	    {
	      /* PGP type */
	      *iobuf=iobuf_temp_with_content((char *)pt,dlen);
	      ret=1;
	      break;
	    }
	  else if(ctype==6 && dlen && dlen<1023 && dlen>=pt[0]+1
		  && fpr && fpr_len && url)
	    {
	      /* IPGP type */
	      *fpr_len=pt[0];

	      if(*fpr_len)
		{
		  *fpr=xmalloc(*fpr_len);
		  memcpy(*fpr,&pt[1],*fpr_len);
		}
	      else
		*fpr=NULL;

	      if(dlen>*fpr_len+1)
		{
		  *url=xmalloc(dlen-(*fpr_len+1)+1);
		  memcpy(*url,&pt[*fpr_len+1],dlen-(*fpr_len+1));
		  (*url)[dlen-(*fpr_len+1)]='\0';
		}
	      else
		*url=NULL;

	      ret=2;
	      break;
	    }

	  /* Neither type matches, so go around to the next answer. */
	  pt+=dlen;
	}
    }

 fail:
  xfree(answer);

  return ret;
}

#else /* !USE_DNS_CERT */

int
get_cert(const char *name,size_t max_size,IOBUF *iobuf,
	 unsigned char **fpr,size_t *fpr_len,char **url)
{
  return -1;
}

#endif

/* Test with simon.josefsson.org */

#ifdef TEST
int
main(int argc,char *argv[])
{
  unsigned char *fpr;
  size_t fpr_len;
  char *url;
  int rc;
  IOBUF iobuf;

  if(argc!=2)
    {
      printf("cert-test [name]\n");
      return 1;
    }

  printf("CERT lookup on %s\n",argv[1]);

  rc=get_cert(argv[1],16384,&iobuf,&fpr,&fpr_len,&url);
  if(rc==-1)
    printf("error\n");
  else if(rc==0)
    printf("no answer\n");
  else if(rc==1)
    {
      printf("key found: %d bytes\n",(int)iobuf_get_temp_length(iobuf));
      iobuf_close(iobuf);
    }
  else if(rc==2)
    {
      if(fpr)
	{
	  size_t i;
	  printf("Fingerprint found (%d bytes): ",(int)fpr_len);
	  for(i=0;i<fpr_len;i++)
	    printf("%02X",fpr[i]);
	  printf("\n");
	}
      else
	printf("No fingerprint found\n");

      if(url)
	printf("URL found: %s\n",url);
      else
	printf("No URL found\n");

      xfree(fpr);
      xfree(url);
    }

  return 0;
}
#endif /* TEST */
