/* srv.c - DNS SRV code
 * Copyright (C) 2003, 2005, 2006, 2007 Free Software Foundation, Inc.
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
#ifdef _WIN32
#include <windows.h>
#else
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "memory.h"
#include "types.h"
#include "srv.h"

/* Not every installation has gotten around to supporting SRVs
   yet... */
#ifndef T_SRV
#define T_SRV 33
#endif

static int
priosort(const void *a,const void *b)
{
  const struct srventry *sa=a,*sb=b;
  if(sa->priority>sb->priority)
    return 1;
  else if(sa->priority<sb->priority)
    return -1;
  else
    return 0;
}

int
getsrv(const char *name,struct srventry **list)
{
  unsigned char answer[PACKETSZ];
  int r,srvcount=0;
  unsigned char *pt,*emsg;
  u16 count,dlen;

  *list=NULL;

  r=res_query(name,C_IN,T_SRV,answer,PACKETSZ);
  if(r<sizeof(HEADER) || r>PACKETSZ)
    return -1;

  if((((HEADER *)answer)->rcode)==NOERROR &&
     (count=ntohs(((HEADER *)answer)->ancount)))
    {
      int i,rc;

      emsg=&answer[r];
      pt=&answer[sizeof(HEADER)];

      /* Skip over the query */

      rc=dn_skipname(pt,emsg);
      if(rc==-1)
	goto fail;

      pt+=rc+QFIXEDSZ;

      while(count-->0 && pt<emsg)
	{
	  struct srventry *srv=NULL;
	  u16 type,class;

	  *list=xrealloc(*list,(srvcount+1)*sizeof(struct srventry));
	  memset(&(*list)[srvcount],0,sizeof(struct srventry));
	  srv=&(*list)[srvcount];
	  srvcount++;

	  rc=dn_skipname(pt,emsg); /* the name we just queried for */
	  if(rc==-1)
	    goto fail;
	  pt+=rc;

	  /* Truncated message? */
	  if((emsg-pt)<16)
	    goto fail;

	  type=*pt++ << 8;
	  type|=*pt++;
	  /* We asked for SRV and got something else !? */
	  if(type!=T_SRV)
	    goto fail;

	  class=*pt++ << 8;
	  class|=*pt++;
	  /* We asked for IN and got something else !? */
	  if(class!=C_IN)
	    goto fail;

	  pt+=4; /* ttl */
	  dlen=*pt++ << 8;
	  dlen|=*pt++;
	  srv->priority=*pt++ << 8;
	  srv->priority|=*pt++;
	  srv->weight=*pt++ << 8;
	  srv->weight|=*pt++;
	  srv->port=*pt++ << 8;
	  srv->port|=*pt++;

	  /* Get the name.  2782 doesn't allow name compression, but
	     dn_expand still works to pull the name out of the
	     packet. */
	  rc=dn_expand(answer,emsg,pt,srv->target,MAXDNAME);
	  if(rc==1 && srv->target[0]==0) /* "." */
	    goto noanswer;
	  if(rc==-1)
	    goto fail;
	  pt+=rc;
	  /* Corrupt packet? */
	  if(dlen!=rc+6)
	    goto fail;

#if 0
	  printf("count=%d\n",srvcount);
	  printf("priority=%d\n",srv->priority);
	  printf("weight=%d\n",srv->weight);
	  printf("port=%d\n",srv->port);
	  printf("target=%s\n",srv->target);
#endif
	}

      /* Now we have an array of all the srv records. */

      /* Order by priority */
      qsort(*list,srvcount,sizeof(struct srventry),priosort);

      /* For each priority, move the zero-weighted items first. */
      for(i=0;i<srvcount;i++)
	{
	  int j;

	  for(j=i;j<srvcount && (*list)[i].priority==(*list)[j].priority;j++)
	    {
	      if((*list)[j].weight==0)
		{
		  /* Swap j with i */
		  if(j!=i)
		    {
		      struct srventry temp;

		      memcpy(&temp,&(*list)[j],sizeof(struct srventry));
		      memcpy(&(*list)[j],&(*list)[i],sizeof(struct srventry));
		      memcpy(&(*list)[i],&temp,sizeof(struct srventry));
		    }

		  break;
		}
	    }
	}

      /* Run the RFC-2782 weighting algorithm.  We don't need very
	 high quality randomness for this, so regular libc srand/rand
	 is sufficient. */
      srand(time(NULL)*getpid());

      for(i=0;i<srvcount;i++)
	{
	  int j;
	  float prio_count=0,chose;

	  for(j=i;j<srvcount && (*list)[i].priority==(*list)[j].priority;j++)
	    {
	      prio_count+=(*list)[j].weight;
	      (*list)[j].run_count=prio_count;
	    }

	  chose=prio_count*rand()/RAND_MAX;

	  for(j=i;j<srvcount && (*list)[i].priority==(*list)[j].priority;j++)
	    {
	      if(chose<=(*list)[j].run_count)
		{
		  /* Swap j with i */
		  if(j!=i)
		    {
		      struct srventry temp;

		      memcpy(&temp,&(*list)[j],sizeof(struct srventry));
		      memcpy(&(*list)[j],&(*list)[i],sizeof(struct srventry));
		      memcpy(&(*list)[i],&temp,sizeof(struct srventry));
		    }
		  break;
		}
	    }
	}
    }
  
  return srvcount;

 noanswer:
  xfree(*list);
  *list=NULL;
  return 0;

 fail:
  xfree(*list);
  *list=NULL;
  return -1;
}

#ifdef TEST
int
main(int argc,char *argv[])
{
  struct srventry *srv;
  int rc,i;

  rc=getsrv("_hkp._tcp.wwwkeys.pgp.net",&srv);
  printf("Count=%d\n\n",rc);
  for(i=0;i<rc;i++)
    {
      printf("priority=%d\n",srv[i].priority);
      printf("weight=%d\n",srv[i].weight);
      printf("port=%d\n",srv[i].port);
      printf("target=%s\n",srv[i].target);
      printf("\n");
    }

  xfree(srv);

  return 0;
}
#endif /* TEST */

/*
Local Variables:
compile-command: "cc -DTEST -I.. -I../include -Wall -g -o srv srv.c -lresolv libutil.a"
End:
*/
