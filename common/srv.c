/* srv.c - DNS SRV code
 * Copyright (C) 2003, 2009 Free Software Foundation, Inc.
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
#include <resolv.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef USE_ADNS
# include <adns.h>
# ifndef HAVE_ADNS_FREE
#  define adns_free free
# endif
#endif

#include "util.h"
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
getsrv (const char *name,struct srventry **list)
{
  int srvcount=0;
  u16 count;
  int i, rc;

  *list = NULL;

#ifdef USE_ADNS
  {
    adns_state state;
    adns_answer *answer = NULL;
    
    rc = adns_init (&state, adns_if_noerrprint, NULL);
    if (rc)
      {
        log_error ("error initializing adns: %s\n", strerror (errno));
        return -1;
      }

    rc = adns_synchronous (state, name, adns_r_srv, adns_qf_quoteok_query,
                           &answer);
    if (rc)
      {
        log_error ("DNS query failed: %s\n", strerror (errno));
        adns_finish (state);
        return -1;
      }
    if (answer->status != adns_s_ok 
        || answer->type != adns_r_srv || !answer->nrrs)
      {
        /* log_error ("DNS query returned an error or no records: %s (%s)\n", */
        /*            adns_strerror (answer->status), */
        /*            adns_errabbrev (answer->status)); */
        adns_free (answer);
        adns_finish (state);
        return 0;
      }

    for (count = 0; count < answer->nrrs; count++)
      {
        struct srventry *srv = NULL;
        struct srventry *newlist;

        if (strlen (answer->rrs.srvha[count].ha.host) >= MAXDNAME)
          {
            log_info ("hostname in SRV record too long - skipped\n");
            continue;
          }
      
        newlist = xtryrealloc (*list, (srvcount+1)*sizeof(struct srventry));
        if (!newlist)
          goto fail;
        *list = newlist;
        memset (&(*list)[srvcount], 0, sizeof(struct srventry));
        srv = &(*list)[srvcount];
        srvcount++;
      
        srv->priority = answer->rrs.srvha[count].priority;
        srv->weight   = answer->rrs.srvha[count].weight;
        srv->port     = answer->rrs.srvha[count].port;
        strcpy (srv->target, answer->rrs.srvha[count].ha.host);
      }

    adns_free (answer);
    adns_finish (state);
  }
#else /*!USE_ADNS*/
  {
    unsigned char answer[2048];
    HEADER *header = (HEADER *)answer;
    unsigned char *pt, *emsg;
    int r;
    u16 dlen;
    
    r = res_query (name, C_IN, T_SRV, answer, sizeof answer);
    if (r < sizeof (HEADER) || r > sizeof answer)
      return -1;
    if (header->rcode != NOERROR || !(count=ntohs (header->ancount)))
      return 0; /* Error or no record found.  */
    
    emsg = &answer[r];
    pt = &answer[sizeof(HEADER)];
  
    /* Skip over the query */
    rc = dn_skipname (pt, emsg);
    if (rc == -1)
      goto fail;
  
    pt += rc + QFIXEDSZ;
  
    while (count-- > 0 && pt < emsg)
      {
        struct srventry *srv=NULL;
        u16 type,class;
        struct srventry *newlist;
      
        newlist = xtryrealloc (*list, (srvcount+1)*sizeof(struct srventry));
        if (!newlist)
          goto fail;
        *list = newlist;
        memset(&(*list)[srvcount],0,sizeof(struct srventry));
        srv=&(*list)[srvcount];
        srvcount++;
      
        rc = dn_skipname(pt,emsg); /* the name we just queried for */
        if (rc == -1)
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
        rc = dn_expand(answer,emsg,pt,srv->target,MAXDNAME);
        if (rc == 1 && srv->target[0] == 0) /* "." */
          {
            xfree(*list);
            *list = NULL;
            return 0;
          }
        if (rc == -1)
          goto fail;
        pt += rc;
        /* Corrupt packet? */
        if (dlen != rc+6)
          goto fail;
      }
  }
#endif /*!USE_ADNS*/
  
  /* Now we have an array of all the srv records. */
  
  /* Order by priority */
  qsort(*list,srvcount,sizeof(struct srventry),priosort);
  
  /* For each priority, move the zero-weighted items first. */
  for (i=0; i < srvcount; i++)
    {
      int j;
      
      for (j=i;j < srvcount && (*list)[i].priority == (*list)[j].priority; j++)
        {
          if((*list)[j].weight==0)
            {
              /* Swap j with i */
              if(j!=i)
                {
                  struct srventry temp;
                  
                  memcpy (&temp,&(*list)[j],sizeof(struct srventry));
                  memcpy (&(*list)[j],&(*list)[i],sizeof(struct srventry));
                  memcpy (&(*list)[i],&temp,sizeof(struct srventry));
                }
              
              break;
            }
        }
    }

  /* Run the RFC-2782 weighting algorithm.  We don't need very high
     quality randomness for this, so regular libc srand/rand is
     sufficient.  Fixme: It is a bit questionaly to reinitalize srand
     - better use a gnupg fucntion for this.  */
  srand(time(NULL)*getpid());

  for (i=0; i < srvcount; i++)
    {
      int j;
      float prio_count=0,chose;
      
      for (j=i; j < srvcount && (*list)[i].priority == (*list)[j].priority; j++)
        {
          prio_count+=(*list)[j].weight;
          (*list)[j].run_count=prio_count;
        }
      
      chose=prio_count*rand()/RAND_MAX;
      
      for (j=i;j<srvcount && (*list)[i].priority==(*list)[j].priority;j++)
        {
          if (chose<=(*list)[j].run_count)
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
  
  return srvcount;

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
      printf("priority=%hu\n",srv[i].priority);
      printf("weight=%hu\n",srv[i].weight);
      printf("port=%hu\n",srv[i].port);
      printf("target=%s\n",srv[i].target);
      printf("\n");
    }

  xfree(srv);

  return 0;
}
#endif /* TEST */

/*
Local Variables:
compile-command: "cc -DTEST -I.. -I../include -Wall -g -o srv srv.c -lresolv  ../tools/no-libgcrypt.o  ../jnlib/libjnlib.a"
End:
*/
