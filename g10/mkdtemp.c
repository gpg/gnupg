/* This is a replacement function for mkdtemp in case the platform
   we're building on (like mine!) doesn't have it. */

#include <config.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include "types.h"
#include "cipher.h"

#ifdef MKDIR_TAKES_ONE_ARG
# undef mkdir
# define mkdir(a,b) mkdir(a)
#endif

char *mkdtemp(char *template)
{
  int attempts,idx,count=0;
  byte *ch;

  idx=strlen(template);

  if(idx==0)
    {
      errno=EINVAL;
      return NULL;
    }

  ch=&template[idx-1];

  /* Walk backwards to count all the Xes */
  while(*ch=='X' && count<idx)
    {
      count++;
      ch--;
    }

  ch++;

  if(count==0)
    {
      errno=EINVAL;
      return NULL;
    }

  /* Try 4 times to make the temp directory */
  for(attempts=0;attempts<4;attempts++)
    {
      int remaining=count;
      char *marker=ch;
      byte *randombits;

      idx=0;

      /* Using really random bits is probably overkill here.  The
	 worst thing that can happen with a directory name collision
	 is that the function will return an error. */

      randombits=get_random_bits(4*remaining,0,0);

      while(remaining>1)
	{
	  sprintf(marker,"%02X",randombits[idx++]);
	  marker+=2;
	  remaining-=2;
	}

      /* Any leftover Xes?  get_random_bits rounds up to full bytes,
         so this is safe. */
      if(remaining>0)
	sprintf(marker,"%X",randombits[idx]&0xF);

      m_free(randombits);

      if(mkdir(template,0700)==0)
	break;
    }

  if(attempts==4)
    return NULL; /* keeps the errno from mkdir, whatever it is */

  return template;
}
