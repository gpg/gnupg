/* ksutil.c - general keyserver utility functions
 * Copyright (C) 2004, 2005 Free Software Foundation, Inc.
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
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "keyserver.h"
#include "ksutil.h"

static void
catch_alarm(int foo)
{
  _exit(KEYSERVER_TIMEOUT);
}

unsigned int
set_timeout(unsigned int seconds)
{
#ifdef HAVE_DOSISH_SYSTEM
  return 0;
#else
  return alarm(seconds);
#endif
}

int
register_timeout(void)
{
#ifdef HAVE_DOSISH_SYSTEM
  return 0;
#else
#if defined(HAVE_SIGACTION) && defined(HAVE_STRUCT_SIGACTION)
  struct sigaction act;

  act.sa_handler=catch_alarm;
  sigemptyset(&act.sa_mask);
  act.sa_flags=0;
  return sigaction(SIGALRM,&act,NULL);
#else 
  if(signal(SIGALRM,catch_alarm)==SIG_ERR)
    return -1;
  else
    return 0;
#endif
#endif
}

struct ks_options *
init_ks_options(void)
{
  struct ks_options *opt;

  opt=calloc(1,sizeof(struct ks_options));

  if(opt)
    {
      opt->action=KS_UNKNOWN;
      opt->flags.check_cert=1;
      opt->timeout=DEFAULT_KEYSERVER_TIMEOUT;
    }

  return opt;
}

void
free_ks_options(struct ks_options *opt)
{
  if(opt)
    {
      free(opt->host);
      free(opt->port);
      free(opt->scheme);
      free(opt->auth);
      free(opt->path);
      free(opt->ca_cert_file);
      free(opt);
    }
}

/* Returns 0 if we "ate" the line.  Returns >0, a KEYSERVER_ error
   code if that error applies.  Returns -1 if we did not match the
   line at all. */
int
parse_ks_options(char *line,struct ks_options *opt)
{
  int version;
  char command[MAX_COMMAND+1];
  char host[MAX_HOST+1];
  char port[MAX_PORT+1];
  char scheme[MAX_SCHEME+1];
  char auth[MAX_AUTH+1];
  char path[URLMAX_PATH+1];
  char option[MAX_OPTION+1];

  if(line[0]=='#')
    return 0;

  if(sscanf(line,"COMMAND %" MKSTRING(MAX_COMMAND) "s\n",command)==1)
    {
      command[MAX_COMMAND]='\0';

      if(strcasecmp(command,"get")==0)
	opt->action=KS_GET;
      else if(strcasecmp(command,"send")==0)
	opt->action=KS_SEND;
      else if(strcasecmp(command,"search")==0)
	opt->action=KS_SEARCH;

      return 0;
    }

  if(sscanf(line,"HOST %" MKSTRING(MAX_HOST) "s\n",host)==1)
    {
      host[MAX_HOST]='\0';
      opt->host=strdup(host);
      if(!opt->host)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"PORT %" MKSTRING(MAX_PORT) "s\n",port)==1)
    {
      port[MAX_PORT]='\0';
      opt->port=strdup(port);
      if(!opt->port)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"SCHEME %" MKSTRING(MAX_SCHEME) "s\n",scheme)==1)
    {
      scheme[MAX_SCHEME]='\0';
      opt->scheme=strdup(scheme);
      if(!opt->scheme)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"AUTH %" MKSTRING(MAX_AUTH) "s\n",auth)==1)
    {
      auth[MAX_AUTH]='\0';
      opt->auth=strdup(auth);
      if(!opt->auth)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"PATH %" MKSTRING(URLMAX_PATH) "s\n",path)==1)
    {
      path[URLMAX_PATH]='\0';
      opt->path=strdup(path);
      if(!opt->path)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"VERSION %d\n",&version)==1)
    {
      if(version!=KEYSERVER_PROTO_VERSION)
	return KEYSERVER_VERSION_ERROR;

      return 0;
    }

  if(sscanf(line,"OPTION %" MKSTRING(MAX_OPTION) "[^\n]\n",option)==1)
    {
      int no=0;
      char *start=&option[0];

      option[MAX_OPTION]='\0';

      if(strncasecmp(option,"no-",3)==0)
	{
	  no=1;
	  start=&option[3];
	}

      if(strcasecmp(start,"verbose")==0)
	{
	  if(no)
	    opt->verbose--;
	  else
	    opt->verbose++;
	}
      else if(strcasecmp(start,"include-disabled")==0)
	{
	  if(no)
	    opt->flags.include_disabled=0;
	  else
	    opt->flags.include_disabled=1;
	}
      else if(strcasecmp(start,"include-revoked")==0)
	{
	  if(no)
	    opt->flags.include_revoked=0;
	  else
	    opt->flags.include_revoked=1;
	}
      else if(strcasecmp(start,"include-subkeys")==0)
	{
	  if(no)
	    opt->flags.include_subkeys=0;
	  else
	    opt->flags.include_subkeys=1;
	}
      else if(strcasecmp(start,"check-cert")==0)
	{
	  if(no)
	    opt->flags.check_cert=0;
	  else
	    opt->flags.check_cert=1;
	}
      else if(strncasecmp(start,"debug",5)==0)
	{
	  if(no)
	    opt->debug=0;
	  else if(start[5]=='=')
	    opt->debug=atoi(&start[6]);
	}
      else if(strncasecmp(start,"timeout",7)==0)
	{
	  if(no)
	    opt->timeout=0;
	  else if(start[7]=='=')
	    opt->timeout=atoi(&start[8]);
	  else if(start[7]=='\0')
	    opt->timeout=DEFAULT_KEYSERVER_TIMEOUT;
	}
      else if(strncasecmp(start,"ca-cert-file",12)==0)
	{
	  if(no)
	    {
	      free(opt->ca_cert_file);
	      opt->ca_cert_file=NULL;
	    }
	  else if(start[12]=='=')
	    {
	      free(opt->ca_cert_file);
	      opt->ca_cert_file=strdup(&start[13]);
	      if(!opt->ca_cert_file)
		return KEYSERVER_NO_MEMORY;
	    }
	}
    }

  return -1;
}

const char *
ks_action_to_string(enum ks_action action)
{
  switch(action)
    {
    case KS_UNKNOWN: return "UNKNOWN";
    case KS_GET:     return "GET";
    case KS_SEND:    return "SEND";
    case KS_SEARCH:  return "SEARCH";
    }

  return "?";
}
