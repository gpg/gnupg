/* exec.c - generic call-a-program code
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
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef EXEC_TEMPFILE_ONLY
#include <sys/wait.h>
#endif
#ifdef HAVE_DOSISH_SYSTEM
#include <windows.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "options.h"
#include "memory.h"
#include "i18n.h"
#include "iobuf.h"
#include "util.h"
#include "exec.h"

#ifdef NO_EXEC
int exec_write(struct exec_info **info,const char *program,
	       const char *args_in,int writeonly,int binary)
{
  log_error(_("no remote program execution supported\n"));
  return G10ERR_GENERAL;
}

int exec_read(struct exec_info *info) { return G10ERR_GENERAL; }
int exec_finish(struct exec_info *info) { return G10ERR_GENERAL; }

#else /* ! NO_EXEC */

#ifndef HAVE_MKDTEMP
char *mkdtemp(char *template);
#endif

/* Makes a temp directory and filenames */
static int make_tempdir(struct exec_info *info)
{
  char *tmp=opt.temp_dir,*name=info->name;

  if(!name)
    name=info->binary?"tempfile" EXTSEP_S "bin":"tempfile" EXTSEP_S "txt";

  /* Make up the temp dir and files in case we need them */

  if(tmp==NULL)
    {
#if defined (__MINGW32__) || defined (__CYGWIN32__)
      tmp=m_alloc(256);
      if(GetTempPath(256,tmp)==0)
	strcpy(tmp,"c:\\windows\\temp");
      else
	{
	  int len=strlen(tmp);

	  /* GetTempPath may return with \ on the end */
	  while(len>0 && tmp[len-1]=='\\')
	    {
	      tmp[len-1]='\0';
	      len--;
	    }
	}
#else /* More unixish systems */
      tmp=getenv("TMPDIR");
      if(tmp==NULL)
	{
	  tmp=getenv("TMP");
	  if(tmp==NULL)
	    {
#ifdef __riscos__
	      tmp="<Wimp$ScrapDir>.GnuPG";
	      mkdir(tmp,0700); /* Error checks occur later on */
#else
	      tmp="/tmp";
#endif
	    }
	}
#endif
    }

  info->tempdir=m_alloc(strlen(tmp)+strlen(DIRSEP_S)+10+1);

  sprintf(info->tempdir,"%s" DIRSEP_S "gpg-XXXXXX",tmp);

#if defined (__MINGW32__) || defined (__CYGWIN32__)
  m_free(tmp);
#endif

  if(mkdtemp(info->tempdir)==NULL)
    log_error(_("%s: can't create directory: %s\n"),
	      info->tempdir,strerror(errno));
  else
    {
      info->madedir=1;

      info->tempfile_in=m_alloc(strlen(info->tempdir)+
				strlen(DIRSEP_S)+strlen(name)+1);
      sprintf(info->tempfile_in,"%s" DIRSEP_S "%s",info->tempdir,name);

      if(!info->writeonly)
	{
	  info->tempfile_out=m_alloc(strlen(info->tempdir)+
				     strlen(DIRSEP_S)+strlen(name)+1);
	  sprintf(info->tempfile_out,"%s" DIRSEP_S "%s",info->tempdir,name);
	}
    }

  return info->madedir?0:G10ERR_GENERAL;
}

/* Expands %i and %o in the args to the full temp files within the
   temp directory. */
static int expand_args(struct exec_info *info,const char *args_in)
{
  const char *ch=args_in;
  int size,len;

  info->use_temp_files=0;
  info->keep_temp_files=0;

  size=100;
  info->command=m_alloc(size);
  len=0;
  info->command[0]='\0';

  while(*ch!='\0')
    {
      if(*ch=='%')
	{
	  char *append=NULL;

	  ch++;

	  switch(*ch)
	    {
	    case 'O':
	      info->keep_temp_files=1;
	      /* fall through */

	    case 'o': /* out */
	      if(!info->madedir)
		{
		  if(make_tempdir(info))
		    goto fail;
		}
	      append=info->tempfile_out;
	      info->use_temp_files=1;
	      break;

	    case 'I':
	      info->keep_temp_files=1;
	      /* fall through */

	    case 'i': /* in */
	      if(!info->madedir)
		{
		  if(make_tempdir(info))
		    goto fail;
		}
	      append=info->tempfile_in;
	      info->use_temp_files=1;
	      break;

	    case '%':
	      append="%";
	      break;
	    }

	  if(append)
	    {
	      while(strlen(append)+len>size-1)
		{
		  size+=100;
		  info->command=m_realloc(info->command,size);
		}

	      strcat(info->command,append);
	      len+=strlen(append);
	    }
	}
      else
	{
	  if(len==size-1) /* leave room for the \0 */
	    {
	      size+=100;
	      info->command=m_realloc(info->command,size);
	    }

	  info->command[len++]=*ch;
	  info->command[len]='\0';
	}

      ch++;
    }

  /* printf("args expanded to \"%s\"\n",info->command); */

  return 0;

 fail:

  m_free(info->command);
  info->command=NULL;

  return G10ERR_GENERAL;
}

/* Either handles the tempfile creation, or the fork/exec.  If it
   returns ok, then info->tochild is a FILE * that can be written to.
   The rules are: if there are no args, then it's a fork/exec/pipe.
   If there are args, but no tempfiles, then it's a fork/exec/pipe via
   shell -c.  If there are tempfiles, then it's a system. */

int exec_write(struct exec_info **info,const char *program,
	       const char *args_in,const char *name,int writeonly,int binary)
{
  int ret=G10ERR_GENERAL;

  if(opt.exec_disable && !opt.no_perm_warn)
    {
      log_info(_("external program calls are disabled due to unsafe "
		 "options file permissions\n"));

      return ret;
    }

#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
  /* There should be no way to get to this spot while still carrying
     setuid privs.  Just in case, bomb out if we are. */
  if(getuid()!=geteuid())
    BUG();
#endif

  if(program==NULL && args_in==NULL)
    BUG();

  *info=m_alloc_clear(sizeof(struct exec_info));

  if(name)
    (*info)->name=m_strdup(name);
  (*info)->binary=binary;
  (*info)->writeonly=writeonly;

  /* Expand the args, if any */
  if(args_in && expand_args(*info,args_in))
    goto fail;

#ifdef EXEC_TEMPFILE_ONLY
  if(!(*info)->use_temp_files)
    {
      log_error(_("this platform requires temp files when calling external "
		  "programs\n"));
      goto fail;
    }

#else /* !EXEC_TEMPFILE_ONLY */

  /* If there are no args, or there are args, but no temp files, we
     can use fork/exec/pipe */
  if(args_in==NULL || (*info)->use_temp_files==0)
    {
      int to[2],from[2];

      if(pipe(to)==-1)
	goto fail;

      if(pipe(from)==-1)
	{
	  close(to[0]);
	  close(to[1]);
	  goto fail;
	}

      if(((*info)->child=fork())==-1)
	{
	  close(to[0]);
	  close(to[1]);
	  close(from[0]);
	  close(from[1]);
	  goto fail;
	}

      if((*info)->child==0)
	{
	  char *shell=getenv("SHELL");

	  if(shell==NULL)
	    shell="/bin/sh";

	  /* I'm the child */

	  /* If the program isn't going to respond back, they get to
             keep their stdout/stderr */
	  if(!(*info)->writeonly)
	    {
	      /* implied close of STDERR */
	      if(dup2(STDOUT_FILENO,STDERR_FILENO)==-1)
		_exit(1);

	      /* implied close of STDOUT */
	      close(from[0]);
	      if(dup2(from[1],STDOUT_FILENO)==-1)
		_exit(1);
	    }

	  /* implied close of STDIN */
	  close(to[1]);
	  if(dup2(to[0],STDIN_FILENO)==-1)
	    _exit(1);

	  if(args_in==NULL)
	    {
	      /* fprintf(stderr,"execing: %s\n",program); */
	      execlp(program,program,NULL);
	    }
	  else
	    {
	      /* fprintf(stderr,"execing: %s -c %s\n",shell,(*info)->command); */
	      execlp(shell,shell,"-c",(*info)->command,NULL);
	    }

	  /* If we get this far the exec failed.  Clean up and return. */

	  log_error(_("unable to execute %s \"%s\": %s\n"),
		    args_in==NULL?"program":"shell",
		    args_in==NULL?program:shell,
		    strerror(errno));

	  if(errno==ENOENT)
	    _exit(127);

	  _exit(1);
	}

      /* I'm the parent */

      close(to[0]);

      (*info)->tochild=fdopen(to[1],binary?"wb":"w");
      if((*info)->tochild==NULL)
	{
	  close(to[1]);
	  ret=G10ERR_WRITE_FILE;
	  goto fail;
	}

      close(from[1]);

      (*info)->fromchild=iobuf_fdopen(from[0],"r");
      if((*info)->fromchild==NULL)
	{
	  close(from[0]);
	  ret=G10ERR_READ_FILE;
	  goto fail;
	}

      /* fd iobufs are cached?! */
      iobuf_ioctl((*info)->fromchild,3,1,NULL);

      return 0;
    }
#endif /* !EXEC_TEMPFILE_ONLY */

  /* It's not fork/exec/pipe, so create a temp file */
  (*info)->tochild=fopen((*info)->tempfile_in,binary?"wb":"w");
  if((*info)->tochild==NULL)
    {
      log_error(_("%s: can't create: %s\n"),
		(*info)->tempfile_in,strerror(errno));
      ret=G10ERR_WRITE_FILE;
      goto fail;
    }

  ret=0;

 fail:
  return ret;
}

int exec_read(struct exec_info *info)
{
  int ret=G10ERR_GENERAL;

  fclose(info->tochild);
  info->tochild=NULL;

  if(info->use_temp_files)
    {
      /* printf("system command is %s\n",info->command); */

      info->progreturn=system(info->command);

      if(info->progreturn==-1)
	{
	  log_error(_("system error while calling external program: %s\n"),
		    strerror(errno));
	  info->progreturn=127;
	  goto fail;
	}
      else
	{
#ifdef WEXITSTATUS
	  info->progreturn=WEXITSTATUS(info->progreturn);
#else
	  info->progreturn/=256;
#endif
	}

      /* 127 is the magic value returned from system() to indicate
         that the shell could not be executed, or from /bin/sh to
         indicate that the program could not be executed. */

      if(info->progreturn==127)
	{
	  log_error(_("unable to execute external program\n"));
	  goto fail;
	}

      if(!info->writeonly)
	{
	  info->fromchild=iobuf_open(info->tempfile_out);
	  if(info->fromchild==NULL)
	    {
	      log_error(_("unable to read external program response: %s\n"),
			strerror(errno));
	      ret=G10ERR_READ_FILE;
	      goto fail;
	    }

	  /* Do not cache this iobuf on close */
	  iobuf_ioctl(info->fromchild,3,1,NULL);
	}
    }

  ret=0;

 fail:
  return ret;
}

int exec_finish(struct exec_info *info)
{
  int ret=info->progreturn;

  if(info->fromchild)
    iobuf_close(info->fromchild);

  if(info->tochild)
    fclose(info->tochild);

#ifndef EXEC_TEMPFILE_ONLY
  if(info->child>0)
    {
      if(waitpid(info->child,&info->progreturn,0)!=0 &&
	 WIFEXITED(info->progreturn))
	ret=WEXITSTATUS(info->progreturn);
      else
	ret=127;
    }
#endif

  if(info->madedir && !info->keep_temp_files)
    {
      if(info->tempfile_in)
	{
	  if(unlink(info->tempfile_in)==-1)
	    log_info(_("Warning: unable to remove tempfile (%s) \"%s\": %s\n"),
		     "in",info->tempfile_in,strerror(errno));
	}
  
      if(info->tempfile_out)
	{
	  if(unlink(info->tempfile_out)==-1)
	    log_info(_("Warning: unable to remove tempfile (%s) \"%s\": %s\n"),
		     "out",info->tempfile_out,strerror(errno));
	}

      if(rmdir(info->tempdir)==-1)
	log_info(_("Warning: unable to remove temp directory \"%s\": %s\n"),
		 info->tempdir,strerror(errno));
    }

  m_free(info->command);
  m_free(info->name);
  m_free(info->tempdir);
  m_free(info->tempfile_in);
  m_free(info->tempfile_out);
  m_free(info);

  return ret;
}
#endif /* ! NO_EXEC */
