/* photoid.c - photo ID handling code
 * Copyright (C) 2001, 2002, 2005, 2006, 2008, 2011 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef _WIN32
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
# ifndef VER_PLATFORM_WIN32_WINDOWS
#  define VER_PLATFORM_WIN32_WINDOWS 1
# endif
#endif

#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "../common/status.h"
#include "exec.h"
#include "keydb.h"
#include "../common/i18n.h"
#include "../common/iobuf.h"
#include "options.h"
#include "main.h"
#include "photoid.h"
#include "../common/ttyio.h"
#include "trustdb.h"

/* Generate a new photo id packet, or return NULL if canceled.
   FIXME:  Should we add a duplicates check similar to generate_user_id? */
PKT_user_id *
generate_photo_id (ctrl_t ctrl, PKT_public_key *pk,const char *photo_name)
{
  PKT_user_id *uid;
  int error=1,i;
  unsigned int len;
  char *filename;
  byte *photo=NULL;
  byte header[16];
  IOBUF file;
  int overflow;

  header[0]=0x10; /* little side of photo header length */
  header[1]=0;    /* big side of photo header length */
  header[2]=1;    /* 1 == version of photo header */
  header[3]=1;    /* 1 == JPEG */

  for(i=4;i<16;i++) /* The reserved bytes */
    header[i]=0;

#define EXTRA_UID_NAME_SPACE 71
  uid=xmalloc_clear(sizeof(*uid)+71);

  if(photo_name && *photo_name)
    filename=make_filename(photo_name,(void *)NULL);
  else
    {
      tty_printf(_("\nPick an image to use for your photo ID."
		   "  The image must be a JPEG file.\n"
		   "Remember that the image is stored within your public key."
		   "  If you use a\n"
		   "very large picture, your key will become very large"
		   " as well!\n"
		   "Keeping the image close to 240x288 is a good size"
		   " to use.\n"));
      filename=NULL;
    }

  while(photo==NULL)
    {
      if(filename==NULL)
	{
	  char *tempname;

	  tty_printf("\n");

	  tty_enable_completion(NULL);

	  tempname=cpr_get("photoid.jpeg.add",
			   _("Enter JPEG filename for photo ID: "));

	  tty_disable_completion();

	  filename=make_filename(tempname,(void *)NULL);

	  xfree(tempname);

	  if(strlen(filename)==0)
	    goto scram;
	}

      file=iobuf_open(filename);
      if (file && is_secured_file (iobuf_get_fd (file)))
        {
          iobuf_close (file);
          file = NULL;
          gpg_err_set_errno (EPERM);
        }
      if(!file)
	{
	  log_error(_("unable to open JPEG file '%s': %s\n"),
		    filename,strerror(errno));
	  xfree(filename);
	  filename=NULL;
	  continue;
	}


      len=iobuf_get_filelength(file, &overflow);
      if(len>6144 || overflow)
	{
	  tty_printf( _("This JPEG is really large (%d bytes) !\n"),len);
	  if(!cpr_get_answer_is_yes("photoid.jpeg.size",
			    _("Are you sure you want to use it? (y/N) ")))
	  {
	    iobuf_close(file);
	    xfree(filename);
	    filename=NULL;
	    continue;
	  }
	}

      photo=xmalloc(len);
      iobuf_read(file,photo,len);
      iobuf_close(file);

      /* Is it a JPEG? */
      if(photo[0]!=0xFF || photo[1]!=0xD8)
	{
	  log_error(_("'%s' is not a JPEG file\n"),filename);
	  xfree(photo);
	  photo=NULL;
	  xfree(filename);
	  filename=NULL;
	  continue;
	}

      /* Build the packet */
      build_attribute_subpkt(uid,1,photo,len,header,16);
      parse_attribute_subpkts(uid);
      make_attribute_uidname(uid, EXTRA_UID_NAME_SPACE);

      /* Showing the photo is not safe when noninteractive since the
         "user" may not be able to dismiss a viewer window! */
      if(opt.command_fd==-1)
	{
	  show_photos (ctrl, uid->attribs, uid->numattribs, pk, uid);
	  switch(cpr_get_answer_yes_no_quit("photoid.jpeg.okay",
					 _("Is this photo correct (y/N/q)? ")))
	    {
	    case -1:
	      goto scram;
	    case 0:
	      free_attributes(uid);
	      xfree(photo);
	      photo=NULL;
	      xfree(filename);
	      filename=NULL;
	      continue;
	    }
	}
    }

  error=0;
  uid->ref=1;

 scram:
  xfree(filename);
  xfree(photo);

  if(error)
    {
      free_attributes(uid);
      xfree(uid);
      return NULL;
    }

  return uid;
}

/* Returns 0 for error, 1 for valid */
int parse_image_header(const struct user_attribute *attr,byte *type,u32 *len)
{
  u16 headerlen;

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
   make sure it is not too big (see parse-packet.c:parse_attribute).
   Extensions should be 3 characters long for the best cross-platform
   compatibility. */
const char *
image_type_to_string(byte type,int style)
{
  const char *string;

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

#if !defined(FIXED_PHOTO_VIEWER) && !defined(DISABLE_PHOTO_VIEWER)
static const char *
get_default_photo_command(void)
{
#if defined(_WIN32)
  OSVERSIONINFO osvi;

  memset(&osvi,0,sizeof(osvi));
  osvi.dwOSVersionInfoSize=sizeof(osvi);
  GetVersionEx(&osvi);

  if(osvi.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS)
    return "start /w %i";
  else
    return "!ShellExecute 400 %i";
#elif defined(__APPLE__)
  /* OS X.  This really needs more than just __APPLE__. */
  return "open %I";
#elif defined(__riscos__)
  return "Filer_Run %I";
#else
  if (!path_access ("xloadimage", X_OK))
    return "xloadimage -fork -quiet -title 'KeyID 0x%k' stdin";
  else if (!path_access ("display",X_OK))
    return "display -title 'KeyID 0x%k' %i";
  else if (getuid () && !path_access ("xdg-open", X_OK))
    return "xdg-open %i";
  else
    return "/bin/true";
#endif
}
#endif

#ifndef DISABLE_PHOTO_VIEWER
struct exec_info
{
  int progreturn;
  struct
  {
    unsigned int binary:1;
    unsigned int writeonly:1;
    unsigned int madedir:1;
    unsigned int use_temp_files:1;
    unsigned int keep_temp_files:1;
  } flags;
  pid_t child;
  FILE *tochild;
  iobuf_t fromchild;
  char *command,*name,*tempdir,*tempfile_in,*tempfile_out;
};

#ifdef NO_EXEC
static int
exec_write(struct exec_info **info,const char *program,
	       const char *args_in,const char *name,int writeonly,int binary)
{
  log_error(_("no remote program execution supported\n"));
  return GPG_ERR_GENERAL;
}

static int
exec_read(struct exec_info *info) { return GPG_ERR_GENERAL; }

static int
exec_finish(struct exec_info *info) { return GPG_ERR_GENERAL; }

#else /* ! NO_EXEC */
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef EXEC_TEMPFILE_ONLY
#include <sys/wait.h>
#endif
#include <fcntl.h>
#include <errno.h>

#include "../common/membuf.h"
#include "../common/sysutils.h"

/* Makes a temp directory and filenames */
static int
make_tempdir(struct exec_info *info)
{
  char *tmp=opt.temp_dir,*namein=info->name,*nameout;

  if(!namein)
    namein=info->flags.binary?"tempin" EXTSEP_S "bin":"tempin" EXTSEP_S "txt";

  nameout=info->flags.binary?"tempout" EXTSEP_S "bin":"tempout" EXTSEP_S "txt";

  /* Make up the temp dir and files in case we need them */

  if(tmp==NULL)
    {
#if defined (_WIN32)
      int err;

      tmp=xmalloc(MAX_PATH+2);
      err=GetTempPath(MAX_PATH+1,tmp);
      if(err==0 || err>MAX_PATH+1)
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

  info->tempdir=xmalloc(strlen(tmp)+strlen(DIRSEP_S)+10+1);

  sprintf(info->tempdir,"%s" DIRSEP_S "gpg-XXXXXX",tmp);

#if defined (_WIN32)
  xfree(tmp);
#endif

  if (!gnupg_mkdtemp(info->tempdir))
    log_error(_("can't create directory '%s': %s\n"),
	      info->tempdir,strerror(errno));
  else
    {
      info->flags.madedir=1;

      info->tempfile_in=xmalloc(strlen(info->tempdir)+
				strlen(DIRSEP_S)+strlen(namein)+1);
      sprintf(info->tempfile_in,"%s" DIRSEP_S "%s",info->tempdir,namein);

      if(!info->flags.writeonly)
	{
	  info->tempfile_out=xmalloc(strlen(info->tempdir)+
				     strlen(DIRSEP_S)+strlen(nameout)+1);
	  sprintf(info->tempfile_out,"%s" DIRSEP_S "%s",info->tempdir,nameout);
	}
    }

  return info->flags.madedir? 0 : GPG_ERR_GENERAL;
}

/* Expands %i and %o in the args to the full temp files within the
   temp directory. */
static int
expand_args(struct exec_info *info,const char *args_in)
{
  const char *ch = args_in;
  membuf_t command;

  info->flags.use_temp_files=0;
  info->flags.keep_temp_files=0;

  if(DBG_EXTPROG)
    log_debug("expanding string \"%s\"\n",args_in);

  init_membuf (&command, 100);

  while(*ch!='\0')
    {
      if(*ch=='%')
	{
	  char *append=NULL;

	  ch++;

	  switch(*ch)
	    {
	    case 'O':
	      info->flags.keep_temp_files=1;
	      /* fall through */

	    case 'o': /* out */
	      if(!info->flags.madedir)
		{
		  if(make_tempdir(info))
		    goto fail;
		}
	      append=info->tempfile_out;
	      info->flags.use_temp_files=1;
	      break;

	    case 'I':
	      info->flags.keep_temp_files=1;
	      /* fall through */

	    case 'i': /* in */
	      if(!info->flags.madedir)
		{
		  if(make_tempdir(info))
		    goto fail;
		}
	      append=info->tempfile_in;
	      info->flags.use_temp_files=1;
	      break;

	    case '%':
	      append="%";
	      break;
	    }

	  if(append)
            put_membuf_str (&command, append);
	}
      else
        put_membuf (&command, ch, 1);

      ch++;
    }

  put_membuf (&command, "", 1);  /* Terminate string.  */

  info->command = get_membuf (&command, NULL);
  if (!info->command)
    return gpg_error_from_syserror ();

  if(DBG_EXTPROG)
    log_debug("args expanded to \"%s\", use %u, keep %u\n",info->command,
	      info->flags.use_temp_files,info->flags.keep_temp_files);

  return 0;

 fail:
  xfree (get_membuf (&command, NULL));
  return GPG_ERR_GENERAL;
}

/* Either handles the tempfile creation, or the fork/exec.  If it
   returns ok, then info->tochild is a FILE * that can be written to.
   The rules are: if there are no args, then it's a fork/exec/pipe.
   If there are args, but no tempfiles, then it's a fork/exec/pipe via
   shell -c.  If there are tempfiles, then it's a system. */

static int
exec_write(struct exec_info **info,const char *program,
           const char *args_in,const char *name,int writeonly,int binary)
{
  int ret = GPG_ERR_GENERAL;

  if(opt.exec_disable && !opt.no_perm_warn)
    {
      log_info(_("external program calls are disabled due to unsafe "
		 "options file permissions\n"));

      return ret;
    }

#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
  /* There should be no way to get to this spot while still carrying
     setuid privs.  Just in case, bomb out if we are. */
  if ( getuid () != geteuid ())
    BUG ();
#endif

  if(program==NULL && args_in==NULL)
    BUG();

  *info=xmalloc_clear(sizeof(struct exec_info));

  if(name)
    (*info)->name=xstrdup(name);
  (*info)->flags.binary=binary;
  (*info)->flags.writeonly=writeonly;

  /* Expand the args, if any */
  if(args_in && expand_args(*info,args_in))
    goto fail;

#ifdef EXEC_TEMPFILE_ONLY
  if(!(*info)->flags.use_temp_files)
    {
      log_error(_("this platform requires temporary files when calling"
		  " external programs\n"));
      goto fail;
    }

#else /* !EXEC_TEMPFILE_ONLY */

  /* If there are no args, or there are args, but no temp files, we
     can use fork/exec/pipe */
  if(args_in==NULL || (*info)->flags.use_temp_files==0)
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
	  if(!(*info)->flags.writeonly)
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
	      if(DBG_EXTPROG)
		log_debug("execlp: %s\n",program);

	      execlp(program,program,(void *)NULL);
	    }
	  else
	    {
	      if(DBG_EXTPROG)
		log_debug("execlp: %s -c %s\n",shell,(*info)->command);

	      execlp(shell,shell,"-c",(*info)->command,(void *)NULL);
	    }

	  /* If we get this far the exec failed.  Clean up and return. */

	  if(args_in==NULL)
	    log_error(_("unable to execute program '%s': %s\n"),
		      program,strerror(errno));
	  else
	    log_error(_("unable to execute shell '%s': %s\n"),
		      shell,strerror(errno));

	  /* This mimics the POSIX sh behavior - 127 means "not found"
             from the shell. */
	  if(errno==ENOENT)
	    _exit(127);

	  _exit(1);
	}

      /* I'm the parent */

      close(to[0]);

      (*info)->tochild=fdopen(to[1],binary?"wb":"w");
      if((*info)->tochild==NULL)
	{
          ret = gpg_error_from_syserror ();
	  close(to[1]);
	  goto fail;
	}

      close(from[1]);

      (*info)->fromchild=iobuf_fdopen(from[0],"r");
      if((*info)->fromchild==NULL)
	{
          ret = gpg_error_from_syserror ();
	  close(from[0]);
	  goto fail;
	}

      /* fd iobufs are cached! */
      iobuf_ioctl((*info)->fromchild, IOBUF_IOCTL_NO_CACHE, 1, NULL);

      return 0;
    }
#endif /* !EXEC_TEMPFILE_ONLY */

  if(DBG_EXTPROG)
    log_debug("using temp file '%s'\n",(*info)->tempfile_in);

  /* It's not fork/exec/pipe, so create a temp file */
  if( is_secured_filename ((*info)->tempfile_in) )
    {
      (*info)->tochild = NULL;
      gpg_err_set_errno (EPERM);
    }
  else
    (*info)->tochild=fopen((*info)->tempfile_in,binary?"wb":"w");
  if((*info)->tochild==NULL)
    {
      ret = gpg_error_from_syserror ();
      log_error(_("can't create '%s': %s\n"),
		(*info)->tempfile_in,strerror(errno));
      goto fail;
    }

  ret=0;

 fail:
  if (ret)
    {
      xfree (*info);
      *info = NULL;
    }
  return ret;
}

static int
exec_read(struct exec_info *info)
{
  int ret = GPG_ERR_GENERAL;

  fclose(info->tochild);
  info->tochild=NULL;

  if(info->flags.use_temp_files)
    {
      if(DBG_EXTPROG)
	log_debug ("running command: %s\n",info->command);

#if defined (_WIN32)
      info->progreturn=w32_system(info->command);
#else
      info->progreturn=system(info->command);
#endif

      if(info->progreturn==-1)
	{
	  log_error(_("system error while calling external program: %s\n"),
		    strerror(errno));
	  info->progreturn=127;
	  goto fail;
	}

#if defined(WIFEXITED) && defined(WEXITSTATUS)
      if(WIFEXITED(info->progreturn))
	info->progreturn=WEXITSTATUS(info->progreturn);
      else
	{
	  log_error(_("unnatural exit of external program\n"));
	  info->progreturn=127;
	  goto fail;
	}
#else
      /* If we don't have the macros, do the best we can. */
      info->progreturn = (info->progreturn & 0xff00) >> 8;
#endif

      /* 127 is the magic value returned from system() to indicate
         that the shell could not be executed, or from /bin/sh to
         indicate that the program could not be executed. */

      if(info->progreturn==127)
	{
	  log_error(_("unable to execute external program\n"));
	  goto fail;
	}

      if(!info->flags.writeonly)
	{
	  info->fromchild=iobuf_open(info->tempfile_out);
          if (info->fromchild
              && is_secured_file (iobuf_get_fd (info->fromchild)))
            {
              iobuf_close (info->fromchild);
              info->fromchild = NULL;
              gpg_err_set_errno (EPERM);
            }
	  if(info->fromchild==NULL)
	    {
              ret = gpg_error_from_syserror ();
	      log_error(_("unable to read external program response: %s\n"),
			strerror(errno));
	      goto fail;
	    }

	  /* Do not cache this iobuf on close */
	  iobuf_ioctl(info->fromchild, IOBUF_IOCTL_NO_CACHE, 1, NULL);
	}
    }

  ret=0;

 fail:
  return ret;
}

static int
exec_finish(struct exec_info *info)
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
	{
	  log_error(_("unnatural exit of external program\n"));
	  ret=127;
	}
    }
#endif

  if(info->flags.madedir && !info->flags.keep_temp_files)
    {
      if(info->tempfile_in)
	{
	  if(unlink(info->tempfile_in)==-1)
	    log_info(_("WARNING: unable to remove tempfile (%s) '%s': %s\n"),
		     "in",info->tempfile_in,strerror(errno));
	}

      if(info->tempfile_out)
	{
	  if(unlink(info->tempfile_out)==-1)
	    log_info(_("WARNING: unable to remove tempfile (%s) '%s': %s\n"),
		     "out",info->tempfile_out,strerror(errno));
	}

      if(rmdir(info->tempdir)==-1)
	log_info(_("WARNING: unable to remove temp directory '%s': %s\n"),
		 info->tempdir,strerror(errno));
    }

  xfree(info->command);
  xfree(info->name);
  xfree(info->tempdir);
  xfree(info->tempfile_in);
  xfree(info->tempfile_out);
  xfree(info);

  return ret;
}
#endif
#endif


void
show_photos (ctrl_t ctrl, const struct user_attribute *attrs, int count,
             PKT_public_key *pk, PKT_user_id *uid)
{
#ifdef DISABLE_PHOTO_VIEWER
  (void)attrs;
  (void)count;
  (void)pk;
  (void)uid;
#else /*!DISABLE_PHOTO_VIEWER*/
  int i;
  struct expando_args args;
  u32 len;
  u32 kid[2]={0,0};

  memset (&args, 0, sizeof(args));
  args.pk = pk;
  args.validity_info = get_validity_info (ctrl, NULL, pk, uid);
  args.validity_string = get_validity_string (ctrl, pk, uid);
  namehash_from_uid (uid);
  args.namehash = uid->namehash;

  if (pk)
    keyid_from_pk (pk, kid);

  es_fflush (es_stdout);

  for(i=0;i<count;i++)
    if(attrs[i].type==ATTRIB_IMAGE &&
       parse_image_header(&attrs[i],&args.imagetype,&len))
      {
	char *command,*name;
	struct exec_info *spawn;
	int offset=attrs[i].len-len;

#ifdef FIXED_PHOTO_VIEWER
	opt.photo_viewer=FIXED_PHOTO_VIEWER;
#else
	if(!opt.photo_viewer)
	  opt.photo_viewer=get_default_photo_command();
#endif

	/* make command grow */
	command=pct_expando(opt.photo_viewer,&args);
	if(!command)
	  goto fail;

	name=xmalloc(16+strlen(EXTSEP_S)+
		     strlen(image_type_to_string(args.imagetype,0))+1);

	/* Make the filename.  Notice we are not using the image
           encoding type for more than cosmetics.  Most external image
           viewers can handle a multitude of types, and even if one
           cannot understand a particular type, we have no way to know
           which.  The spec permits this, by the way. -dms */

#ifdef USE_ONLY_8DOT3
	sprintf(name,"%08lX" EXTSEP_S "%s",(ulong)kid[1],
		image_type_to_string(args.imagetype,0));
#else
	sprintf(name,"%08lX%08lX" EXTSEP_S "%s",(ulong)kid[0],(ulong)kid[1],
		image_type_to_string(args.imagetype,0));
#endif

	if(exec_write(&spawn,NULL,command,name,1,1)!=0)
	  {
	    xfree(name);
	    goto fail;
	  }

#ifdef __riscos__
        riscos_set_filetype_by_mimetype(spawn->tempfile_in,
                                        image_type_to_string(args.imagetype,2));
#endif

	xfree(name);

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
  log_error(_("unable to display photo ID!\n"));
#endif /*!DISABLE_PHOTO_VIEWER*/
}
