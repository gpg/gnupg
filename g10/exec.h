#ifndef _EXEC_H_
#define _EXEC_H_

#include <unistd.h>
#include <stdio.h>
#include "iobuf.h"

struct exec_info
{
  int progreturn,binary,writeonly,madedir,use_temp_files,keep_temp_files;
  pid_t child;
  FILE *tochild;
  IOBUF fromchild;
  char *command,*name,*tempdir,*tempfile_in,*tempfile_out;
};

int exec_write(struct exec_info **info,const char *program,
	       const char *args_in,const char *name,int writeonly,int binary);
int exec_read(struct exec_info *info);
int exec_finish(struct exec_info *info);
int set_exec_path(const char *path,int method);

#endif /* !_EXEC_H_ */
