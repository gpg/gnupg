/* riscos.c -  RISC OS stuff
 *	Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG for RISC OS.
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

#ifndef __RISCOS__C__
#define __RISCOS__C__

#include <config.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <kernel.h>
#include <swis.h>
#include "util.h"
#include "memory.h"

#define __UNIXLIB_INTERNALS
#include <unixlib/swiparams.h> /* needed for MMM_TYPE_* definitions */
#undef __UNIXLIB_INTERNALS


/* RISC OS file open descriptor control list */

struct fds_item {
    int fd;
    struct fds_item *next;
};
static struct fds_item *fds_list = NULL;
static int fdlist_initialized = 0;


/* local RISC OS functions */

static int
is_read_only(const char *filename)
{
    int type, attr;
    
    if (_swix(OS_File, _INR(0,1) | _OUT(0) | _OUT(5),
              17, filename, &type, &attr))
        log_fatal("Can't get file attributes for file \"%s\"!\n", filename);
    
    if (type == 0)
        log_fatal("Can't find file \"%s\"!\n", filename);

    if (_swix(OS_File, _INR(0,1) | _IN(5), 4, filename, attr))
        return 1;

    return 0;
}

/* exported RISC OS functions */

void
riscos_global_defaults(void)
{
    __riscosify_control = __RISCOSIFY_NO_PROCESS;
    __feature_imagefs_is_file = 1;
}

int
riscos_load_module(const char *name, const char * const path[], int fatal)
{
    int i;

    /* Is module already loaded? */
    if (!_swix(OS_Module, _INR(0,1), 18, name))
        return 1;

    /* Check all the places where the module could be located */
    for (i=0; path[i]; ++i)
        if (!_swix(OS_Module, _INR(0,1), 1, path[i]))
            return 1;

    /* Can't find module in the default locations */
    if (fatal)
        log_fatal("Operation cannot be performed without \"%s\" module!\n",
                  name);
    else
        log_info("Can't load \"%s\" module, continuing anyway!\n", name);

    return 0;
}

int
riscos_get_filetype_from_string(const char *string, int len)
{
    int result = 0xfff;

    if (strlen(string) < 5 || string[len - 4] != ',')
        return -1;

    sscanf(string+len-3, "%3x", &result);

    return result;
}

int
riscos_get_filetype(const char *filename)
{
    int result;

    if (_swix(OS_File, _INR(0,1) | _OUT(6), 23, filename, &result))
        log_fatal("Can't get filetype for file \"%s\"!\n", filename);

    return result;
}        

void
riscos_set_filetype_by_number(const char *filename, int type)
{
    if (_swix(OS_File, _INR(0,2), 18, filename, type))
        log_fatal("Can't set filetype for file \"%s\"!\n"
                  "Is the file on a read-only file system?\n", filename);
}        

void
riscos_set_filetype_by_mimetype(const char *filename, const char *mimetype)
{
    int result;

    if (_swix(MimeMap_Translate, _INR(0,2) | _OUT(3),
              MMM_TYPE_MIME, mimetype, MMM_TYPE_RISCOS, &result))
        log_fatal("Can't translate MIME type \"%s\"!\n", mimetype);

    riscos_set_filetype_by_number(filename, result);
}        

pid_t
riscos_getpid(void)
{
    int state;

    if (_swix(Wimp_ReadSysInfo, _IN(0) | _OUT(0), 3, &state))
        log_fatal("Wimp_ReadSysInfo failed: Can't get WimpState (R0=3)!\n");

    if (state)
        if (_swix(Wimp_ReadSysInfo, _IN(0) | _OUT(0), 5, &state))
            log_fatal("Wimp_ReadSysInfo failed: "
                      "Can't get task handle (R0=5)!\n");

    return (pid_t) state;
}

int
riscos_kill(pid_t pid, int sig)
{
    int buf[4], iter = 0;

    if (sig)
        kill(pid, sig);

    do {
        if (_swix(TaskManager_EnumerateTasks, _INR(0,2) | _OUT(0),
                  iter, buf, 16, &iter))
            log_fatal("TaskManager_EnumerateTasks failed!\n");
        if (buf[0] == pid)
            return 0;
    } while (iter >= 0);

    return __set_errno(ESRCH);
}

int
riscos_access(const char *path, int amode)
{
    /* Do additional check, i.e. whether path is on write-protected floppy */
    if ((amode & W_OK) && is_read_only(path))
        return 1;
    return access(path, amode);
}

int
riscos_getchar(void)
{
    int c, flags;

    if (_swix(OS_ReadC, _OUT(0) | _OUT(_FLAGS), &c, &flags))
        log_fatal("OS_ReadC failed: Couldn't read from keyboard!\n");
    if (flags & _C)
        log_fatal("OS_ReadC failed: Return Code = %i!\n", c);

    return c;
}

#ifdef DEBUG
void
riscos_dump_fdlist(void)
{
    struct fds_item *iter = fds_list;
    printf("List of open file descriptors:\n");
    while (iter) {
        printf("  %i\n", iter->fd);
        iter = iter->next;
    }
}
#endif /* DEBUG */

int
riscos_fdopenfile(const char *filename, const int allow_write)
{
    struct fds_item *h;
    int fd;
    if (allow_write)
        fd = open(filename, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    else
        fd = open(filename, O_RDONLY);
    if (fd == -1)
        log_error("Can't open file \"%s\": %i, %s!\n",
                  filename, errno, strerror(errno));

    if (!fdlist_initialized) {
        atexit (riscos_close_fds);
        fdlist_initialized = 1;
    }

    h = fds_list;
    fds_list = (struct fds_item *) m_alloc(sizeof(struct fds_item));
    if (!fds_list)
        log_fatal("Can't claim memory for fdopenfile() buffer!\n");
    fds_list->fd = fd;
    fds_list->next = h;

    return fd;
}

void
riscos_close_fds(void)
{
    FILE *fp;
    struct fds_item *h = fds_list;
    while( fds_list ) {
        h = fds_list->next;
        fp = fdopen (fds_list->fd, "a");
        if (fp)
            fflush(fp);
        close(fds_list->fd);
        m_free(fds_list);
        fds_list = h;
    }
}

int
riscos_renamefile(const char *old, const char *new)
{
    _kernel_oserror *e;

    if (e = _swix(OS_FSControl, _INR(0,2), 25, old, new)) {
        if (e->errnum == 214)
            return __set_errno(ENOENT);
        if (e->errnum == 176)
            return __set_errno(EEXIST);
        printf("Error during renaming: %i, %s!\n", e->errnum, e->errmess);
        return __set_errno(EOPSYS);
    }
    return 0;
}

char *
riscos_gstrans(const char *old)
{
    int size = 256, last;
    char *buf, *tmp;

    buf = (char *) m_alloc(size);
    if (!buf)
        log_fatal("Can't claim memory for OS_GSTrans buffer!\n");
    while (_C & _swi(OS_GSTrans, _INR(0,2) | _OUT(2) | _RETURN(_FLAGS),
                     old, buf, size, &last)) {
        size += 256;
        tmp = (char *) m_realloc(buf, size);
        if (!tmp)
             log_fatal("Can't claim memory for OS_GSTrans buffer!\n");
        buf = tmp;
    }

    buf[last] = '\0';
    tmp = (char *) m_realloc(buf, last + 1);
    if (!tmp)
        log_fatal("Can't realloc memory after OS_GSTrans!\n");

    return tmp;
}

/***************
 * Extract from a given path the filename component.
 * (cloned from util/fileutil.c and then heavily modified)
 */
char *
riscos_make_basename(const char *filepath, const char *realfname)
{
    char *result, *p = (char*)filepath-1;
    int i, filetype;

    if ( !(p=strrchr(filepath, DIRSEP_C)) )
        if ( !(p=strrchr(filepath, ':')) )
            ;

    i = strlen(p+1);
    result = m_alloc(i + 5);
    if (!result)
        log_fatal("Can't claim memory for riscos_make_basename() buffer!\n");
    strcpy(result, p+1);
    
    filetype = riscos_get_filetype( realfname );
    result[i++] = ',';
    result[i++] = "0123456789abcdef"[(filetype >> 8) & 0xf];
    result[i++] = "0123456789abcdef"[(filetype >> 4) & 0xf];
    result[i++] = "0123456789abcdef"[(filetype >> 0) & 0xf];
    result[i]   = 0;

    for(i=0; i<strlen(result); ++i)
        if(result[i] == '/')
            result[i] = '.';

    return result;
}

#define RegEx_CompilePattern         0x52AC0
#define RegEx_Search                 0x52AC2
#define RegEx_Free                   0x52AC7
#define RegEx_CompileExtendedPattern 0x52AC9

static const char * const regex_path[] = {
    "GnuPG:RegEx",
    "System:310.Modules.RegEx",
    "System:Modules.RegEx",
    NULL
};

int
riscos_check_regexp(const char *exp, const char *string, int debug)
{
    static int regex_initialized = 0;
    int ret;
    char *buf;
  
    if (!regex_initialized)
        regex_initialized = riscos_load_module("RegEx", regex_path, 0);
  
    if (!regex_initialized) {
        log_info("Regular expressions cannot be used!\n");
        return 0;
    }
  
    if (_swix(RegEx_CompileExtendedPattern, _INR(0,2) | _OUT(0) | _OUT(3),
              0, exp, 1<<18,
              &buf, &ret)) {
        log_info("RegEx could not compile pattern \"%s\".\n", exp);
        log_info("ErrorCode = %i\n", ret);
        return 0;
    }
  
    if (_swix(RegEx_Search, _INR(0,4) | _OUT(5),
              buf, string, -1, 0, -1,
              &ret)) {
        log_info("RegEx error during execution of serach pattern \"%s\"\n",
                 exp);
        log_info("on string \"%s\"\n", string);
        return 0;
    }
  
    _swix(RegEx_Free, _IN(0), buf);
  
    if(debug)
        log_debug("regexp \"%s\" on \"%s\": %s\n",exp,string,ret>=0?"YES":"NO");
  
    return (ret>=0);
}

#ifdef DEBUG
void
riscos_list_openfiles(void)
{
    char *name;
    int i, len;
    
    for (i = 255; i >= 0; --i) {
        if (_swix(OS_Args, _INR(0,2) | _IN(5) | _OUT(5), 7, i, 0, 0, &len))
            continue;

        name = (char *) m_alloc(1-len);
        if (!name)
            log_fatal("Can't claim memory for OS_Args buffer!\n");

        if (_swix(OS_Args, _INR(0,2) | _IN(5), 7, i, name, 1-len)) {
            m_free(name);
            log_fatal("Error when calling OS_Args(7)!\n");
        }
        
        if (_swix(OS_Args, _INR(0,1) | _OUT(0), 254, i, &len)) {
            m_free(name);
            log_fatal("Error when calling OS_Args(254)!\n");
        }
        
        printf("%3i: %s (%c%c)\n", i, name,
                                   (len & 0x40) ? 'R' : 0,
                                   (len & 0x80) ? 'W' : 0);
        m_free(name);
    }
}
#endif

void
riscos_not_implemented(const char *feature)
{
    log_info("%s is not implemented in the RISC OS version!\n", feature);
}

#endif /* !__RISCOS__C__ */
