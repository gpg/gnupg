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
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <kernel.h>
#include <swis.h>
#include "util.h"
#include "memory.h"

#define __UNIXLIB_INTERNALS
#include <unixlib/unix.h>
#undef __UNIXLIB_INTERNALS

/* RISC OS file open descriptor control list */

struct fds_item {
    int fd;
    struct fds_item *next;
};
static struct fds_item *fds_list = NULL;
static int initialized = 0;


/* local RISC OS functions */

static int
is_read_only(const char *filename)
{
    _kernel_swi_regs r;
    
    r.r[0] = 17;
    r.r[1] = (int) filename;
    
    if (_kernel_swi(OS_File, &r, &r))
        log_fatal("Can't get file attributes for %s!\n", filename);
    
    if (r.r[0] == 0)
        log_fatal("Can't find file %s!\n", filename);

    r.r[0] = 4;
    if (_kernel_swi(OS_File, &r, &r))
        return 1;

    return 0;
}


/* exported RISC OS functions */

pid_t
riscos_getpid(void)
{
    _kernel_swi_regs r;

    r.r[0] = 3;
    if (_kernel_swi(Wimp_ReadSysInfo, &r, &r))
        log_fatal("Wimp_ReadSysInfo failed: Can't get WimpState (R0=3)!\n");

    if (!r.r[0])
        return (pid_t) 0;

    r.r[0] = 5;
    if (_kernel_swi(Wimp_ReadSysInfo, &r, &r))
        log_fatal("Wimp_ReadSysInfo failed: Can't get task handle (R0=5)!\n");

    return (pid_t) r.r[0];
}

int
riscos_kill(pid_t pid, int sig)
{
    _kernel_swi_regs r;
    int buf[4];

    if (sig)
        kill(pid, sig);

    r.r[0] = 0;
    do {
        r.r[1] = (int) buf;
        r.r[2] = 16;
        if (_kernel_swi(TaskManager_EnumerateTasks, &r, &r))
            log_fatal("TaskManager_EnumerateTasks failed!\n");
        if (buf[0] == pid)
            return 0;
    } while (r.r[0] >= 0);

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

#ifdef DEBUG
void
dump_fdlist(void)
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
fdopenfile(const char *filename, const int allow_write)
{
    struct fds_item *h;
    int fd;
    if (allow_write)
        fd = open(filename, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    else
        fd = open(filename, O_RDONLY);
    if (fd == -1)
        log_error("Can't open file %s: %i, %s!\n", filename, errno, strerror(errno));

    if (!initialized) {
        atexit (close_fds);
        initialized = 1;
    }

    h = fds_list;
    fds_list = (struct fds_item *) m_alloc(sizeof(struct fds_item));
    fds_list->fd = fd;
    fds_list->next = h;

    return fd;
}

void
close_fds(void)
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
renamefile(const char *old, const char *new)
{
    _kernel_swi_regs r;
    _kernel_oserror *e;

    r.r[0] = 25;
    r.r[1] = (int) old;
    r.r[2] = (int) new;
    if (e = _kernel_swi(OS_FSControl, &r, &r)) {
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
gstrans(const char *old)
{
    _kernel_swi_regs r;
    int c = 0;
    int size = 256;
    char *buf, *tmp;

    buf = (char *) m_alloc(size);
    if (!buf)
        log_fatal("Can't claim memory for OS_GSTrans buffer!\n");
    do {
        r.r[0] = (int) old;
        r.r[1] = (int) buf;
        r.r[2] = size;
        _kernel_swi_c(OS_GSTrans, &r, &r, &c);
        if (c) {
            size += 256;
            tmp = (char *) m_realloc(buf, size);
            if (!tmp)
                 log_fatal("Can't claim memory for OS_GSTrans buffer!\n");
            buf = tmp;
        }
    } while (c);

    buf[r.r[2]] = '\0';
    tmp = (char *) m_realloc(buf, r.r[2] + 1);
    if (!tmp)
        log_fatal("Can't realloc memory after OS_GSTrans!\n");

    return tmp;
}

#ifdef DEBUG
void
list_openfiles(void)
{
    _kernel_swi_regs r;
    char *name;
    int i;
    
    for (i = 255; i >= 0; --i) {
        r.r[0] = 7;
        r.r[1] = i;
        r.r[2] = 0;
        r.r[5] = 0;
        if (_kernel_swi(OS_Args, &r, &r))
            continue;

        name = (char *) m_alloc(1-r.r[5]);
        if (!name)
            log_fatal("Can't claim memory for OS_Args buffer!\n");

        r.r[0] = 7;
        r.r[1] = i;
        r.r[2] = (int) name;
        r.r[5] = 1-r.r[5];
        if (_kernel_swi(OS_Args, &r, &r)) {
            m_free(name);
            log_fatal("Error when calling OS_Args(7)!\n");
        }
        
        r.r[0] = 254;
        r.r[1] = i;
        if (_kernel_swi(OS_Args, &r, &r)) {
            m_free(name);
            log_fatal("Error when calling OS_Args(254)!\n");
        }
        
        printf("%3i: %s (%c%c)\n", i, name,
                                   (r.r[0] & 0x40) ? 'R' : 0,
                                   (r.r[0] & 0x80) ? 'W' : 0);
        m_free(name);
    }
}
#endif

void
not_implemented(const char *feature)
{
    log_info("%s is not implemented in the RISC OS version!\n", feature);
}

#endif /* !__RISCOS__C__ */
