/* exdll.h for use with gpg4win
 * Copyright (C) 1999-2005 Nullsoft, Inc.
 *
 * This license applies to everything in the NSIS package, except
 * where otherwise noted.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any
 * damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any
 * purpose, including commercial applications, and to alter it and
 * redistribute it freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must
 *    not claim that you wrote the original software. If you use this
 *    software in a product, an acknowledgment in the product
 *    documentation would be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must
 *    not be misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source
 *    distribution.
 ************************************************************
 * 2005-11-14 wk  Applied license text to original exdll.h file from
 *                NSIS 2.0.4 and did some formatting changes.
 */

#ifndef _EXDLL_H_
#define _EXDLL_H_

/* only include this file from one place in your DLL.  (it is all
   static, if you use it in two places it will fail) */

#define EXDLL_INIT()           {  \
        g_stringsize=string_size; \
        g_stacktop=stacktop;      \
        g_variables=variables; }

/* For page showing plug-ins */
#define WM_NOTIFY_OUTER_NEXT (WM_USER+0x8)
#define WM_NOTIFY_CUSTOM_READY (WM_USER+0xd)
#define NOTIFY_BYE_BYE 'x'

typedef struct _stack_t {
  struct _stack_t *next;
  char text[1];          /* This should be the length of string_size. */
} stack_t;


static unsigned int g_stringsize;
static stack_t **g_stacktop;
static char *g_variables;

static int __stdcall popstring(char *str, size_t maxlen); /* 0 on success, 1 on empty stack */
static void __stdcall pushstring(const char *str);

enum
  {
    INST_0,         // $0
    INST_1,         // $1
    INST_2,         // $2
    INST_3,         // $3
    INST_4,         // $4
    INST_5,         // $5
    INST_6,         // $6
    INST_7,         // $7
    INST_8,         // $8
    INST_9,         // $9
    INST_R0,        // $R0
    INST_R1,        // $R1
    INST_R2,        // $R2
    INST_R3,        // $R3
    INST_R4,        // $R4
    INST_R5,        // $R5
    INST_R6,        // $R6
    INST_R7,        // $R7
    INST_R8,        // $R8
    INST_R9,        // $R9
    INST_CMDLINE,   // $CMDLINE
    INST_INSTDIR,   // $INSTDIR
    INST_OUTDIR,    // $OUTDIR
    INST_EXEDIR,    // $EXEDIR
    INST_LANG,      // $LANGUAGE
    __INST_LAST
};

typedef struct {
  int autoclose;
  int all_user_var;
  int exec_error;
  int abort;
  int exec_reboot;
  int reboot_called;
  int XXX_cur_insttype; /* deprecated */
  int XXX_insttype_changed; /* deprecated */
  int silent;
  int instdir_error;
  int rtl;
  int errlvl;
} exec_flags_t;

typedef struct {
  exec_flags_t *exec_flags;
  int (__stdcall *ExecuteCodeSegment)(int, HWND);
} extra_parameters_t;


/* Utility functions (not required but often useful). */
static int __stdcall
popstring(char *str, size_t maxlen)
{
  stack_t *th;
  if (!g_stacktop || !*g_stacktop)
    return 1;
  th=(*g_stacktop);
  lstrcpyn (str, th->text, maxlen);
  *g_stacktop = th->next;
  GlobalFree((HGLOBAL)th);
  return 0;
}

static void __stdcall
pushstring(const char *str)
{
  stack_t *th;
  if (!g_stacktop) return;
  th=(stack_t*)GlobalAlloc(GPTR,sizeof(stack_t)+g_stringsize);
  lstrcpyn(th->text,str,g_stringsize);
  th->next=*g_stacktop;
  *g_stacktop=th;
}

static char * __stdcall
getuservariable(const int varnum)
{
  if (varnum < 0 || varnum >= __INST_LAST) return NULL;
  return g_variables+varnum*g_stringsize;
}

static void __stdcall
setuservariable(const int varnum, const char *var)
{
  if (var != NULL && varnum >= 0 && varnum < __INST_LAST)
    lstrcpy(g_variables + varnum*g_stringsize, var);
}



#endif/*_EXDLL_H_*/
