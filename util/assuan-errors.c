/* assuan-errors.c - error codes
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
 *	Copyright (C) 2005 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Please note that this is a stripped down and modified version of
   the orginal Assuan code from libassuan. */ 

#include <stdio.h>
#include "assuan.h"

/* This function returns a textual representaion of the given error
   code.  If this is an unknown value, a string with the value is
   returned (Beware: it is hold in a static buffer).  Return value:
   String with the error description.
 */
const char *
assuan_strerror (assuan_error_t err)
{
  const char *s;
  static char buf[50];

  switch (err)
    {
    case ASSUAN_No_Error: s="no error"; break;
    case ASSUAN_General_Error: s="general error"; break;
    case ASSUAN_Out_Of_Core: s="out of core"; break;
    case ASSUAN_Invalid_Value: s="invalid value"; break;
    case ASSUAN_Timeout: s="timeout"; break;
    case ASSUAN_Read_Error: s="read error"; break;
    case ASSUAN_Write_Error: s="write error"; break;
    case ASSUAN_Problem_Starting_Server: s="problem starting server"; break;
    case ASSUAN_Not_A_Server: s="not a server"; break;
    case ASSUAN_Not_A_Client: s="not a client"; break;
    case ASSUAN_Nested_Commands: s="nested commands"; break;
    case ASSUAN_Invalid_Response: s="invalid response"; break;
    case ASSUAN_No_Data_Callback: s="no data callback"; break;
    case ASSUAN_No_Inquire_Callback: s="no inquire callback"; break;
    case ASSUAN_Connect_Failed: s="connect failed"; break;
    case ASSUAN_Accept_Failed: s="accept failed"; break;
    case ASSUAN_Not_Implemented: s="not implemented"; break;
    case ASSUAN_Server_Fault: s="server fault"; break;
    case ASSUAN_Invalid_Command: s="invalid command"; break;
    case ASSUAN_Unknown_Command: s="unknown command"; break;
    case ASSUAN_Syntax_Error: s="syntax error"; break;
    case ASSUAN_Parameter_Error: s="parameter error"; break;
    case ASSUAN_Parameter_Conflict: s="parameter conflict"; break;
    case ASSUAN_Line_Too_Long: s="line too long"; break;
    case ASSUAN_Line_Not_Terminated: s="line not terminated"; break;
    case ASSUAN_No_Input: s="no input"; break;
    case ASSUAN_No_Output: s="no output"; break;
    case ASSUAN_Canceled: s="canceled"; break;
    case ASSUAN_Unsupported_Algorithm: s="unsupported algorithm"; break;
    case ASSUAN_Server_Resource_Problem: s="server resource problem"; break;
    case ASSUAN_Server_IO_Error: s="server io error"; break;
    case ASSUAN_Server_Bug: s="server bug"; break;
    case ASSUAN_No_Data_Available: s="no data available"; break;
    case ASSUAN_Invalid_Data: s="invalid data"; break;
    case ASSUAN_Unexpected_Command: s="unexpected command"; break;
    case ASSUAN_Too_Much_Data: s="too much data"; break;
    case ASSUAN_Inquire_Unknown: s="inquire unknown"; break;
    case ASSUAN_Inquire_Error: s="inquire error"; break;
    case ASSUAN_Invalid_Option: s="invalid option"; break;
    case ASSUAN_Invalid_Index: s="invalid index"; break;
    case ASSUAN_Unexpected_Status: s="unexpected status"; break;
    case ASSUAN_Unexpected_Data: s="unexpected data"; break;
    case ASSUAN_Invalid_Status: s="invalid status"; break;
    case ASSUAN_Locale_Problem: s="locale problem"; break;
    case ASSUAN_Not_Confirmed: s="not confirmed"; break;
    case ASSUAN_USER_ERROR_FIRST: s="user error first"; break;
    case ASSUAN_USER_ERROR_LAST: s="user error last"; break;
    default: 
      {
        unsigned int source, code;

        source = ((err >> 24) & 0xff);
        code = (err & 0x00ffffff);
        if (source) /* Assume this is an libgpg-error. */
          sprintf (buf, "ec=%u.%u", source, code ); 
        else
          sprintf (buf, "ec=%d", err ); 
        s=buf; break;
      }
    }

  return s;
}

