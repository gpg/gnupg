/* Generated automatically by mkerrors */
/* Do not edit! */

#include <stdio.h>
#include "keybox-defs.h"

/**
 * keybox_strerror:
 * @err:  Error code 
 * 
 * This function returns a textual representaion of the given
 * errorcode. If this is an unknown value, a string with the value
 * is returned (Beware: it is hold in a static buffer).
 * 
 * Return value: String with the error description.
 **/
const char *
keybox_strerror (KeyboxError err)
{
  const char *s;
  static char buf[25];

  switch (err)
    {
    case KEYBOX_No_Error: s="no error"; break;
    case KEYBOX_General_Error: s="general error"; break;
    case KEYBOX_Out_Of_Core: s="out of core"; break;
    case KEYBOX_Invalid_Value: s="invalid value"; break;
    case KEYBOX_Timeout: s="timeout"; break;
    case KEYBOX_Read_Error: s="read error"; break;
    case KEYBOX_Write_Error: s="write error"; break;
    case KEYBOX_File_Error: s="file error"; break;
    case KEYBOX_Blob_Too_Short: s="blob too short"; break;
    case KEYBOX_Blob_Too_Large: s="blob too large"; break;
    case KEYBOX_Invalid_Handle: s="invalid handle"; break;
    case KEYBOX_File_Create_Error: s="file create error"; break;
    case KEYBOX_File_Open_Error: s="file open error"; break;
    case KEYBOX_File_Close_Error: s="file close error"; break;
    case KEYBOX_Nothing_Found: s="nothing found"; break;
    case KEYBOX_Wrong_Blob_Type: s="wrong blob type"; break;
    case KEYBOX_Missing_Value: s="missing value"; break;
    default:  sprintf (buf, "ec=%d", err ); s=buf; break;
    }

  return s;
}

