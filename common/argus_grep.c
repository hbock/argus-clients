/*
 * Argus Software
 * Copyright (c) 2000-2008 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * argus-grep.c  - support to find regular expressions in argus user data buffers.
 *
 * written by Carter Bullard
 * QoSient, LLC
 */

/* 
 * $Id: //depot/argus/clients/common/argus_grep.c#3 $
 * $DateTime: 2009/04/15 15:06:17 $
 * $Change: 1711 $
 */

#include <unistd.h>
#include <sys/types.h>

#include <compat.h>
#include <argus_def.h>
#include <argus_out.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_grep.h>

void
ArgusInitializeGrep (struct ArgusParserStruct *parser)
{
   if (parser && (parser->estr)) {
      int rege;
      if ((rege = regcomp(&parser->upreg, parser->estr, REG_EXTENDED | REG_NOSUB)) != 0) {
         char errbuf[MAXSTRLEN];
         if (regerror(rege, &parser->upreg, errbuf, MAXSTRLEN))
            ArgusLog (LOG_ERR, "ArgusProcessLabelOption: user data regex error %s", errbuf);
      }
   }
}


/* Scan the specified portion of the buffer, to see if there
   is a match of any kind.  The idea is for every string in the
   buffer, just call regexec() with the strings. */

static int
ArgusGrepBuf (regex_t *preg, char *beg, char *lim)
{
   int retn = 0, b;
   char *p = beg;

   while (!(p > lim)) {
      regmatch_t pmatch;
      int nmatch = 0;

      bzero(&pmatch, sizeof(pmatch));

      if ((b = regexec(preg, p, nmatch, &pmatch, 0)) != 0) {
         switch (b) {
            case REG_NOMATCH: {
               int slen = strlen(p);
               p += slen + 1;
               break;
            }

            default:
               return retn;
         }

      } else
         return 1;
   }

   return retn;
}



int
ArgusGrepUserData (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusDataStruct *user = NULL;
   int len, retn = 0, found = 0;

   if (((argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) ==  NULL) &&
       ((argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) ==  NULL))
      return(0);

   if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) !=  NULL) {
      char *buf = (char *)&user->array;
      if (parser->ArgusGrepSource) {
         if ((user->hdr.type == ARGUS_DATA_DSR) && (user->hdr.subtype & ARGUS_LEN_16BITS)) {
            len = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
         } else 
            len = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

         if ((retn = ArgusGrepBuf (&parser->upreg, buf, &buf[len])))
            found++;
      }
   }

   if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) !=  NULL) {
      char *buf = (char *)&user->array;
      if (parser->ArgusGrepDestination) {
         if ((user->hdr.type == ARGUS_DATA_DSR) && (user->hdr.subtype & ARGUS_LEN_16BITS)) {
            len = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
         } else
            len = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

         if ((retn = ArgusGrepBuf (&parser->upreg, buf, &buf[len])))
            found++;
      }
   }

   if ((!parser->vflag && found) || (parser->vflag && !found))
      retn = 1;

   return (retn);
}
