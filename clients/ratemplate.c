/*
 * Argus Software
 * Copyright (c) 2000-2009 QoSient, LLC
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
 * 
 * $Id: //depot/argus/clients/clients/ratemplate.c#15 $
 * $DateTime: 2009/05/15 12:40:06 $
 * $Change: 1732 $
 */

/*
 * ratemplate.c  - template for ra* client programs.
 *    add application specific code, stir and enjoy.
 */


#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>

#include <compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <signal.h>
#include <ctype.h>

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   parser->RaWriteOut = 1;

   if (!(parser->RaInitialized)) {

/*
   the library sets signal handling routines for 
   SIGHUP, SIGTERM, SIGQUIT, SIGINT, SIGUSR1, and SIGUSR2.
   SIGHUP doesn't do anything, SIGTERM, SIGQUIT, and SIGINT
   call the user supplied RaParseComplete().  SIGUSR1 and
   SIGUSR2 modify the debug level so if compiled with
   ARGUS_DEBUG support, programs can start generating 
   debug information.  USR1 increments by 1, USR2 sets
   it back to zero.

*/
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
#endif
         switch (sig) {
            case SIGHUP:
            case SIGINT:
            case SIGTERM:
            case SIGQUIT: {
               struct ArgusWfileStruct *wfile = NULL;

               if (ArgusParser->ArgusWfileList != NULL) {
                  struct ArgusListObjectStruct *lobj = NULL;
                  int i, count = ArgusParser->ArgusWfileList->count;

                  if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
                     for (i = 0; i < count; i++) {
                        if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                           if (wfile->fd != NULL) {
#ifdef ARGUSDEBUG
                              ArgusDebug (2, "RaParseComplete: closing %s\n", wfile->filename);
#endif
                              fflush (wfile->fd);
                              fclose (wfile->fd);
                              wfile->fd = NULL;
                           }
                        }
                        lobj = lobj->nxt;
                     }
                  }
               }
               exit(0);
               break;
            }
         }
      }
   }
}


void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

   fprintf (stderr, "Ratemplate Version %s\n", version);
   fprintf (stderr, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -A                 print record summaries on termination.\n");
   fprintf (stderr, "         -b                 dump packet-matching code.\n");
   fprintf (stderr, "         -c <char>          specify a delimiter <char> for output columns.\n");
   fprintf (stderr, "         -C <[host]:port>   specify remote Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stderr, "         -D <level>         specify debug level\n");
#endif
   fprintf (stderr, "         -e <encode>        convert user data using <encode> method.\n");
   fprintf (stderr, "                            Supported types are <Ascii> and <Encode64>.\n");
   fprintf (stderr, "         -E <file>          write records that are rejected by the filter\n");
   fprintf (stderr, "                            into <file>\n");
   fprintf (stderr, "         -F <conffile>      read configuration from <conffile>.\n");
   fprintf (stderr, "         -h                 print help.\n");
   fprintf (stderr, "         -n                 don't convert numbers to names.\n");
   fprintf (stderr, "         -p <digits>        print fractional time with <digits> precision.\n");
   fprintf (stderr, "         -q                 quiet mode. don't print record outputs.\n");
   fprintf (stderr, "         -r <file>          read argus data <file>. '-' denotes stdin.\n");
   fprintf (stderr, "         -R <dir>           recursively process files in directory\n");
   fprintf (stderr, "         -s [-][+[#]]field  specify fields to print.\n");
   fprintf (stderr, "                   fields:  srcid, stime, ltime, trans, seq, flgs, dur, avgdur,\n");
   fprintf (stderr, "                            stddev, mindur, maxdur, saddr, daddr, proto, sport,\n");
   fprintf (stderr, "                            dport, stos, dtos, sdsb, ddsb, sttl, dttl, sipid,\n");
   fprintf (stderr, "                            dipid, smpls, dmpls, [s|d]pkts, [s|d]bytes,\n");
   fprintf (stderr, "                            [s||d]appbytes, [s|d]load, [s|d]loss, [s|d]ploss,\n");
   fprintf (stderr, "                            [s|d]rate, smac, dmac, dir, [s|d]intpkt, [s|d]jit,\n");
   fprintf (stderr, "                            status, suser, duser, swin, dwin, svlan, dvlan,\n");
   fprintf (stderr, "                            svid, dvid, svpri, dvpri, srng, drng, stcpb, dtcpb,\n");
   fprintf (stderr, "                            tcprtt, inode\n");
   fprintf (stderr, "         -S <host[:port]>   specify remote argus <host> and optional port\n");
   fprintf (stderr, "                            number.\n");
   fprintf (stderr, "         -t <timerange>     specify <timerange> for reading records.\n");
   fprintf (stderr, "                   format:  timeSpecification[-timeSpecification]\n");
   fprintf (stderr, "                            timeSpecification: [[[yyyy/]mm/]dd.]hh[:mm[:ss]]\n");
   fprintf (stderr, "                                                 [yyyy/]mm/dd\n");
   fprintf (stderr, "                                                 -%%d{yMdhms}\n");
   fprintf (stderr, "         -T <secs>          attach to remote server for T seconds.\n");
   fprintf (stderr, "         -u                 print time in Unix time format.\n");
#ifdef ARGUS_SASL
   fprintf (stderr, "         -U <user/auth>     specify <user/auth> authentication information.\n");
#endif
   fprintf (stderr, "         -w <file>          write output to <file>. '-' denotes stdout.\n");
   fprintf (stderr, "         -z                 print Argus TCP state changes.\n");
   fprintf (stderr, "         -Z <s|d|b>         print actual TCP flag values.\n");
   fprintf (stderr, "                            <'s'rc | 'd'st | 'b'oth>\n");
   exit(1);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         break;
      }
   }
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}
