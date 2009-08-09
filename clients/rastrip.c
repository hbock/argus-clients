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
 * $Id: //depot/argus/clients/clients/rastrip.c#22 $
 * $DateTime: 2009/05/15 12:40:06 $
 * $Change: 1732 $
 */

/*
 * rastrip.c  - remove fields from argus records.
 *       
 * written by Carter Bullard
 * QoSient, LLC
 *
 */


#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>

#include <signal.h>
#include <ctype.h>

#include <compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#define ARGUS_ADD_OPTION		1
#define ARGUS_SUB_OPTION		2


extern char *ArgusDSRKeyWords[ARGUSMAXDSRTYPE];
int ArgusDSRFields[ARGUSMAXDSRTYPE];

/*
#define ARGUS_TRANSPORT_INDEX            0
#define ARGUS_FLOW_INDEX                 1
#define ARGUS_TIME_INDEX                 2
#define ARGUS_METRIC_INDEX               3
#define ARGUS_AGR_INDEX                  4
#define ARGUS_NETWORK_INDEX              5 
#define ARGUS_VLAN_INDEX                 6 
#define ARGUS_MPLS_INDEX                 7
#define ARGUS_JITTER_INDEX               8
#define ARGUS_IPATTR_INDEX               9
#define ARGUS_PSIZE_INDEX               10
#define ARGUS_SRCUSERDATA_INDEX         11
#define ARGUS_DSTUSERDATA_INDEX         12
#define ARGUS_MAC_INDEX                 13 
#define ARGUS_ICMP_INDEX                14
#define ARGUS_ENCAPS_INDEX              15
#define ARGUS_TIME_ADJ_INDEX            16
#define ARGUS_COR_INDEX                 17
#define ARGUS_COCODE_INDEX              18
                                                                                                                                                          
char *ArgusDSRKeyWords[ARGUSMAXDSRTYPE] = {
   "trans",
   "flow",
   "time",
   "metric",
   "agr",
   "net",
   "vlan",
   "mpls",
   "jitter",
   "ipattr",
   "psize",
   "suser",
   "duser",
   "mac",
   "icmp",
   "encaps",
   "tadj",
   "cor",
   "cocode",
};
*/

int ArgusReplaceMode = 0;
int ArgusStripDown = 0;
int ArgusFirstMOptionField = 1;

void ArgusProcessOptions(struct ArgusModeStruct *);

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;

   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      parser->RaInitialized++;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strcmp ("replace", mode->mode))) {
               ArgusReplaceMode++;
               if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
                  ArgusLog (LOG_ERR, "replace mode and -w option are incompatible\n");
               }
               break;
            }
            mode = mode->nxt;
         }
      }

      if ((mode = parser->ArgusModeList) != NULL)
         ArgusProcessOptions(mode);
      else {
         bzero ((char *)ArgusDSRFields, sizeof(ArgusDSRFields));
         ArgusDSRFields[ARGUS_TIME_INDEX] = 1;
         ArgusDSRFields[ARGUS_FLOW_INDEX] = 1;
         ArgusDSRFields[ARGUS_METRIC_INDEX] = 1;
         ArgusDSRFields[ARGUS_NETWORK_INDEX] = 1;
      }

      if (!(ArgusStripDown))
         ArgusStripDown++;
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

   fprintf (stderr, "Rastrip Version %s\n", version);
   fprintf (stderr, "usage: %s [-M [modes] [+|-]dsr [dsr ...]] [ra-options]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -M replace      strip dsrs and overwrite current file.\n");
   fprintf (stderr, "            [+|-] dsrs   [add|subtract] dsrs from records.\n");
   fprintf (stderr, "               dsrs:     stime, ltime, count, dur, avgdur,\n");
   fprintf (stderr, "                         srcid, ind, mac, dir, jitter, status, user,\n");
   fprintf (stderr, "                         win, trans, seq, vlan, vid, vpri, mpls.\n");

   exit(1);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];
   int x;

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         for (x = 0; x < ARGUSMAXDSRTYPE; x++) {
            if (!(ArgusDSRFields[x])) {
               argus->dsrs[x] = NULL;
            }
         }
         
         if (parser->ArgusWfileList != NULL) {
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusListObjectStruct *lobj = NULL;
            int i, count = parser->ArgusWfileList->count;

            if ((lobj = parser->ArgusWfileList->start) != NULL) {
               for (i = 0; i < count; i++) {
                  if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                     int pass = 1;
                     if (wfile->filterstr) {
                        struct nff_insn *wfcode = wfile->filter.bf_insns;
                        pass = ArgusFilterRecord (wfcode, argus);
                     }

                     if (pass != 0) {
                        if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                           struct ArgusRecord *argusrec = NULL;
                           static char sbuf[0x10000];
                           if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                              ArgusHtoN(argusrec);
#endif
                              ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                           }
                        }
                     }
                  }

                  lobj = lobj->nxt;
               }
            }

         } else {
            if (!parser->qflag) {
               if (parser->Lflag) {
                  if (parser->RaLabel == NULL)
                     parser->RaLabel = ArgusGenerateLabel(parser, argus);
       
                  if (!(parser->RaLabelCounter++ % parser->Lflag))
                     printf ("%s\n", parser->RaLabel);
       
                  if (parser->Lflag < 0)
                     parser->Lflag = 0;
               }

               *(int *)&buf = 0;
               ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
               fprintf (stdout, "%s\n", buf);
            }
         }
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


void
ArgusProcessOptions(struct ArgusModeStruct *mode)
{
   int x, RaOptionOperation, setValue = 0;
   char *ptr = NULL;
   char *endptr;

   if (mode != NULL) {
      while (mode) {
         if ((strcmp ("replace", mode->mode))) {
            if (isdigit((int)*mode->mode)) {
                ArgusStripDown = strtol(mode->mode, &endptr, 10);
                if (mode->mode == endptr)
                   usage();

            } else {
               if (*mode->mode == '-') {
                  if (ArgusFirstMOptionField) {
                     for (x = 0; x < ARGUSMAXDSRTYPE; x++)
                        ArgusDSRFields[x] = 1;
                     ArgusFirstMOptionField = 0;
                  }
                  ptr = mode->mode + 1;
                  RaOptionOperation = ARGUS_SUB_OPTION;
               } else 
               if (*mode->mode == '+') {
                  if (ArgusFirstMOptionField) {
                     bzero ((char *)ArgusDSRFields, sizeof(ArgusDSRFields));
                     ArgusDSRFields[ARGUS_TIME_INDEX] = 1;
                     ArgusDSRFields[ARGUS_FLOW_INDEX] = 1;
                     ArgusDSRFields[ARGUS_METRIC_INDEX] = 1;
                     ArgusDSRFields[ARGUS_NETWORK_INDEX] = 1;
                  }
                  ptr = mode->mode + 1;
                  RaOptionOperation = ARGUS_ADD_OPTION;
               } else {
                  if (ArgusFirstMOptionField) {
                     bzero ((char *) ArgusDSRFields, sizeof(ArgusDSRFields));
                     ArgusFirstMOptionField = 0;
                  }
                  ptr = mode->mode;
                  RaOptionOperation = ARGUS_ADD_OPTION;
               }

               setValue = (RaOptionOperation == ARGUS_ADD_OPTION) ? 1 : 0;

               for (x = 0; x < ARGUSMAXDSRTYPE; x++) {
                  if (strlen(ArgusDSRKeyWords[x])) {
                     if (!strncmp (ArgusDSRKeyWords[x], ptr, strlen(ArgusDSRKeyWords[x]))) {
                        ArgusDSRFields[x] = setValue;
                        break;
                     }
                  }
               }
            }
         }

         mode = mode->nxt;
      }
   }
}
