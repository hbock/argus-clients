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
 * $Id: //depot/argus/clients/clients/rasort.c#26 $
 * $DateTime: 2009/05/15 12:40:06 $
 * $Change: 1732 $
 */

/*
 * rasort.c  - sort argus records based on various fields.
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

#include <compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_sort.h>
#include <argus_filter.h>

#include <signal.h>
#include <ctype.h>


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode;
   int i = 0, x = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      parser->RaWriteOut = 0;

      if (parser->vflag)
         ArgusReverseSortDir++;

      if ((ArgusSorter = ArgusNewSorter()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit ArgusNewSorter error %s", strerror(errno));

      bzero ((char *) ArgusSorter->ArgusSortAlgorithms, sizeof(ArgusSorter->ArgusSortAlgorithms));
      ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[0];
 
      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strcmp ("replace", mode->mode))) {
               ArgusSorter->ArgusReplaceMode++;
               if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
                  ArgusLog (LOG_ERR, "replace mode and -w option are incompatible\n");
               }
            }
 
            mode = mode->nxt;
         }
      }

      if ((mode = parser->ArgusMaskList) != NULL) {
         while (mode) {
            for (x = 0; x < MAX_SORT_ALG_TYPES; x++) {
               if (!strncmp (ArgusSortKeyWords[x], mode->mode, strlen(ArgusSortKeyWords[x]))) {
                  ArgusSorter->ArgusSortAlgorithms[i++] = ArgusSortAlgorithmTable[x];
                  break;
               }
            }

            if (x == MAX_SORT_ALG_TYPES)
               ArgusLog (LOG_ERR, "sort syntax error. \'%s\' not supported", mode->mode);

            mode = mode->nxt;
         }
      }

      parser->RaInitialized++;
   }
}

void
RaArgusInputComplete (struct ArgusInput *input)
{
   struct ArgusRecordStruct *nsr;
   struct ArgusWfileStruct *wfile = NULL;
   char buf[MAXSTRLEN];
   int count, label, i, fd;
 
   if (ArgusSorter->ArgusReplaceMode) {
      if (ArgusParser->ArgusWfileList == NULL)
         ArgusParser->ArgusWfileList = ArgusNewList();
 
      if ((count = ArgusSorter->ArgusRecordQueue->count) > 0) {
         if (!(ArgusParser->ArgusRandomSeed))
            srandom(ArgusParser->ArgusRandomSeed);

         srandom (ArgusParser->ArgusRealTime.tv_usec);
         label = random() % 100000;
 
         bzero(buf, sizeof(buf));
         snprintf (buf, MAXSTRLEN, "%s.tmp%d", input->filename, label);
         if ((fd = open(buf, O_CREAT|O_EXCL, input->statbuf.st_mode)) < 0)
            ArgusLog (LOG_ERR, "open %s error: %s", buf, strerror(errno));
 
         close(fd);
 
         if ((wfile = (struct ArgusWfileStruct *) ArgusCalloc (1, sizeof (*wfile))) != NULL) {
            ArgusPushFrontList(ArgusParser->ArgusWfileList, (struct ArgusListRecord *)wfile, ARGUS_NOLOCK);
            wfile->filename  = strdup(buf);
 
         } else
            ArgusLog (LOG_ERR, "setArgusWfile, ArgusCalloc %s", strerror(errno));
 
         ArgusSortQueue (ArgusSorter, ArgusSorter->ArgusRecordQueue);
 
         for (i = 0, count = ArgusSorter->ArgusRecordQueue->count; i < count; i++)
            RaSendArgusRecord ((struct ArgusRecordStruct *)ArgusSorter->ArgusRecordQueue->array[i]);
 
         while ((nsr = (struct ArgusRecordStruct *) ArgusPopQueue(ArgusSorter->ArgusRecordQueue, ARGUS_NOLOCK)) != NULL)
            ArgusDeleteRecordStruct(ArgusParser, nsr);
 
         rename (wfile->filename, input->filename);
         fclose (wfile->fd);
         ArgusDeleteList (ArgusParser->ArgusWfileList, ARGUS_WFILE_LIST);
         ArgusParser->ArgusWfileList = NULL;
 
         if (ArgusParser->Vflag)
            ArgusLog(LOG_INFO, "file %s sorted", input->filename);
      }
   }
}


void
RaParseComplete (int sig)
{
   int i = 0, count = 0;
 
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         count = ArgusSorter->ArgusRecordQueue->count;

         if (count > 0) {
            ArgusSortQueue (ArgusSorter, ArgusSorter->ArgusRecordQueue);
 
            for (i = 0; i < count; i++)
               RaSendArgusRecord ((struct ArgusRecordStruct *) ArgusSorter->ArgusRecordQueue->array[i]);
         }
      }

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
             
   fprintf (stderr, "Rasort Version %s\n", version);
   fprintf (stderr, "usage: %s [[-M mode] [-m sortfield] ...] [ra-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "options:    -M replace         replace the original file with the sorted output.\n");
   fprintf (stderr, "            -m <sortfield>     specify the <sortfield>(s) in order.\n");
   fprintf (stderr, "                               valid sorfields are:\n");
   fprintf (stderr, "                                  stime, ltime, trans, dur, avgdur, mindur,\n");
   fprintf (stderr, "                                  maxdur, smac, dmac, saddr, daddr, proto, \n");
   fprintf (stderr, "                                  sport, dport, stos, dtos, sttl, dttl, bytes,\n");
   fprintf (stderr, "                                  sbytes, dbytes, pkts, spkts, dpkts, load,\n"); 
   fprintf (stderr, "                                  sload, sload, dload, loss, sloss, dloss,\n"); 
   fprintf (stderr, "                                  ploss, psloss, pdloss, rate, srate, drate,\n"); 
   fprintf (stderr, "                                  seq, smpls, dmpls, svlan, dvlan, srcid,\n");
   fprintf (stderr, "                                  stcpb, dtcpb, tcprtt\n"); 
   fprintf (stderr, "\n"); 
   fprintf (stderr, "ra-options: -b                 dump packet-matching code.\n");
   fprintf (stderr, "            -C <[host]:<port>  specify remote Cisco Netflow source.\n");
   fprintf (stderr, "                               source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stderr, "            -D <level>         specify debug level\n");
#endif
   fprintf (stderr, "            -F <conffile>      read configuration from <conffile>.\n");
   fprintf (stderr, "            -h                 print help.\n");
   fprintf (stderr, "            -r <file>          read argus data <file>. '-' denotes stdin.\n");
   fprintf (stderr, "            -s [-][+[#]]field  specify fields to print.\n");
   fprintf (stderr, "            -S <host[:port]>   specify remote argus <host> and optional port\n");
   fprintf (stderr, "                               number.\n");
   fprintf (stderr, "            -t <timerange>     specify <timerange> for reading records.\n");
   fprintf (stderr, "                      format:  timeSpecification[-timeSpecification]\n");
   fprintf (stderr, "                               timeSpecification: [mm/dd[/yy].]hh[:mm[:ss]]\n");
   fprintf (stderr, "                                                   mm/dd[/yy]\n");
   fprintf (stderr, "                                                   -%%d{yMhdms}\n");
   fprintf (stderr, "            -T <secs>          attach to remote server for T seconds.\n");
#ifdef ARGUS_SASL
   fprintf (stderr, "            -U <user/auth>     specify <user/auth> authentication information.\n");
#endif
   fprintf (stderr, "            -w <file>          write output to <file>. '-' denotes stdout.\n");
   exit(1);
}

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tns = NULL;

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if ((tns = ArgusCopyRecordStruct(ns)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCopyRecordStruct(0x%x) error\n", ns);

         ArgusAddToQueue (ArgusSorter->ArgusRecordQueue, &tns->qhdr, ARGUS_NOLOCK);
         break;
      }
   }
}

int
RaSendArgusRecord(struct ArgusRecordStruct *ns)
{
   int retn = 1;
   char buf[MAXSTRLEN];

   if (ns->status & ARGUS_RECORD_WRITTEN)
      return (retn);
 
   if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = ArgusParser->ArgusWfileList->count;

      if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int pass = 1;
               if (wfile->filterstr) {
                  struct nff_insn *wfcode = wfile->filter.bf_insns;
                  pass = ArgusFilterRecord (wfcode, ns);
               }

               if (pass != 0) {
                  if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;
                     char buf[2048];
                     if ((argusrec = ArgusGenerateRecord (ns, 0L, buf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        ArgusWriteNewLogfile (ArgusParser, ns->input, wfile, argusrec);
                     }
                  }
               }
            }
            lobj = lobj->nxt;
         }
      }

   } else {
      if (!ArgusParser->qflag) {
         if (ArgusParser->Lflag) {
            if (ArgusParser->RaLabel == NULL)
               ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, ns);
 
            if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag))
               printf ("%s\n", ArgusParser->RaLabel);
 
            if (ArgusParser->Lflag < 0)
               ArgusParser->Lflag = 0;
         }

         *(int *)&buf = 0;
         ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);
         fprintf (stdout, "%s\n", buf);
         fflush(stdout);
      }
   }

   ns->status |= ARGUS_RECORD_WRITTEN;
   return (retn);
}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}



