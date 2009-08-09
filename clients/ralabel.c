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
 */

/*
 * ralabel - add descriptor labels to flows.
 *           this particular labeler adds descriptors based
 *           on addresses.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/argus/clients/clients/ralabel.c#12 $
 * $DateTime: 2009/03/11 13:05:40 $
 * $Change: 1676 $
 */

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>

#if defined(HAVE_SOLARIS)
#include <strings.h>
#include <string.h>
#endif

#include <math.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_label.h>
#include <argus_client.h>
#include <argus_filter.h>
#include <argus_main.h>
#include <argus_cluster.h>


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if ((parser->ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if (parser->ArgusFlowModelFile) {
         RaLabelParseResourceFile (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile);
         parser->ArgusFlowModelFile = NULL;
      }

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "noprune", 7))) {
               parser->ArgusLabeler->prune = 0;
            } else
            if (!(strncasecmp (mode->mode, "addr", 4))) {
               if (parser->ArgusFlowModelFile) {
                  if (!(RaReadAddressConfig (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile) > 0))
                     ArgusLog (LOG_ERR, "ArgusNewLabeler: RaReadAddressConfig error");
               }
            } else
            if ((!(strncasecmp (mode->mode, "debug.tree", 10))) ||
                (!(strncasecmp (mode->mode, "debug", 5)))) {
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
               if (parser->ArgusLabeler &&  parser->ArgusLabeler->ArgusAddrTree)
                  RaPrintLabelTree (parser->ArgusLabeler, parser->ArgusLabeler->ArgusAddrTree[AF_INET], 0, 0);
               exit(0);
            }

            mode = mode->nxt;
         }
      }

      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
            struct ArgusWfileStruct *wfile = NULL, *start = NULL;
 
            if ((wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList)) != NULL) {
               start = wfile;
               fflush(wfile->fd);
               ArgusPopFrontList(ArgusParser->ArgusWfileList, ARGUS_NOLOCK);
               ArgusPushBackList(ArgusParser->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_NOLOCK);
               wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList);
            } while (wfile != start);
         } 

         fflush(stdout);
         exit(0);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaParseComplete (%d) returning\n", sig);
#endif
}

void
ArgusClientTimeout ()
{

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusClientTimeout: returning\n");
#endif
}

void
parse_arg (int argc, char**argv)
{ 

#ifdef ARGUSDEBUG
   ArgusDebug (6, "parse_arg (%d, 0x%x) returning\n", argc, argv);
#endif
}


void
usage ()
{
   extern char version[];
   fprintf (stderr, "RaLabeler Version %s\n", version);
   fprintf (stderr, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [ra-options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [ra-options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "options: -f <conffile>     read ralabel spec from <conffile>.\n");
   exit(1);
}

char *RaProcessAddress (struct ArgusParserStruct *, struct ArgusRecordStruct *, unsigned int *, int);
extern struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);


char *
RaProcessAddress (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, unsigned int *addr, int type)
{
   struct ArgusLabelerStruct *labeler = NULL;
   struct RaAddressStruct *raddr;
   char *retn = NULL;

   if ((labeler = parser->ArgusLabeler) == NULL)
      ArgusLog (LOG_ERR, "RaProcessAddress: No labeler\n");

   if (labeler->ArgusAddrTree != NULL) {
      switch (type) {
         case ARGUS_TYPE_IPV4: {
            struct RaAddressStruct node;
            bzero ((char *)&node, sizeof(node));

            node.addr.type = AF_INET;
            node.addr.len = 4;
            node.addr.addr[0] = *addr;
            node.addr.masklen = 32;

            if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_LONGEST_MATCH)) != NULL)
               retn = raddr->label;
            else {
               char *ptr, *sptr;
               if ((ptr = ArgusGetName(ArgusParser, (u_char *)addr)) != NULL) {
                  if ((sptr = strrchr(ptr, '.')) != NULL) {
                     if (strlen(++sptr) == 2) {
                        if (!isdigit((int)*sptr)) {
                           char *tptr = sptr;
                           int i, ch;
                           for (i = 0; i < 2; i++, tptr++) {
                              ch = *tptr;
                              if (islower(ch)) {
                                 ch = toupper(ch);
                                 *tptr = ch;
                              }
                           }
                           retn = sptr;
                        }
                     }
                  }
               }
            }

            break;
         }

         case ARGUS_TYPE_IPV6:
            break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessAddress (0x%x, 0x%x, 0x%x, %d) returning %s\n", parser, argus, addr, type, retn);
#endif

   return (retn);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusLabelStruct *lstruct = NULL;
   char buf[MAXSTRLEN];

   ArgusLabelRecord(parser, argus);

   lstruct = (void *) argus->dsrs[ARGUS_LABEL_INDEX];

   if (parser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = parser->ArgusWfileList->count;

      if ((lobj = parser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
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
                 
   fflush (stdout);

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessRecord (0x%x) returning\n", argus);
#endif
}


int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaSendArgusRecord (0x%x) returning\n", argus);
#endif
   return 1;
}

void ArgusWindowClose(void) { } 

