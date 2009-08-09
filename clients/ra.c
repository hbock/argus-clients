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
 * $Id: //depot/argus/clients/clients/ra.c#41 $
 * $DateTime: 2009/05/21 18:16:12 $
 * $Change: 1742 $
 */

/*
 *
 * ra  - Read Argus 
 *       This program read argus output streams, either through a socket,
 *       a piped stream, or in a file, filters and optionally writes the
 *       output to a file, its stdout or prints the binary records to
 *       stdout in ASCII.
 *
 * written by Carter Bullard
 * QoSient, LLC
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
#include <argus_filter.h>

#include <signal.h>
#include <ctype.h>

extern int ArgusTotalMarRecords;
extern int ArgusTotalFarRecords;

extern struct ArgusParserStruct *ArgusParser;

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

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "poll", 4)))
               parser->RaPollMode++;

            if (!(strncasecmp (mode->mode, "rmon", 4)))
               parser->RaMonMode++;

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

         if (ArgusParser->Aflag) {
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE_CC__) || defined(__APPLE__) || defined(HAVE_SOLARIS)
            printf (" Totalrecords %-8lld  TotalMarRecords %-8lld  TotalFarRecords %-8lld TotalPkts %-8lld TotalBytes %-8lld\n",
                          ArgusParser->ArgusTotalRecords, ArgusParser->ArgusTotalMarRecords, ArgusParser->ArgusTotalFarRecords,
                          ArgusParser->ArgusTotalPkts, ArgusParser->ArgusTotalBytes);
#else
            printf (" Totalrecords %-8Ld  TotalManRecords %-8Ld  TotalFarRecords %-8Ld TotalPkts %-8Ld TotalBytes %-8Ld\n",
                          ArgusParser->ArgusTotalRecords, ArgusParser->ArgusTotalMarRecords, ArgusParser->ArgusTotalFarRecords,
                          ArgusParser->ArgusTotalPkts, ArgusParser->ArgusTotalBytes);
#endif
         }

         fflush(stdout);
         ArgusShutDown(sig);
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
   ArgusDebug (2, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

   fprintf (stderr, "Ra Version %s\n", version);
   fprintf (stderr, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -A                    print record summaries on termination.\n");
   fprintf (stderr, "         -b                    dump packet-matching code.\n");
   fprintf (stderr, "         -c <char>             specify a delimiter <char> for output columns.\n");
   fprintf (stderr, "         -C <[host]:port>      specify Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stderr, "         -D <level>            specify debug level\n");
#endif
   fprintf (stderr, "         -e <regex>            match regular expression in flow user data fields.\n");
   fprintf (stderr, "                               Prepend the regex with either \"s:\" or \"d:\" to limit the match\n");
   fprintf (stderr, "                               to either the source or destination user data fields.\n");
   fprintf (stderr, "         -E <file>             write records that are rejected by the filter into <file>\n");
   fprintf (stderr, "         -F <conffile>         read configuration from <conffile>.\n");
   fprintf (stderr, "         -h                    print help.\n");
   fprintf (stderr, "         -M <option>           specify a Mode of operation.\n");
   fprintf (stderr, "            rmon               convert bi-directional flow data to RMON in/out stats\n");
   fprintf (stderr, "            poll               attach to remote server to get MAR and then disconnect\n");
   fprintf (stderr, "            xml                pritn output in xml format\n");
   fprintf (stderr, "            TZ='timezone'      set TZ environment variable with timezone string\n");
   fprintf (stderr, "            saslmech='mech'    specify the sasl mechanism to use for this connection\n");
   fprintf (stderr, "            label='str'        specify label matching expression\n");
   fprintf (stderr, "            dsrs='strip str'   specify input dsrs (see rastrip.1)\n");
   fprintf (stderr, "            sql='str'          use str as \"WHERE\" clause in sql call.\n");
   fprintf (stderr, "            disa               Use US DISA diff-serve encodings\n");
   fprintf (stderr, "            hex                process user data using hex encoding\n");
   fprintf (stderr, "            ascii              process user data using ascii encoding\n");
   fprintf (stderr, "            encode32           process user data using encode32 encoding\n");
   fprintf (stderr, "            encode64           process user data using encode64 encoding\n");
   fprintf (stderr, "         -n                    don't convert numbers to names.\n");
   fprintf (stderr, "         -p <digits>           print fractional time with <digits> precision.\n");
   fprintf (stderr, "         -q                    quiet mode. don't print record outputs.\n");
   fprintf (stderr, "         -r <file>             read argus data <file>. '-' denotes stdin.\n");
   fprintf (stderr, "         -R <dir>              recursively process files in directory\n");
   fprintf (stderr, "         -s [-][+[#]]field[:w] specify fields to print.\n");
   fprintf (stderr, "                   fields:     srcid, stime, ltime, sstime, dstime, sltime, dltime,\n");
   fprintf (stderr, "                               trans, seq, flgs, dur, avgdur, stddev, mindur, maxdur,\n");
   fprintf (stderr, "                               saddr, daddr, proto, sport, dport, stos, dtos, sdsb, ddsb\n");
   fprintf (stderr, "                               sco, dco, sttl, dttl, sipid, dipid, smpls, dmpls, svlan, dvlan\n");
   fprintf (stderr, "                               svid, dvid, svpri, dvpri, [s|d]pkts, [s|d]bytes,\n");
   fprintf (stderr, "                               [s||d]appbytes, [s|d]load, [s|d]loss, [s|d]ploss, [s|d]rate,\n");
   fprintf (stderr, "                               smac, dmac, dir, [s|d]intpkt, [s|d]jit, state, suser, duser,\n");
   fprintf (stderr, "                               swin, dwin, trans, srng, erng, stcpb, dtcpb, tcprtt, inode,\n");
   fprintf (stderr, "                               offset, smaxsz, dmaxsz, sminsz, dminsz\n");
   fprintf (stderr, "         -S <host[:port]>      specify remote argus and optional port number\n");
   fprintf (stderr, "         -t <timerange>        specify <timerange> for reading records.\n");
   fprintf (stderr, "                   format:     timeSpecification[-timeSpecification]\n");
   fprintf (stderr, "                               timeSpecification: [[[yyyy/]mm/]dd.]hh[:mm[:ss]]\n");
   fprintf (stderr, "                                                    [yyyy/]mm/dd\n");
   fprintf (stderr, "                                                    -%%d{yMdhms}\n");
   fprintf (stderr, "         -T <secs>             attach to remote server for T seconds.\n");
   fprintf (stderr, "         -u                    print time in Unix time format.\n");
#ifdef ARGUS_SASL
   fprintf (stderr, "         -U <user/auth>        specify <user/auth> authentication information.\n");
#endif
   fprintf (stderr, "         -w <file>             write output to <file>. '-' denotes stdout.\n");
   fprintf (stderr, "         -X                    don't read default rarc file.\n");
   fprintf (stderr, "         -z                    print Argus TCP state changes.\n");
   fprintf (stderr, "         -Z <s|d|b>            print actual TCP flag values.\n");
   fprintf (stderr, "                               <'s'rc | 'd'st | 'b'oth>\n");
   exit(1);
}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
         RaProcessManRecord (parser, argus);
         break;

      case ARGUS_EVENT:
         RaProcessEventRecord (parser, argus);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];
         if (metric != NULL) {
            parser->ArgusTotalPkts  += metric->src.pkts;
            parser->ArgusTotalPkts  += metric->dst.pkts;
            parser->ArgusTotalBytes += metric->src.bytes;
            parser->ArgusTotalBytes += metric->dst.bytes;
         }

         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(argus);
            struct ArgusFlow *flow;

            if ((flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, argus);
            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else {
            RaProcessThisRecord(parser, argus);
         }
      }
   }
}

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];

   if (parser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = parser->ArgusWfileList->count;

      if ((lobj = parser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int retn = 1;
               if (wfile->filterstr) {
                  struct nff_insn *wfcode = wfile->filter.bf_insns;
                  retn = ArgusFilterRecord (wfcode, argus);
               }

               if (retn != 0) {
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
         if (parser->Lflag && !(parser->ArgusPrintXml)) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);
 
            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);
 
            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         bzero (buf, sizeof(buf));
         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);

         fprintf (stdout, "%s", buf);

         if (parser->eflag == ARGUS_HEXDUMP) {
            int i;
            for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
               if (parser->RaPrintAlgorithmList[i] != NULL) {
                  struct ArgusDataStruct *user = NULL;
                  if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData) {
                     int slen = 0, len = parser->RaPrintAlgorithmList[i]->length;
                     if (len > 0) {
                        if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
                           if (user->hdr.type == ARGUS_DATA_DSR) {
                              slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                           } else
                              slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;
                              
                           slen = (user->count < slen) ? user->count : slen;
                           slen = (slen > len) ? len : slen;
                           ArgusDump ((const u_char *) &user->array, slen, "      ");
                        }
                     }
                  }
                  if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
                     int slen = 0, len = parser->RaPrintAlgorithmList[i]->length;
                     if (len > 0) {
                        if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
                           if (user->hdr.type == ARGUS_DATA_DSR) {
                              slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                           } else
                              slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                           slen = (user->count < slen) ? user->count : slen;
                           slen = (slen > len) ? len : slen;
                           ArgusDump ((const u_char *) &user->array, slen, "      ");
                        }
                     }
                  }
               } else
                  break;
            }
         }

         fprintf (stdout, "\n");
         fflush (stdout);
      }
   }
}

void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];

   if (parser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = parser->ArgusWfileList->count;

      if ((lobj = parser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int retn = 1;
               if (wfile->filterstr) {
                  struct nff_insn *wfcode = wfile->filter.bf_insns;
                  retn = ArgusFilterRecord (wfcode, argus);
               }

               if (retn != 0) {
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

      if ((parser->ArgusPrintMan) && (!parser->qflag)) {
         if (parser->Lflag && !(parser->ArgusPrintXml)) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);
 
            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);
 
            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         bzero (buf, sizeof(buf));
         if (argus->dsrs[0] != NULL) {
            ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
            fprintf (stdout, "%s\n", buf);
         }
         fflush (stdout);
      }
   }

#ifdef ARGUSDEBUG
   {
      struct ArgusRecord *rec = (struct ArgusRecord *)argus->dsrs[0];
      if (rec != NULL) {
         struct ArgusMarStruct *mar = &rec->ar_un.mar;
         ArgusDebug (6, "RaProcessManRecord (0x%x, 0x%x) mar parsed 0x%x", parser, argus, mar); 
      }
   }
#endif
}


void
RaProcessEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];

   if (parser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = parser->ArgusWfileList->count;

      if ((lobj = parser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int retn = 1;
               if (wfile->filterstr) {
                  struct nff_insn *wfcode = wfile->filter.bf_insns;
                  retn = ArgusFilterRecord (wfcode, argus);
               }

               if (retn != 0) {
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

      if ((parser->ArgusPrintEvent) && (!parser->qflag)) {
         if (parser->Lflag && !(parser->ArgusPrintXml)) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);
 
            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);
 
            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         bzero (buf, sizeof(buf));
         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);

         fprintf (stdout, "%s\n", buf);
         fflush (stdout);
      }
   }

#ifdef ARGUSDEBUG
   {
      struct ArgusRecord *rec = (struct ArgusRecord *)argus->dsrs[0];

      if (rec != NULL) {
         struct ArgusEventStruct *event = &rec->ar_un.event;
         ArgusDebug (6, "RaProcessEventRecord (0x%x, 0x%x) event parsed 0x%x", parser, argus, event); 
      }
   }
#endif
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}
