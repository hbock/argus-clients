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
 * rasrvstats.c  - argus server statistics.
 *
 * written by Carter Bullard
 * QoSient, LLC 2003
 *
 * 
 * $Id: //depot/argus/clients/clients/rasrvstats.c#13 $
 * $DateTime: 2009/05/19 22:17:26 $
 * $Change: 1738 $
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
#include <argus_sort.h>

#include <argus_filter.h>
#include <argus_cluster.h>
#include <netinet/ip_icmp.h>

struct ArgusServiceRecord {
   u_int status;
   struct ArgusRecordStruct *argus;
};

int ArgusReplaceMode = 0;

#define ARGUS_MAXFLOWDEFS       5

#define ARGUS_SERVICE           0
#define ARGUS_SERVICE_SUBNET    1
#define ARGUS_SERVER            2
#define ARGUS_CLIENT_SUBNET     3
#define ARGUS_CLIENT            4

int RaTotals[ARGUS_MAXFLOWDEFS] = {0, 0, 0, 0, 0,};

char *RaSrvStatsFlowModelConf [] = {
   "filter=\"ip\" model=\"proto dport\" status=0 idle=0",
   "filter=\"ip\" model=\"daddr/24 proto dport\" status=0 idle=0",
   "filter=\"ip\" model=\"daddr proto dport\" status=0 idle=0",
   "filter=\"ip\" model=\"saddr/24 daddr proto dport\" status=0 idle=0",
   "filter=\"ip\" model=\"saddr daddr proto dport\" status=0 idle=0",
   NULL,
}; 

void RaPrintOutQueue (struct ArgusQueueStruct *, int);

struct ArgusQueueStruct *ArgusModelerQueue = NULL;

int RaHistoTimeSeries = 1;

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
            if (!(strncasecmp (mode->mode, "rmon", 4)))
               parser->RaMonMode++;
            if (!(strncasecmp (mode->mode, "norep", 5)))
               parser->RaAgMode++;
            if (!(strncasecmp (mode->mode, "ind", 3)))
               ArgusProcessFileIndependantly = 1;
            if (!(strcmp ("replace", mode->mode))) {
               ArgusProcessFileIndependantly = 1;
               ArgusReplaceMode++;
               if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
                  ArgusLog (LOG_ERR, "replace mode and -w option are incompatible\n");
               }
            }

            mode = mode->nxt;
         }
      }

      if ((ArgusAggregator = ArgusParseAggregator(parser, NULL, RaSrvStatsFlowModelConf)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");

      if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewQueue error");

      if ((ArgusSorter = ArgusNewSorter()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));
        
      if (parser->vflag)
         ArgusReverseSortDir++;

      parser->RaInitialized++;
   }
}


void
RaArgusInputComplete (struct ArgusInput *input)
{
   if (ArgusProcessFileIndependantly) {
      RaParseComplete (0);

      ArgusParser->RaInitialized = 0;
      ArgusClientInit(ArgusParser);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (7, "RaArgusInputComplete(0x%x) done", input);
#endif
}

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {
         if (RaTotals[ARGUS_SERVICE] > 0) {
            printf ("%s  Total Services %d  Total Servers %d  Total Clients %d\n", ArgusParser->ArgusProgramName,
               RaTotals[ARGUS_SERVICE], RaTotals[ARGUS_SERVER], RaTotals[ARGUS_CLIENT]);

            RaPrintOutQueue (ArgusModelerQueue, 0);
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

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaParseComplete(%d) done", sig);
#endif
}


void
ArgusClientTimeout ()
{
   struct ArgusAggregatorStruct *agg = ArgusAggregator;

   while (agg) {
      int done = 0;

      while (!done) {
         if (agg->queue->start) {
            struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *) agg->queue->start;
            double nslt = ArgusFetchLastTime(ns);
            double glt  = (double)(ArgusParser->ArgusGlobalTime.tv_sec * 1.0) + (double)(ArgusParser->ArgusGlobalTime.tv_usec/1000000.0);

            if (agg->idleint && ((glt - nslt) >= agg->idleint)) {
               ArgusRemoveHashEntry(&ns->htblhdr);
               ArgusRemoveFromQueue(agg->queue, &ns->qhdr, ARGUS_NOLOCK);
               RaSendArgusRecord(ns);
               ArgusDeleteRecordStruct (ArgusParser, ns);

            } else 
               done = 1;
         } else
            done = 1;
      }

      agg = agg->nxt;
   }

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
          
   fprintf (stderr, "Racluster Version %s\n", version);
   fprintf (stderr, "usage:  %s [-f rasrvstats.conf]\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage:  %s [-f rasrvstats.conf] [ra-options] [- filter-expression]\n\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "options:  -f <rasrvstats.conf>     read aggregation rules from <rasrvstats.conf>.\n");
   fprintf (stderr, "          -m flow key fields       specify fields to be used as flow keys.\n");
   fprintf (stderr, "          -M modes                 modify mode of operation.\n");
   fprintf (stderr, "             Available modes:      \n");
   fprintf (stderr, "                ind                aggregate multiple files independently\n");
   fprintf (stderr, "                norep              do not report aggregation statistics\n");
   fprintf (stderr, "                rmon               convert bi-directional data into rmon in/out data\n");
   fprintf (stderr, "                replace            replace input files with aggregation output\n");
   fprintf (stderr, "          -V                       verbose mode.\n");

   exit(1); 
}


void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (parser->Vflag || parser->Aflag) {
            ArgusProcessServiceAvailability(parser, ns);
            if (parser->xflag) {
               if ((parser->vflag && (ns->status & RA_SVCPASSED)) ||
                  (!parser->vflag && (ns->status & RA_SVCFAILED))) {
#ifdef ARGUSDEBUG
                  ArgusDebug (3, "RaProcessRecord (0x%x, 0x%x) service test failed", parser, ns); 
#endif
                  return;
               }
            }
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
            if (ArgusAggregator->ArgusMatrixMode) {
               struct ArgusFlow *flow = (struct ArgusFlow *) &ns->canon.flow;
               if (agg->mask & ((0x01LL << ARGUS_MASK_SADDR) | (0x01LL << ARGUS_MASK_DADDR))) {
                  switch (flow->hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_LAYER_3_MATRIX:
                     case ARGUS_FLOW_CLASSIC5TUPLE: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              if (flow->ip_flow.ip_src > flow->ip_flow.ip_dst)
                                 ArgusReverseRecord(ns);
                           }
                           break;

                           case ARGUS_TYPE_IPV6: {
                              int i;
                              for (i = 0; i < 4; i++) {
                                 if (flow->ipv6_flow.ip_src[i] < flow->ipv6_flow.ip_dst[i])
                                    break;

                                 if (flow->ipv6_flow.ip_src[i] > flow->ipv6_flow.ip_dst[i]) {
                                    ArgusReverseRecord(ns);
                                    break;
                                 }
                              }
                           }
                           break;
                        }
                        break;
                     }

                     default:
                        break;
                  }

               } else
               if (agg->mask & ((0x01LL << ARGUS_MASK_SMAC) | (0x01LL << ARGUS_MASK_DMAC))) {

                  struct ArgusMacStruct *m1 = NULL;
                  if ((m1 = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX]) != NULL) {
                     switch (m1->hdr.subtype) {
                        case ARGUS_TYPE_ETHER: {
                           struct ether_header *e1 = &m1->mac.mac_union.ether.ehdr;
                           int i;

                           for (i = 0; i < 6; i++) {
#if defined(HAVE_SOLARIS)
                              if (e1->ether_shost.ether_addr_octet[i] < e1->ether_dhost.ether_addr_octet[i])
                                 break;
                              if (e1->ether_shost.ether_addr_octet[i] > e1->ether_dhost.ether_addr_octet[i]) {
                                 ArgusReverseRecord(ns);
                                 break;
                              }
#else
                              if (e1->ether_shost[i] < e1->ether_dhost[i])
                                 break;
                              if (e1->ether_shost[i] > e1->ether_dhost[i]) {
                                 ArgusReverseRecord(ns);
                                 break;
                              }
#endif
                           }
                           break;
                        }
                     }
                  }
               }
            }

            RaProcessThisRecord(parser, ns);
         }
      }

      break;
   }
}


void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   int retn = 0;

   struct ArgusAggregatorStruct *agg = ArgusAggregator;
   struct ArgusHashStruct *hstruct = NULL;
   struct ArgusRecordStruct *tns;
   int found = 0;

   while (agg && !found) {
      struct nff_insn *fcode = agg->filter.bf_insns;

      if ((retn = ArgusFilterRecord (fcode, ns)) != 0) {
         if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
            agg->rap = agg->drap;

         ArgusGenerateNewFlow(agg, ns);

         if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

         if ((tns = ArgusFindRecord(agg->htable, hstruct)) != NULL) {
            double dur, nsst, tnsst, nslt, tnslt;
            if (parser->Aflag) {
               if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                  RaSendArgusRecord(tns);
                  ArgusZeroRecord(tns);
                  tns->status &= ~(RA_SVCTEST);
                  tns->status |= (ns->status & RA_SVCTEST);
               }
            }

            nsst  = ArgusFetchStartTime(ns);
            tnsst = ArgusFetchStartTime(tns);
            nslt  = ArgusFetchLastTime(ns);
            tnslt = ArgusFetchLastTime(tns);

            dur = ((tnslt > nslt) ? tnslt : nslt) - ((nsst < tnsst) ? nsst : tnsst); 
            
            if (agg->statusint && (dur >= agg->statusint)) {
               RaSendArgusRecord(tns);
               ArgusZeroRecord(tns);
            }

            ArgusMergeRecords (agg, tns, ns);

         } else {
            struct ArgusFlow *flow;

            if ((flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               if (!parser->RaMonMode) {
                  int tryreverse = 1;

                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_ESP:
                              tryreverse = 0;
                              break;
                        }
                        break;
                     }
                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_ESP:
                              tryreverse = 0;
                              break;
                        }
                        break;
                     }
                  }

                  if (tryreverse) {
                     if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                     if ((tns = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              switch (flow->ip_flow.ip_p) {
                                 case IPPROTO_ICMP: {
                                    struct ArgusICMPFlow *icmpFlow = &flow->flow_un.icmp;

                                    if (ICMP_INFOTYPE(icmpFlow->type)) {
                                       switch (icmpFlow->type) {
                                          case ICMP_ECHO:
                                          case ICMP_ECHOREPLY:
                                             icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                             if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                tns = ArgusFindRecord(agg->htable, hstruct);
                                             icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                             if (tns)
                                                ArgusReverseRecord (ns);
                                             break;

                                          case ICMP_ROUTERADVERT:
                                          case ICMP_ROUTERSOLICIT:
                                             icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                             if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                tns = ArgusFindRecord(agg->htable, hstruct);
                                             icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                             if (tns)
                                                ArgusReverseRecord (ns);
                                             break;

                                          case ICMP_TSTAMP:
                                          case ICMP_TSTAMPREPLY:
                                             icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                             if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                tns = ArgusFindRecord(agg->htable, hstruct);
                                             icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                             if (tns)
                                                ArgusReverseRecord (ns);
                                             break;

                                          case ICMP_IREQ:
                                          case ICMP_IREQREPLY:
                                             icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                             if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                tns = ArgusFindRecord(agg->htable, hstruct);
                                             icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                             if (tns)
                                                ArgusReverseRecord (ns);
                                             break;

                                          case ICMP_MASKREQ:
                                          case ICMP_MASKREPLY:
                                             icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                             if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                tns = ArgusFindRecord(agg->htable, hstruct);
                                             icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                             if (tns)
                                                ArgusReverseRecord (ns);
                                             break;
                                       }
                                    }
                                    break;
                                 }
                              }
                           }
                        }
                        if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                           ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                     } else {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              switch (flow->ip_flow.ip_p) {
                                 case IPPROTO_TCP: {
                                    struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)ns->dsrs[ARGUS_NETWORK_INDEX];
                                    if (tcp != NULL) {
                                       struct ArgusTCPObject *ttcp = (struct ArgusTCPObject *)tns->dsrs[ARGUS_NETWORK_INDEX];
                                       if (ttcp != NULL) {
                                          if ((tcp->status & ARGUS_SAW_SYN) && !(ttcp->status & ARGUS_SAW_SYN)) {
                                             ArgusReverseRecord (tns);
                                          } else
                                             ArgusReverseRecord (ns);
                                       } else
                                          ArgusReverseRecord (ns);
                                    } else
                                       ArgusReverseRecord (ns);
                                    break;
                                 }

                                 default:
                                    ArgusReverseRecord (ns);
                                    break;
                              }
                           }
                           break;

                           case ARGUS_TYPE_IPV6: {
                              switch (flow->ipv6_flow.ip_p) {
                                 case IPPROTO_TCP: {
                                    struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)ns->dsrs[ARGUS_NETWORK_INDEX];
                                    if (tcp != NULL) {
                                       struct ArgusTCPObject *ttcp = (struct ArgusTCPObject *)tns->dsrs[ARGUS_NETWORK_INDEX];
                                       if (ttcp != NULL) {
                                          if ((tcp->status & ARGUS_SAW_SYN) && !(ttcp->status & ARGUS_SAW_SYN)) {
                                             ArgusReverseRecord (tns);
                                          } else
                                             ArgusReverseRecord (ns);
                                       } else
                                          ArgusReverseRecord (ns);
                                    } else
                                       ArgusReverseRecord (ns);
                                    break;
                                 }

                                 default:
                                    ArgusReverseRecord (ns);
                                    break;
                              }
                           }
                           break;

                           default:
                              ArgusReverseRecord (ns);
                        }
                     }
                  }
               }
            }

            if (tns != NULL) {
               if (parser->Aflag) {
                  if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                     RaSendArgusRecord(tns);
                     ArgusZeroRecord(tns);
                  }
                  tns->status &= ~(RA_SVCTEST);
                  tns->status |= (ns->status & RA_SVCTEST);
               } else
                  ArgusMergeRecords (agg, tns, ns);

               ArgusRemoveFromQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);
               ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);

            } else {
               tns = ArgusCopyRecordStruct(ns);
               tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
               ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);
            }
         }

         if (agg->cont)
            agg = agg->nxt;
         else
            found++;

      } else
         agg = agg->nxt;
   }
}


int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{  
   struct ArgusRecord *argusrec = NULL;
   char buf[0x10000], argusbuf[0x10000];
   int retn = 1;

   if (argus->status & ARGUS_RECORD_WRITTEN)
      return (retn);
   
   if (ArgusParser->RaAgMode)
      argus->dsrs[ARGUS_AGR_INDEX] = NULL;
   
   if ((argusrec = ArgusGenerateRecord (argus, 0L, argusbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
      ArgusHtoN(argusrec);
#endif
      if (ArgusParser->ArgusWfileList != NULL) {
         struct ArgusWfileStruct *wfile = NULL;
         struct ArgusListObjectStruct *lobj = NULL;
         int i, count = ArgusParser->ArgusWfileList->count;
         
         if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
            for (i = 0; i < count; i++) {
               if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                  if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                     ArgusWriteNewLogfile (ArgusParser, wfile, argusrec);
                  }
               }
               lobj = lobj->nxt;
            }
         }
      
      } else {
         if (!ArgusParser->qflag) { 
            if (ArgusParser->Lflag) {
               if (ArgusParser->RaLabel == NULL)
                  ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, argus);
               
               if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag))
                  printf ("%s\n", ArgusParser->RaLabel);
               
               if (ArgusParser->Lflag < 0)
                  ArgusParser->Lflag = 0;
            }
            
            *(int *)&buf = 0;
            ArgusPrintRecord(ArgusParser, buf, argus, MAXSTRLEN);
            fprintf (stdout, "%s\n", buf);
            fflush(stdout);
         }
      }
   }
   
   argus->status |= ARGUS_RECORD_WRITTEN;
   return (retn);
}


void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}


#include <netdb.h>

struct RaSrvDescTableEntry {
   int srvDport, srvDaddr, proto, port;
   char *name, *desc;
};

struct RaSrvDescTableEntry *RaFindSrvHashObject (int, int);

void
RaPrintOutQueue (struct ArgusQueueStruct *queue, int level)
{
/*
   struct ArgusIPFlow *ipFlow = NULL;
   struct ArgusRecordStore *obj = NULL;
   struct ArgusRecordData *data = NULL;
   struct RaSrvDescTableEntry *dtblent = NULL;
   double value;
   int i = 0, n;

   struct ArgusAGRStruct *ArgusThisAgr = NULL;
   struct timeval  buf,  *time = &buf;
*/
   int num = ArgusParser->eNflag;

   if (queue != NULL) {
      ArgusSortQueue(ArgusSorter, queue);

      if (num == 0)
         num = queue->count;

/*
      for (n = 0; n < num; n++) {
         if ((obj = (struct ArgusRecordStore *) queue->array[n]) != NULL) {
            for (i = 0; i < RaHistoTimeSeries; i++) {
               if ((data = obj->data[i]) != NULL) {
                  ipFlow = &data->argus->argus_far.flow.ip_flow;

                  switch (level) {
                     case ARGUS_SERVICE:
                        printf("\n"); 
                        switch (ipFlow->ip_p) {
                           case IPPROTO_TCP: {
                              if ((ipFlow->dport == 0xFFFF) && (ipFlow->sport == 20)) {
                                 unsigned short port = ipFlow->sport;

                                 if ((dtblent = RaFindSrvHashObject(ipFlow->ip_p, port)) != NULL)
                                    printf("Service: %-8s src tcp port %-5d \"%s\"\n", dtblent->name, dtblent->port, dtblent->desc); 
                                 else
                                    printf("Service: %-8s src tcp port %-5d\n", tcpport_string(port), port); 
                              } else {
                                 unsigned short port = ipFlow->dport;

                                 if ((dtblent = RaFindSrvHashObject(ipFlow->ip_p, port)) != NULL)
                                    printf("Service: %-12s tcp port %-5d \"%s\"\n", dtblent->name, dtblent->port, dtblent->desc); 
                                 else
                                    printf("Service: %-12s tcp port %-5d\n", tcpport_string(port), port); 
                              }
                              fflush(stdout);
                              break;
                           }
         
                           case IPPROTO_UDP:
                              if ((dtblent = RaFindSrvHashObject(ipFlow->ip_p, ipFlow->dport)) != NULL)
                                 printf("Service: %-12s udp port %-5d \"%s\"\n", dtblent->name, dtblent->port, dtblent->desc); 
                              else
                                 printf("Service: %-12s udp port %-5d\n", udpport_string(ipFlow->dport), ipFlow->dport); 
                              fflush(stdout);
                              break;

                           case IPPROTO_IGMP:
                              printf("Service:  igmp:\n");
                              fflush(stdout);
                              break;
         
                           default:
                              printf("Service:  %s\n", get_ip_string(data->argus));
                              fflush(stdout);
                              break;
                        }
                        break;
         
                     case ARGUS_SERVICE_SUBNET:
                        break;

                     case ARGUS_SERVER:
                        printf("   Server: %-20.20s Trans           Mean (sec)\n",
                                     ipaddr_string(&ipFlow->ip_dst));
                        fflush(stdout);
                        break;

                     case ARGUS_CLIENT_SUBNET:
                        break;

                     case ARGUS_CLIENT:
                        if (data->act.n > 0) {
                           data->agr.act.meanval = data->act.sumtime/data->act.n;
                           value = (data->act.sumsqrd/data->act.n - pow (data->act.sumtime/data->act.n, 2.0));
                           data->agr.act.stdev = sqrt (value);
                           data->agr.act.n = data->act.n;
                        }

                        if (data->idle.n > 0) {
                           data->agr.idle.meanval = data->idle.sumtime/data->idle.n;
                           value = (data->idle.sumsqrd/data->idle.n - pow (data->idle.sumtime/data->idle.n, 2.0));
                           data->agr.idle.stdev = sqrt (value);
                           data->agr.idle.n = data->idle.n;
                        }
         
                        if ((ArgusThisAgr = (struct ArgusAGRStruct *) &data->agr)) {
                           int ArgusThisMultiplier = 1000;

                           if (ArgusThisAgr->status & ARGUS_AGR_USECACTTIME)
                              ArgusThisMultiplier = 1000000;

                           time->tv_sec  = ArgusThisAgr->act.meanval / ArgusThisMultiplier;
                           time->tv_usec = ArgusThisAgr->act.meanval % ArgusThisMultiplier;

                        }

                        printf("          %15.15s:      %5d  %4d.%06d ", ipaddr_string(&ipFlow->ip_src),
                                            data->agr.count, (int) time->tv_sec, (int) time->tv_usec);

                        if ((ArgusThisAgr = (struct ArgusAGRStruct *) &data->agr)) {
                           int ArgusThisMultiplier = 1000;

                           if (ArgusThisAgr->status & ARGUS_AGR_USECACTTIME)
                              ArgusThisMultiplier = 1000000;

                           time->tv_sec  = ArgusThisAgr->act.stdev / ArgusThisMultiplier;
                           time->tv_usec = ArgusThisAgr->act.stdev % ArgusThisMultiplier;
                        }

                        printf(" +/- %d.%06d\n", (int) time->tv_sec, (int) time->tv_usec);

                        break;
                  }
               }
            }

            if (Hflag && (level == ARGUS_CLIENT))
               printf("\n");

            fflush(stdout);

            RaPrintOutQueue (obj->queue, level + 1);

         } else
            break;
      }
*/
   }
}
