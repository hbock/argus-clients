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
 * racluster.c  - command line aggregation.
 *
 * written by Carter Bullard
 * QoSient, LLC 2003
 *
 */

/* 
 * $Id: //depot/argus/clients/clients/racluster.c#46 $
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



void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   int correct = 1;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "nocorrect", 9)))
               correct = 0;
            if (!(strncasecmp (mode->mode, "rmon", 4)))
               parser->RaMonMode++;
            if (!(strncasecmp (mode->mode, "norep", 5)))
               parser->RaAgMode++;
            if (!(strncasecmp (mode->mode, "ind", 3)))
               ArgusProcessFileIndependantly = 1;
            if (!(strncasecmp (mode->mode, "replace", 7))) {
               ArgusProcessFileIndependantly = 1;
               parser->ArgusReplaceMode++;
               if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
                  ArgusLog (LOG_ERR, "replace mode and -w option are incompatible\n");
               }
            }

            mode = mode->nxt;
         }
      }

      if ((parser->ArgusMaskList) == NULL)
         parser->ArgusReverse = 1;

      if (parser->ArgusFlowModelFile) {
         if ((parser->ArgusAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");
        
      } else 
         if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if (correct == 0) {
         if (parser->ArgusAggregator->correct != NULL)
            free(parser->ArgusAggregator->correct);
         parser->ArgusAggregator->correct = NULL;
      }
      
      if (parser->Hstr)
         if (!(ArgusHistoMetricParse (parser, parser->ArgusAggregator)))
            usage ();

      if (parser->vflag)
         ArgusReverseSortDir++;

      parser->RaInitialized++;
   }
}


void
RaArgusInputComplete (struct ArgusInput *input)
{
   if (ArgusProcessFileIndependantly) {
      ArgusParser->ArgusCurrentFile = input;
      RaParseComplete (0);

      ArgusParser->RaInitialized = 0;
      ArgusParser->ArgusCurrentFile = NULL;
      ArgusClientInit(ArgusParser);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (7, "RaArgusInputComplete(0x%x) done", input);
#endif
}

void
RaParseComplete (int sig)
{
   struct ArgusModeStruct *mode = NULL;
   int i = 0, x = 0, nflag = ArgusParser->eNflag;
   struct ArgusInput *file = ArgusParser->ArgusCurrentFile;
   char buf[MAXSTRLEN];
   int label;

   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {
         struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

         ArgusParser->RaParseCompleting += sig;

         if (ArgusParser->ArgusReplaceMode && file) {

            if (!(ArgusParser->ArgusRandomSeed))
               srandom(ArgusParser->ArgusRandomSeed);

            srandom (ArgusParser->ArgusRealTime.tv_usec);
            label = random() % 100000;

            bzero(buf, sizeof(buf));
            snprintf (buf, MAXSTRLEN, "%s.tmp%d", file->filename, label);

            setArgusWfile(ArgusParser, buf, NULL);
         }
 
         while (agg != NULL) {
            if (agg->queue->count) {
               struct ArgusRecordStruct *argus;

               if (!(ArgusSorter))
                  if ((ArgusSorter = ArgusNewSorter()) == NULL)
                     ArgusLog (LOG_ERR, "RaParseComplete: ArgusNewSorter error %s", strerror(errno));

               if ((mode = ArgusParser->ArgusMaskList) != NULL) {
                  while (mode) {
                     for (x = 0; x < MAX_SORT_ALG_TYPES; x++) {
                        if (!strncmp (ArgusSortKeyWords[x], mode->mode, strlen(ArgusSortKeyWords[x]))) {
                           ArgusSorter->ArgusSortAlgorithms[i++] = ArgusSortAlgorithmTable[x];
                           break;
                        }
                     }

                     mode = mode->nxt;
                  }
               }

               ArgusSortQueue (ArgusSorter, agg->queue);
       
               argus = ArgusCopyRecordStruct((struct ArgusRecordStruct *) agg->queue->array[0]);

               if (nflag == 0)
                  ArgusParser->eNflag = agg->queue->count;
               else
                  ArgusParser->eNflag = nflag > agg->queue->count ? agg->queue->count : nflag;

               for (i = 1; i < ArgusParser->eNflag; i++)
                  ArgusMergeRecords (agg, argus, (struct ArgusRecordStruct *)agg->queue->array[i]);

               ArgusParser->ns = argus;

               for (i = 0; i < ArgusParser->eNflag; i++)
                  RaSendArgusRecord ((struct ArgusRecordStruct *) agg->queue->array[i]);

               ArgusDeleteRecordStruct(ArgusParser, ArgusParser->ns);
            }

            agg = agg->nxt;
         }

         if (ArgusParser->ArgusAggregator != NULL)
            ArgusDeleteAggregator(ArgusParser, ArgusParser->ArgusAggregator);

         if (ArgusParser->ArgusReplaceMode && file) {
            if (ArgusParser->ArgusWfileList != NULL) {
               struct ArgusWfileStruct *wfile = NULL;

               if ((wfile = (void *)ArgusParser->ArgusWfileList->start) != NULL) {
                  fflush (wfile->fd);
                  rename (wfile->filename, file->filename);
                  fclose (wfile->fd);
                  wfile->fd = NULL;
               }

               ArgusDeleteList(ArgusParser->ArgusWfileList, ARGUS_WFILE_LIST);
               ArgusParser->ArgusWfileList = NULL;

               if (ArgusParser->Vflag)
                  ArgusLog(LOG_INFO, "file %s aggregated", file->filename);
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

   ArgusParser->eNflag = nflag;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaParseComplete(%d) done", sig);
#endif
}


void
ArgusClientTimeout ()
{
   struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

   while (agg) {
      int i, count;

      if ((count = agg->queue->count) > 0) {
         for (i = 0; i < count; i++) {
            struct ArgusRecordStruct *ns = (void *) ArgusPopQueue(agg->queue, ARGUS_LOCK);
            double nsst = ArgusFetchStartTime(ns);
            double nslt = ArgusFetchLastTime(ns);
            double glt  = (double)(ArgusParser->ArgusGlobalTime.tv_sec * 1.0) + (double)(ArgusParser->ArgusGlobalTime.tv_usec/1000000.0);

            if (agg->statusint && ((glt - nsst) >= agg->statusint)) {
               RaSendArgusRecord(ns);

            } else {
               if (agg->idleint && ((glt - nslt) >= agg->idleint)) {
                  ArgusRemoveHashEntry(&ns->htblhdr);
                  RaSendArgusRecord(ns);
                  ArgusDeleteRecordStruct (ArgusParser, ns);
                  ns = NULL;
               }
            }

            if (ns != NULL)
               ArgusAddToQueue(agg->queue, &ns->qhdr, ARGUS_LOCK);
         }
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
   fprintf (stderr, "usage:  %s [-f racluster.conf]\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage:  %s [-f racluster.conf] [ra-options] [- filter-expression]\n\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "options:  -f <racluster.conf>      read aggregation rules from <racluster.conf>.\n");
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
         struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

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

         if (parser->RaMonMode && (flow != NULL)) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(ns);
            struct ArgusFlow *flow;

            if ((flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);

            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);
            
         } else {
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
         
            if (flow && agg && agg->ArgusMatrixMode) {
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
         break;
      }
   }
}


void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{

   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusHashStruct *hstruct = NULL;
   int found = 0;

   while (agg && !found) {
      int retn = 0, fretn = -1, lretn = -1;
      if (agg->filterstr) {
         struct nff_insn *fcode = agg->filter.bf_insns;
         fretn = ArgusFilterRecord (fcode, argus);
      }

      if (agg->labelstr) {
         struct ArgusLabelStruct *label;
         if (((label = (void *)argus->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
            if (regexec(&agg->lpreg, label->l_un.label, 0, NULL, 0))
               lretn = 0;
            else
               lretn = 1;
         } else
            lretn = 0;
      }

      retn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

      if (retn != 0) {
         struct ArgusRecordStruct *tns, *ns = ArgusCopyRecordStruct(argus);

         if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
            agg->rap = agg->drap;

         ArgusGenerateNewFlow(agg, ns);

         if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

         if ((tns = ArgusFindRecord(agg->htable, hstruct)) != NULL) {
            if (parser->Aflag) {
               if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                  RaSendArgusRecord(tns);
                  tns->status &= ~(RA_SVCTEST);
                  tns->status |= (ns->status & RA_SVCTEST);
               }
            }

            if (tns->status & ARGUS_RECORD_WRITTEN) {
               ArgusZeroRecord (tns);

            } else {
               double dur, nsst, tnsst, nslt, tnslt;

               nsst  = ArgusFetchStartTime(ns);
               tnsst = ArgusFetchStartTime(tns);
               nslt  = ArgusFetchLastTime(ns);
               tnslt = ArgusFetchLastTime(tns);

               dur = ((tnslt > nslt) ? tnslt : nslt) - ((nsst < tnsst) ? nsst : tnsst); 
               
               if (agg->statusint && (dur >= agg->statusint)) {
                  RaSendArgusRecord(tns);
                  ArgusZeroRecord(tns);
               } else {
                  dur = ((tnslt > nslt) ? tnslt : nslt) - ((nsst < tnsst) ? nsst : tnsst);
                  if (agg->idleint && (dur >= agg->idleint)) {
                     RaSendArgusRecord(tns);
                     ArgusZeroRecord(tns);
                  }
               }
            }

            ArgusMergeRecords (agg, tns, ns);
            ArgusDeleteRecordStruct(parser, ns);

         } else {
            struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
            if (!parser->RaMonMode && parser->ArgusReverse) {
               int tryreverse = 0;

               if (flow != NULL) {
                  if (agg->correct != NULL)
                     tryreverse = 1;

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
               } else
                  tryreverse = 0;

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

            if (tns != NULL) {
               if (parser->Aflag) {
                  if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST))
                     RaSendArgusRecord(tns);

                  tns->status &= ~(RA_SVCTEST);
                  tns->status |= (ns->status & RA_SVCTEST);
               } else
                  ArgusMergeRecords (agg, tns, ns);

               ArgusRemoveFromQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);
               ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);
               ArgusDeleteRecordStruct (parser, ns);

            } else {
               tns = ns;
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

   if (ArgusParser->RaAgMode)
      argus->dsrs[ARGUS_AGR_INDEX] = NULL;

   if (argus->status & ARGUS_RECORD_WRITTEN)
      return (retn);

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
                  int pass = 1;
                  if (wfile->filterstr) {
                     struct nff_insn *wfcode = wfile->filter.bf_insns;
                     pass = ArgusFilterRecord (wfcode, argus);
                  }

                  if (pass != 0) {
                     if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                        ArgusWriteNewLogfile (ArgusParser, argus->input, wfile, argusrec);
                     }
                  }

                  lobj = lobj->nxt;
               }
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
