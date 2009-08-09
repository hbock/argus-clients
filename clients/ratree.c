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
 * ratree  - build patricia tree of addresses in file.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/argus/clients/clients/ratree.c#14 $
 * $DateTime: 2009/04/13 19:15:53 $
 * $Change: 1710 $
 */

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>

#include <math.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_label.h>
#include <argus_client.h>
#include <argus_filter.h>
#include <argus_main.h>
#include <argus_cluster.h>

int ArgusDebugTree = 0;

/*
   IANA style address label configuration file syntax is:
      addr "label"

      where addr is:
         %d[[[.%d].%d].%d]/%d   CIDR address
         CIDR - CIDR            Address range

   The Regional Internet Registries (RIR) database support allows for
   country codes to be associated with address prefixes.  We'll treat
   them as simple labels.   The file syntax is:

      rir|co|[asn|ipv4|ipv6]|#allocatable|[allocated | assigned]

   So if we find '|', we know the format.

   This is a sample line out of delegated-ipv4.conf which is supplied in this distribution
      delegated-arin-latest:arin|US|ipv4|208.0.0.0|2359296|19960313|allocated
*/


#define ARGUS_EXACT_MATCH	0
#define ARGUS_LONGEST_MATCH	1
#define ARGUS_ANY_MATCH		2

#define ARGUS_VISITED		0x10


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if ((ArgusLabeler = ArgusNewLabeler(parser, ARGUS_LABELER_ADDRESS)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if ((ArgusLabeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
         ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusCalloc error %s\n", strerror(errno));

      parser->ArgusLabeler = ArgusLabeler;

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE_VISITED;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "debug.mol", 9))) {
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_MOL;

               RaMapLabelMol (ArgusLabeler, ArgusLabeler->ArgusAddrTree[AF_INET], 0, 0, 0, 0);
               RaPrintLabelMol (ArgusLabeler, ArgusLabeler->ArgusAddrTree[AF_INET], 0, 0, 0, 0);
               exit(0);
            } else
            if ((!(strncasecmp (mode->mode, "debug.tree", 10))) ||
                (!(strncasecmp (mode->mode, "debug", 5)))) {
               ArgusDebugTree = 1;
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
               RaPrintLabelTree (ArgusLabeler, ArgusLabeler->ArgusAddrTree[AF_INET], 0, 0);
            } else
            if (!(strncasecmp (mode->mode, "graph", 5))) {
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_GRAPH;
            } else
            if (!(strncasecmp (mode->mode, "rmon", 4)))
               parser->RaMonMode++;

            mode = mode->nxt;
         }
      }

      if (parser->Lflag > 0) {
         extern int RaPrintLabelTreeLevel;
         RaPrintLabelTreeLevel = parser->Lflag - 1;
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
      }

      if (ArgusLabeler && (ArgusLabeler->ArgusAddrTree && (ArgusLabeler->ArgusAddrTree[AF_INET] != NULL))) {
         RaPruneAddressTree(ArgusLabeler, ArgusLabeler->ArgusAddrTree[AF_INET], 0);
         RaPrintLabelTree (ArgusLabeler, ArgusLabeler->ArgusAddrTree[AF_INET], 0, 0);
      }
      fflush(stdout);
      exit(0);
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
   fprintf (stderr, "Ratree Version %s\n", version);
   fprintf (stderr, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [options] [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -f <conffile>     read service signatures from <conffile>.\n");
   exit(1);
}

void RaProcessAddress (struct ArgusParserStruct *, struct ArgusRecordStruct *, unsigned int *, int, int);

void
RaProcessAddress (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, unsigned int *addr, int type, int level)
{
   struct RaAddressStruct *raddr;

   if (ArgusLabeler->ArgusAddrTree != NULL) {
      if (addr && *addr) {
         switch (type) {
            case ARGUS_TYPE_IPV4: {
               struct RaAddressStruct *node = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*node));

               if (level == 0)
                  level = 32;

               if (node != NULL) {
                  node->addr.type = AF_INET;
                  node->addr.len = 4;
                  node->addr.masklen = level;
                  node->addr.addr[0] = *addr;
                  node->addr.mask[0] = 0xFFFFFFFF << (32 - level);

                  if ((raddr = RaFindAddress (parser, ArgusLabeler->ArgusAddrTree[node->addr.type], node, ARGUS_EXACT_MATCH)) == NULL) {
                     RaInsertAddress (parser, ArgusLabeler, ArgusLabeler->ArgusAddrTree[node->addr.type], node, ARGUS_VISITED);
                  } else {
                     ArgusFree(node);
                     node = raddr;
                  }

                  while (node != NULL) {
                     if (node->ns != NULL)
                        ArgusMergeRecords (parser->ArgusAggregator, node->ns, argus);
                     else
                        node->ns = ArgusCopyRecordStruct(argus);
                     node = node->p;
                  }
               }
               break;
            }

            case ARGUS_TYPE_IPV6:
               break;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessAddress (0x%x, 0x%x, 0x%x, %d, %d) returning\n", parser, argus, addr, type, level);
#endif
}


void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT:
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(ns);
            struct ArgusFlow *flow;

            if ((flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);

            ArgusReverseRecord(tns);

            if ((flow = (struct ArgusFlow *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }
    
            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else {
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;

            if (agg && agg->ArgusMatrixMode) {
               if (agg->mask & ((0x01 << ARGUS_MASK_SADDR) | (0x01 << ARGUS_MASK_DADDR))) {
                  struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];

                  if (flow != NULL) {
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
                  }

               } else
               if (agg->mask & ((0x01 << ARGUS_MASK_SMAC) | (0x01 << ARGUS_MASK_DMAC))) {

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
   }

   if (ArgusDebugTree)
      if (ArgusLabeler && (ArgusLabeler->ArgusAddrTree && (ArgusLabeler->ArgusAddrTree[AF_INET] != NULL))) {
         fprintf (stdout, "----------------------\n");
         RaPrintLabelTree (ArgusLabeler, ArgusLabeler->ArgusAddrTree[AF_INET], 0, 0);
         fprintf (stdout, "----------------------\n");
      }
}

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   char buf[0x10000];

   if ((agg->rap = RaFlowModelOverRides(agg, argus)) == NULL)
      agg->rap = agg->drap;

   ArgusGenerateNewFlow(agg, argus);

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
/*
         if (parser->Lflag) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);
 
            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);
 
            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }
*/
         *(int *)&buf = 0;
         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
         fprintf (stdout, "%s ", buf);
      }
   }

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (flow) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4:
                        if (agg->mask & ARGUS_MASK_SADDR_INDEX)
                           RaProcessAddress(parser, argus, &flow->ip_flow.ip_src, ARGUS_TYPE_IPV4, agg->saddrlen);
                        if (agg->mask & ARGUS_MASK_DADDR_INDEX)
                           RaProcessAddress(parser, argus, &flow->ip_flow.ip_dst, ARGUS_TYPE_IPV4, agg->daddrlen);
                        break;
                     case ARGUS_TYPE_IPV6:
                        if (agg->mask & ARGUS_MASK_SADDR_INDEX)
                           RaProcessAddress(parser, argus, (unsigned int *) &flow->ipv6_flow.ip_src, ARGUS_TYPE_IPV6, agg->saddrlen);
                        if (agg->mask & ARGUS_MASK_DADDR_INDEX)
                           RaProcessAddress(parser, argus, (unsigned int *) &flow->ipv6_flow.ip_dst, ARGUS_TYPE_IPV6, agg->daddrlen);
                        break;
                  }
                  break; 
               }
            }
         }
         break;
      }
   }

   if ((parser->ArgusWfileList == NULL) && !parser->qflag)
      fprintf (stdout, "\n");

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
