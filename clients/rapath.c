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
 * rapath - print derivable path information from argus data.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/argus/clients/clients/rapath.c#23 $
 * $DateTime: 2009/07/22 18:40:35 $
 * $Change: 1767 $
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

#include <math.h>

int RaInitialized = 0;
int RaPrintThinkMapOutput = 0;
int RaPrintSVGOutput = 0;
int RaPrintASpath = 0;

extern int RaHistoStart;
extern int RaHistoEnd;

struct ArgusQueueStruct *ArgusModelerQueue;

int RaCompareArgusStore (const void *, const void *);
void RaPackQueue (struct ArgusQueueStruct *);
void RaSortQueue (struct ArgusQueueStruct *);
void RaProcessQueue(struct ArgusQueueStruct *, unsigned char);

#define RAMAP_ETHER_MAC_ADDR            0x1
#define RAMAP_IP_ADDR                   0x10

#define MAX_OBJ_SIZE            1024
unsigned int RaMapHash = 0;
unsigned int RaHashSize  = 0;

struct RaMapHashTableStruct {
   int size;
   struct RaMapHashTableHeader **array;
};
 
struct RaMapHashTableHeader {
   struct ArgusQueueHeader qhdr;
   struct RaMapHashTableHeader *nxt, *prv;
   unsigned int hash;
   int type, len, value, mask, visited;
   void *obj, *sub;
};
 
struct ArgusHashTable *ArgusHashTable;
struct RaMapHashTableStruct RaMapAddrTable;
struct RaMapHashTableHeader *RaMapFindHashObject (struct RaMapHashTableStruct *, void *, int, int);
struct RaMapHashTableHeader *RaMapAddHashEntry (struct RaMapHashTableStruct *, void *, int, int);
void RaMapRemoveHashEntry (struct RaMapHashTableStruct *, struct RaMapHashTableHeader *);


unsigned int RaMapCalcHash (void *, int, int);

char *ArgusAggregationConfig[] = {
   "filter=\"icmpmap\" model=\"saddr daddr proto sttl inode\"  status=120 idle=3600\n",
   "                   model=\"saddr daddr proto sttl\"        status=0   idle=3600\n",
   NULL,
};

#define ARGUS_RCITEMS    4

#define ARGUS_RC_FILTER  0
#define ARGUS_RC_MODEL   1
#define ARGUS_RC_STATUS  2
#define ARGUS_RC_IDLE    3

extern char *ArgusAggregatorFields[];

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;

   parser->RaWriteOut = 0;
 
   if (!(parser->RaInitialized)) {
      if (ArgusParser->RaSOptionStrings[0] == NULL) {
         parser->RaSOptionIndex = 0;
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("saddr");
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("dir");
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("daddr");
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("inode");
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("ias:8");
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("sttl");
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("avgdur");
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("stddev");
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("maxdur");
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("mindur");
         parser->RaSOptionStrings[parser->RaSOptionIndex++] = strdup("trans");
         ArgusProcessSOptions(parser);
      } 
      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strcasecmp (mode->mode, "think")))
               RaPrintThinkMapOutput++;
            if (!(strcasecmp (mode->mode, "svg")))
               RaPrintSVGOutput++;
            if (!(strcasecmp (mode->mode, "aspath")))
               RaPrintASpath++;
            mode = mode->nxt;
         }
      }

      if (parser->ArgusFlowModelFile) {
         if ((parser->ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

         RaLabelParseResourceFile (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile);
         parser->ArgusFlowModelFile = NULL;
      }

      if ((parser->ArgusAggregator = ArgusParseAggregator(parser, NULL, ArgusAggregationConfig)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((ArgusSorter = ArgusNewSorter()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));

      if (parser->vflag)
         ArgusReverseSortDir++;

      bzero ((char *) ArgusSorter->ArgusSortAlgorithms, sizeof(ArgusSorter->ArgusSortAlgorithms));
      ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[ARGUSSORTSRCADDR];
      ArgusSorter->ArgusSortAlgorithms[1] = ArgusSortAlgorithmTable[ARGUSSORTDSTADDR];
      ArgusSorter->ArgusSortAlgorithms[2] = ArgusSortAlgorithmTable[ARGUSSORTPROTOCOL];
      ArgusSorter->ArgusSortAlgorithms[3] = ArgusSortAlgorithmTable[ARGUSSORTSRCTTL];
      ArgusSorter->ArgusSortAlgorithms[4] = ArgusSortAlgorithmTable[ARGUSSORTTRANSACTIONS];
      ArgusSorter->ArgusSortAlgorithms[4] = ArgusSortAlgorithmTable[ARGUSSORTMINDURATION];
 
      if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
         exit(0);

      if ((ArgusHashTable = ArgusNewHashTable(RABINS_HASHTABLESIZE)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s\n", strerror(errno));

      if ((RaMapAddrTable.array = (struct RaMapHashTableHeader **) ArgusCalloc (RA_HASHTABLESIZE,
                                    sizeof (struct RaMapHashTableHeader *))) != NULL) {
         RaMapAddrTable.size = RA_HASHTABLESIZE;
      }

      parser->RaCumulativeMerge = 1;

      if (parser->Hflag) {
         if (!(ArgusHistoMetricParse (parser, parser->ArgusAggregator)))
            usage();
      }

      parser->Aflag = (parser->Aflag) ? 0 : 1;
      parser->RaInitialized++;
   }
}


void
ArgusClientTimeout ()
{
/*
   RaProcessQueue (ArgusModelerQueue, ARGUS_STATUS);
*/
#ifdef ARGUSDEBUG
      ArgusDebug (9, "ArgusClientTimeout() done\n");
#endif  
}


struct RaPathTreeNode {
   struct RaPathTreeNode *nxt;
   struct ArgusQueueStruct *nodes;
   int as, ttl;
};


struct RaPathTreeNode *RaPathBuildTree (struct RaPathTreeNode *, struct ArgusQueueStruct *);
void   RaPrintTree (struct RaPathTreeNode *);

/*
   The idea is to build the path tree for a given queue.  The queue
   should have ArgusRecordStruct's that have unique icmp->osrcaddr
   elements, sorted by sttl.  These queue elements represent the
   unique elements to deal with in this path and a path is constructed.

   Nodes in the path can be single elements,

*/

char nodeChar = 'A';
char RaTreeBuffer[MAXSTRLEN];
 
void RaPathInsertTree (struct RaPathTreeNode *, struct RaPathTreeNode *);
void RaPrintTreeNodes (struct RaPathTreeNode *, int);


struct RaPathTreeNode *
RaPathBuildTree (struct RaPathTreeNode *tree, struct ArgusQueueStruct *queue)
{
   struct RaPathTreeNode *path = NULL, *node = NULL;
   struct ArgusRecordStruct *argus;
   unsigned int pttl, tttl, as;

   if (queue->count > 0) {
      while ((argus = (struct ArgusRecordStruct *) ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
         struct ArgusIPAttrStruct *attr = (void *)argus->dsrs[ARGUS_IPATTR_INDEX];
         struct ArgusAsnStruct *asn = (void *)argus->dsrs[ARGUS_ASN_INDEX];

         tttl = attr->src.ttl;

         if (path == NULL) {
            if ((path = (struct RaPathTreeNode *) ArgusCalloc (1, sizeof (*node))) == NULL)
               ArgusLog (LOG_ERR, "ArgusCalloc error %s", strerror(errno));

            node = path;
            node->ttl = tttl;

            if ((asn !=  NULL) && (asn->hdr.argus_dsrvl8.len > 2)) 
               if ((as = asn->inode_as) != 0) {
                  node->as = as;
               }

            if ((node->nodes = ArgusNewQueue()) == NULL)
               ArgusLog (LOG_ERR, "ArgusNewQueue error %s", strerror(errno));

            ArgusAddToQueue (node->nodes, &argus->qhdr, ARGUS_NOLOCK);

         } else {
            struct ArgusIPAttrStruct *pattr = (void *)((struct ArgusRecordStruct *)node->nodes->start)->dsrs[ARGUS_IPATTR_INDEX];

            if ((pattr != NULL) && (attr != NULL)) {
               pttl = pattr->src.ttl;

               if (pttl == tttl) {
                  ArgusAddToQueue (node->nodes, &argus->qhdr, ARGUS_NOLOCK);

                  if ((asn !=  NULL) && (asn->hdr.argus_dsrvl8.len > 2))
                     if (node->as != asn->inode_as)
                        node->as = -1;
               } else {
                  struct RaPathTreeNode *prv = node;

                  if ((node = (struct RaPathTreeNode *) ArgusCalloc (1, sizeof (*node))) == NULL)
                     ArgusLog (LOG_ERR, "ArgusCalloc error %s", strerror(errno));

                  node->ttl = tttl;

                  if ((asn !=  NULL) && (asn->hdr.argus_dsrvl8.len > 2)) 
                     if ((as = asn->inode_as) != 0)
                        node->as = as;

                  prv->nxt = node;

                  if ((node->nodes = ArgusNewQueue()) == NULL)
                     ArgusLog (LOG_ERR, "ArgusNewQueue error %s", strerror(errno));

                  ArgusAddToQueue (node->nodes, &argus->qhdr, ARGUS_NOLOCK);
               }
            }
         }
      }
   }
 
   if (tree == NULL)
      tree = path;
   else 
      RaPathInsertTree (tree, path);

   return (tree);
}



void
RaPathInsertTree (struct RaPathTreeNode *tree, struct RaPathTreeNode *path)
{
}

void
RaPrintTreeNodes (struct RaPathTreeNode *tree, int level)
{
   struct RaPathTreeNode *path = tree;
   unsigned short as = 0;
   int status = 0, shop = 0;

   while (path != NULL) {
      struct ArgusQueueStruct *queue = path->nodes;
      struct ArgusRecordStruct *argus;
      int hopcount, multias = 0;

      if (status == 0) {
         if (path->as != 0) {
            if (path->as == -1) {
               multias = 1;
            } else {
               as = path->as;
               printf ("AS%d:", as);
               if (!RaPrintASpath)
                  printf ("[");
               else
                  printf ("%d", path->ttl);
               status++;
            }
         }
         shop = path->ttl;
         hopcount = 0;
      }

      if (queue->count > 1) {
         if (!RaPrintASpath || (RaPrintASpath && !status)) {
            printf ("{");
            while ((argus = (struct ArgusRecordStruct *) ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
               if (multias) {
                  struct ArgusAsnStruct *asn = (void *)argus->dsrs[ARGUS_ASN_INDEX];
                  if ((asn != NULL) && (asn->hdr.argus_dsrvl8.len > 2))
                     printf ("AS%d", asn->inode_as);
                     if (!RaPrintASpath)
                        printf (":[");
               }
               if (!RaPrintASpath)
                  printf ("%c", nodeChar);

               if (multias) {
                  if (!RaPrintASpath)
                     printf ("]");
               }

               if (queue->count > 0)
                  printf (",");
               nodeChar++;
            }
            printf ("}");
            if (RaPrintASpath)
               printf (":%d", path->ttl);
         }

      } else {
         if (!(RaPrintASpath && status)) {
            printf ("%c", nodeChar++);

            if (RaPrintASpath)
               printf (":%d", path->ttl);
         }
      }

      if ((path = path->nxt) != NULL) {
         if (status) {
            if (path->as != as) {
               if (!RaPrintASpath)
                  printf ("]");
               else {
                  if (hopcount > 0) {
                     printf ("-%d", shop + hopcount);
                     hopcount = 0;
                  }
                  printf (" -> ");
               }
               status--;
               as = 0;
            } else
               hopcount++;

         } else 
            if (RaPrintASpath)
               printf (" -> ");
         
         if (!RaPrintASpath)
            printf (" -> ");
         
      } else {
         if (status) {
            if (RaPrintASpath) {
               if (hopcount > 0)
                  printf ("-%d ", shop + hopcount);
            } else
               printf ("]");
         }
         printf ("\n");
      }
   }
}

void
RaPrintTree (struct RaPathTreeNode *tree)
{
   bzero (RaTreeBuffer, MAXSTRLEN);
   RaPrintTreeNodes(tree, 0);
   printf ("\n");
}


void RaArgusInputComplete (struct ArgusInput *input) { return; }


int RaParseCompleting = 0;

void
RaParseComplete (int sig)
{
   struct ArgusModeStruct *mode = NULL;
   int i = 0, x = 0, nflag = ArgusParser->eNflag;

   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {
         struct ArgusAggregatorStruct *pagg, *agg = ArgusParser->ArgusAggregator;

         ArgusParser->RaParseCompleting += sig;
 
         while ((pagg = agg) != NULL) {
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

               if (ArgusParser->Aflag)
                  RaPrintTree (RaPathBuildTree (NULL, agg->queue));

               nodeChar = 'A';
               for (i = 0; i < ArgusParser->eNflag; i++)
                  RaSendArgusRecord ((struct ArgusRecordStruct *) agg->queue->array[i]);
               ArgusFree(ArgusParser->ns);
            }

            agg = agg->nxt;
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
usage ()
{
   extern char version[];

   fprintf (stderr, "Rapath Version %s\n", version);
   fprintf (stderr, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [options]\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -D <level>       specify debug level\n");
   fprintf (stderr, "         -n               don't convert numbers to names.\n");
   fprintf (stderr, "         -r <filelist>    read argus data <filelist>. '-' denotes stdin.\n");
   fprintf (stderr, "         -S <host[:port]> specify remote argus <host> and optional port number.\n");
   fprintf (stderr, "         -t <timerange>   specify <timerange> for reading records.\n");
   fprintf (stderr, "                 format:  timeSpecification[-timeSpecification]\n");
   fprintf (stderr, "                          timeSpecification: [mm/dd[/yy].]hh[:mm[:ss]]\n");
   fprintf (stderr, "                                              mm/dd[/yy]\n");
   fprintf (stderr, "                                              -%%d{yMhdms}\n");
   fprintf (stderr, "         -T <secs>        attach to remote server for T seconds.\n");
#ifdef ARGUS_SASL
   fprintf (stderr, "         -U <user/auth>   specify <user/auth> authentication information.\n");
#endif
   exit(1);
}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaPrintArgusPath (struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusIcmpStruct *icmp = NULL;

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_LAYER_3_MATRIX:
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if (flow->ip_flow.ip_src > flow->ip_flow.ip_dst) {
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        int i;
                        for (i = 0; i < 4; i++) {
                           if (flow->ipv6_flow.ip_src[i] < flow->ipv6_flow.ip_dst[i])
                              break;

                           if (flow->ipv6_flow.ip_src[i] > flow->ipv6_flow.ip_dst[i]) {
                              break;
                           }
                        }
                        break;
                     }
                  }
                  break;
               }
               default:
                  return;
                  break;
            }

            if ((icmp = (struct ArgusIcmpStruct *) ns->dsrs[ARGUS_ICMP_INDEX]) != NULL) {
               if ((icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMPUNREACH_MAPPED) ||
                   (icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMPTIMXCED_MAPPED)) {

                  unsigned int srchost, dsthost, intnode;
       
                  srchost = flow->ip_flow.ip_src;
                  dsthost = flow->ip_flow.ip_dst;
       
                  intnode = icmp->osrcaddr;

                  if ((intnode == srchost) || (intnode == dsthost))
                     return;
               }

               switch (flow->ip_flow.ip_p) {
                  case IPPROTO_UDP:
                  case IPPROTO_TCP:
                     break;

                  case IPPROTO_ICMP:
                     break;

                  default:
                     break;
               }

               RaProcessThisRecord (parser, ns);
            }
         }
         break;
      }
   }
}


void RaUpdateArgusStorePath(struct ArgusRecord *, struct ArgusRecordStruct *);

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tns;
   struct ArgusHashStruct *hstruct = NULL;
   int retn = 0;

   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
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
            if (parser->Aflag) {
               if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                  RaSendArgusRecord(tns);
                  ArgusZeroRecord(tns);
                  tns->status &= ~(RA_SVCTEST);
                  tns->status |= (ns->status & RA_SVCTEST);
               }
            }
            ArgusMergeRecords (agg, tns, ns);

         } else {
            if (!parser->RaMonMode) {
               struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
               int tryreverse = 1;

               if (flow != NULL) {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_ESP:
                              tryreverse = 0;
                              break;
                        }
                     }
                  }
               }

               if (tryreverse) {
                  if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                     ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                  if ((tns = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
                     if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                  } else {
                     ArgusReverseRecord (ns);
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

            } else {
               tns = ArgusCopyRecordStruct(ns);
               ArgusAddHashEntry (agg->htable, tns, hstruct);
               ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);
            }
         }

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
               }
               lobj = lobj->nxt;
            }
         }

      } else {
         if (!ArgusParser->qflag) {
            if (ArgusParser->Lflag) {
               if (ArgusParser->RaLabel == NULL)
                  ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, argus);
 
               if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag)) {
                  if (ArgusParser->Aflag)
                     printf (" Node %s\n", ArgusParser->RaLabel);
                  else
                     printf ("%s\n", ArgusParser->RaLabel);
               }
 
               if (ArgusParser->Lflag < 0)
                  ArgusParser->Lflag = 0;
            }

            *(int *)&buf = 0;
            ArgusPrintRecord(ArgusParser, buf, argus, MAXSTRLEN);
            
            if (ArgusParser->Aflag) {
               fprintf (stdout, "  %c   %s\n", nodeChar++, buf);
            } else
               fprintf (stdout, "%s\n", buf);
            fflush(stdout);
         }
      }
   }

   argus->status |= ARGUS_RECORD_WRITTEN;
   return (retn);
}

/*

char *RaPrintTimeStats (struct ArgusRecord *, char *);

char *
RaPrintTimeStats (struct ArgusRecord *argus, char *str)
{
   char *retn = NULL;
   struct ArgusAGRStruct *agr;

   ArgusThisFarStatus = ArgusIndexRecord (argus, ArgusThisFarHdrs);

   if ((agr = (struct ArgusAGRStruct *) ArgusThisFarHdrs[ARGUS_AGR_DSR_INDEX]) != NULL) {
      retn = str;
      snprintf (retn, 256, "%7d +/- %-6d   max %7d  min %7d   n = %d", agr->act.meanval, agr->act.stdev,
                                                  agr->act.maxval, agr->act.minval, agr->act.n);
   }

   return (retn);
}

void
RaPrintArgusPath (struct ArgusRecordStruct *ns)
{
   char buf[MAXSTRLEN], *str = NULL;
   struct ArgusRecordStruct *obj = NULL;
   struct ArgusRecordData *data = NULL;
   struct ArgusRecord *argus = ns->data[0]->argus;
   struct ArgusAGRStruct *agr = NULL;
   unsigned int srchost, dsthost, intnode, ttl;
   char srcAddrString[64], dstAddrString[64], intAddrString[64];
   char statsbuf[256], *stats = statsbuf;
   char date[128];
   int i, len, pad, margin;

   str = get_ip_string (ns->data[0]->argus);
   printf ("%s\n", str);
   len = strlen(str);
   
   ArgusPrintDate (date, ns->data[0]->argus);

   pad = len - (strlen(date) + (3 * hfield) + (cflag ? ((4 * 10) + 3) : 0) + (Iflag ? 7 : 0) + (gflag ? 9 : 0));
 
   if (pad < hfield) {
      pad += 2 * hfield;
      hfield = pad / 3;
      pad = hfield;
   }

   if (ns->queue) {
      RaSortQueue(ns->queue);

      for (i = 0; i < ns->queue->count; i++) {
         struct ArgusICMPObject *icmp = NULL;

         if ((obj = (struct ArgusRecordStruct *) ns->queue->array[i]) == NULL)
            ArgusLog (LOG_ERR, "RaSortQueue array error");

         icmp = (struct ArgusICMPStruct *) obj->dsrs[ARGUS_ICMP_DSR_INDEX];

         data = obj->data[0];
         argus = data->argus;

         if (argus && (data->status & RA_MODIFIED)) {
            if (data->act.n > 0) {
               data->agr.act.n = data->act.n;
               data->agr.act.meanval = data->act.sumtime/data->act.n;
               data->agr.act.stdev = sqrt (data->act.sumsqrd/data->act.n - pow (data->act.sumtime/data->act.n, 2.0));
            }
            if (data->idle.n > 0) {
               data->agr.idle.n = data->idle.n;
               data->agr.idle.meanval = data->idle.sumtime/data->idle.n;
               data->agr.idle.stdev = sqrt (data->idle.sumsqrd/data->idle.n - pow (data->idle.sumtime/data->idle.n, 2.0));
            }

            ArgusThisFarStatus = ArgusIndexRecord(argus, ArgusThisFarHdrs);

            if ((agr = (struct ArgusAGRStruct *) ArgusThisFarHdrs[ARGUS_AGR_DSR_INDEX]) != NULL) {
               bcopy ((char *)&data->agr, (char *)agr, data->agr.length);

            } else {
               bcopy ((char *) argus, buf, argus->ahdr.length);
               argus = (struct ArgusRecord *) buf;
               ArgusThisFarStatus = ArgusIndexRecord(argus, ArgusThisFarHdrs);

               bcopy ((char *)&data->agr, &buf[argus->ahdr.length], data->agr.length);
               argus->ahdr.length += data->agr.length;
               argus->ahdr.status |= ARGUS_MERGED;
               ArgusFree (data->argus);
               data->argus = RaCopyArgusRecord(argus);
               ArgusThisFarStatus = ArgusIndexRecord(data->argus, ArgusThisFarHdrs);
            }
         }

         srchost = argus->argus_far.flow.ip_flow.ip_src;
         dsthost = argus->argus_far.flow.ip_flow.ip_dst;

         intnode = icmp->osrcaddr;
   
         ttl = argus->argus_far.attr_ip.sttl;
   
         snprintf(srcAddrString, 64, "%s", ipaddr_string(&srchost));
         snprintf(dstAddrString, 64, "%s", ipaddr_string(&dsthost));
         snprintf(intAddrString, 64, "%s", ipaddr_string(&intnode));

         stats = RaPrintTimeStats (argus, statsbuf);

         if (idflag)
            printf ("                ");

         margin = pad + ((2 * hfield) - (strlen(srcAddrString) + strlen(dstAddrString)));

         if (dsthost != intnode) {
            if (nflag)
               printf ("Path  %15.15s  ->  %15.15s    INode:  %15.15s  ",
                               srcAddrString, dstAddrString, intAddrString);
            else
               printf ("Path  %s  ->  %s    INode:  %*.*s  ",
                               srcAddrString, dstAddrString,
                               margin, margin, intAddrString);
         } else {
            if (nflag)
               printf ("Path  %15.15s  ->  %15.15s    TNode:  %15.15s  ",
                               srcAddrString, dstAddrString, intAddrString);
            else
               printf ("Path  %s  ->  %s    TNode:  %*.*s  ",
                               srcAddrString, dstAddrString,
                               margin, margin, intAddrString);
         }
         printf ("  Dis: %3d  %s\n", ttl, stats);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "RaPrintArgusPath (0x%x) returning\n", ns);
#endif
}


void
RaUpdateArgusStorePath(struct ArgusRecord *argus, struct ArgusRecordStruct *ns)
{
   int found = 0;
   struct ArgusRecordStruct *str;
   struct ArgusICMPObject *argicmp = (struct ArgusICMPObject *) ArgusThisFarHdrs[ARGUS_ICMP_DSR_INDEX];

   ns->status |= RA_MODIFIED;
   ns->qhdr.lasttime = ArgusParser->ArgusGlobalTime;

   if (ns->queue) {
      str = (struct ArgusRecordStruct *) ns->queue->start;
      do {
         struct ArgusICMPObject *stricmp = (struct ArgusICMPObject *) str->dsrs[ARGUS_ICMP_DSR_INDEX];

         if ((argus->argus_far.attr_ip.sttl == str->data[0]->argus->argus_far.attr_ip.sttl)) {
            if ((stricmp && argicmp) && (stricmp->osrcaddr == argicmp->osrcaddr)) {
               RaMergeArgusRecord(argus, str, 0);
               found++;
               break;
            }
         }
         str = (struct ArgusRecordStruct *) str->qhdr.nxt;
      } while (str != (struct ArgusRecordStruct *) ns->queue->start);

      if (!(found) && ((argus->argus_far.status & ARGUS_ICMPTIMXCED_MAPPED)  ||
                      ((argus->argus_far.status & ARGUS_ICMPUNREACH_MAPPED)  &&
                       (ns->queue->count > 0)))) {
         if (ns->queue && ((str = RaNewArgusStore(argus)) != NULL)) {
            if ((str->data[0] = RaNewArgusData(argus)) != NULL) {
               RaAddToQueue (ns->queue, &str->qhdr, ARGUS_NOLOCK);
               str->dsrstatus = ArgusIndexRecord (str->data[0]->argus, str->dsrs);
               str->status |= RA_MODIFIED;
            }
         }
      }

      if (str != NULL) {
         if (!(str->data[RaThisActiveIndex])) {
            struct ArgusRecordData *data = NULL;

            if ((data = RaNewArgusData(argus)) != NULL) {
               data->farhdrstatus = ArgusIndexRecord (data->argus, data->farhdrs);
               data->status |= RA_MODIFIED;

               if (data->farhdrstatus & ARGUS_AGR_DSR_STATUS) {
                  double sumtime;

                  bcopy((char *)data->farhdrs[ARGUS_AGR_DSR_INDEX], (char *)&data->agr, sizeof(data->agr));
                  data->act.n        = data->agr.act.n;
                  sumtime            = data->agr.act.meanval * data->agr.act.n;
                  data->act.sumtime  = sumtime;
                  data->act.sumsqrd  = (data->agr.act.n * pow(data->agr.act.stdev, 2.0)) + pow(sumtime, 2.0)/data->agr.act.n;

                  data->idle.n       = data->agr.idle.n;
                  sumtime            = data->agr.idle.meanval * data->agr.idle.n;
                  data->idle.sumtime = sumtime;
                  data->idle.sumsqrd = (data->agr.idle.n * pow(data->agr.idle.stdev, 2.0)) + pow(sumtime, 2.0)/data->agr.idle.n;
               }

               str->data[RaThisActiveIndex] = data;
            } else
               ArgusLog (LOG_ERR, "RaNewArgusData failed %s\n", strerror(errno));

         } else
            RaMergeArgusRecord(argus, str, RaThisActiveIndex);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "RaUpdateArgusStore: \n");
#endif
}

void RaPrintSVGHeader(void);
void RaPrintSVGFooter(void);
void RaPrintSVGFunctions(struct ArgusRecordStruct *);

void
RaPrintSVGHeader()
{
   extern char version[];

   fprintf (stdout, "<html>\n");
   fprintf (stdout, "<head>\n");
   fprintf (stdout, "<!-- Generated using %s %s -->\n", ArgusParser->ArgusProgramName, version);
   fprintf (stdout, "<script language=\"Javascript\">\n");
   fprintf (stdout, "<!--\n");

   fprintf (stdout, "   var ChartType = \"Histogram\"\n");
   fprintf (stdout, "   var TotalElements = %d\n", RaHistoMetricSeries);
   fprintf (stdout, "   var WidthStart = %f\n", RaHistoStart/1000000.0);
   fprintf (stdout, "   var WidthStop  = %f\n", RaHistoEnd/1000000.0);
   fprintf (stdout, "   var XAxisTickElements = 5\n\n");

   fflush(stdout);
}

void
RaPrintSVGFunctions(struct ArgusRecordStruct *ns)
{
   char buf[MAXSTRLEN], *ptr = buf;
   struct ArgusRecordStruct *obj = NULL;
   struct ArgusRecordData *data = NULL;
   struct ArgusRecord *argus = ns->data[0]->argus;
   struct ArgusAGRStruct *agr = NULL;
   unsigned int srchost, dsthost, intnode, ttl, i, x;
   char srcAddrString[64], dstAddrString[64], intAddrString[64];
   char sdate[128], ldate[128];
   int RaSeriesNumber = 0;

   bzero(sdate, sizeof(sdate));
   bzero(ldate, sizeof(ldate));

   ArgusPrintStartDate (sdate, ns->data[0]->argus);
   ArgusPrintLastDate (ldate, ns->data[0]->argus);

   if (ns->queue) {
      RaSortQueue(ns->queue);

      fprintf (stdout, "   var SeriesNumber = %d\n\n", ns->queue->count);

      fprintf (stdout, "   function Run() {\n");
      fprintf (stdout, "      Populate ()\n");
      fprintf (stdout, "      Display ()\n");
      fprintf (stdout, "   }\n\n");

      fprintf (stdout, "   function Populate() {\n");

      for (x = 0; x < ns->queue->count; x++) {
         struct ArgusICMPObject *icmp = NULL;

         if ((obj = (struct ArgusRecordStruct *) ns->queue->array[x]) == NULL)
            ArgusLog (LOG_ERR, "RaSortQueue array error");

         icmp = (struct ArgusICMPObject *) obj->dsrs[ARGUS_ICMP_DSR_INDEX];

         data = obj->data[0];
         argus = data->argus;

         if (argus && (obj->status & RA_MODIFIED)) {
            if (data->act.n > 0) {
               data->agr.act.meanval = data->act.sumtime/data->act.n;
               data->agr.act.stdev = sqrt (data->act.sumsqrd/data->act.n - pow (data->act.sumtime/data->act.n, 2.0));
            }
            if (data->idle.n > 0) {
               data->agr.idle.meanval = data->idle.sumtime/data->idle.n;
               data->agr.idle.stdev = sqrt (data->idle.sumsqrd/data->idle.n - pow (data->idle.sumtime/data->idle.n, 2.0));
            }
   
            data->agr.type   = ARGUS_AGR_DSR;
            data->agr.length = sizeof(data->agr);
            bcopy ((char *) argus, buf, argus->ahdr.length);
            bcopy ((char *)&data->agr,&buf[argus->ahdr.length], data->agr.length);
   
            argus = (struct ArgusRecord *) ptr;
            argus->ahdr.length += data->agr.length;
         }

         srchost = argus->argus_far.flow.ip_flow.ip_src;
         dsthost = argus->argus_far.flow.ip_flow.ip_dst;

         intnode = icmp->osrcaddr;

         ttl = argus->argus_far.attr_ip.sttl;

         snprintf(srcAddrString, 64, "%s", ipaddr_string(&srchost));
         snprintf(dstAddrString, 64, "%s", ipaddr_string(&dsthost));
         snprintf(intAddrString, 64, "%s", ipaddr_string(&intnode));

         if (dsthost != intnode) {
            ArgusThisFarStatus = ArgusIndexRecord (argus, ArgusThisFarHdrs);
 
            agr = (struct ArgusAGRStruct *) ArgusThisFarHdrs[ARGUS_AGR_DSR_INDEX];

            fprintf (stdout, "      window.addPathHost(%2d, %f, %f, %f, %f, %d)\n", RaSeriesNumber, 
                                                agr->act.meanval/1000000.0, agr->act.stdev/1000000.0,
                                                agr->act.maxval/1000000.0, agr->act.minval/1000000.0, agr->count);
            fprintf (stdout, "      window.addSeriesAttribute(%2d, \"%s\")\n", RaSeriesNumber, intAddrString);

         } else {
            fprintf (stdout, "      window.addPathTerminus(%2d, %f, %f, %f, %f, %d)\n", RaSeriesNumber, 
                                                agr->act.meanval/1000000.0, agr->act.stdev/1000000.0,
                                                agr->act.maxval/1000000.0, agr->act.minval/1000000.0, agr->count);
            fprintf (stdout, "      window.addSeriesAttribute(%2d, \"%s\")\n", RaSeriesNumber, dstAddrString);
         }

         for (i = 1; i < RaHistoMetricSeries; i++) {
            if ((data = obj->data[i]) != NULL) {
               argus = data->argus;

               if (argus && (obj->status & RA_MODIFIED)) {
                  if (data->act.n > 0) {
                     data->agr.act.meanval = data->act.sumtime/data->act.n;
                     data->agr.act.stdev = sqrt (data->act.sumsqrd/data->act.n - pow (data->act.sumtime/data->act.n, 2.0));
                  }
                  if (data->idle.n > 0) {
                     data->agr.idle.meanval = data->idle.sumtime/data->idle.n;
                     data->agr.idle.stdev = sqrt (data->idle.sumsqrd/data->idle.n - pow (data->idle.sumtime/data->idle.n, 2.0));
                  }

                  data->agr.type   = ARGUS_AGR_DSR;
                  data->agr.length = sizeof(data->agr);
                  bcopy ((char *) argus, buf, argus->ahdr.length);
                  bcopy ((char *)&data->agr,&buf[argus->ahdr.length], data->agr.length);

                  argus = (struct ArgusRecord *) ptr;
                  argus->ahdr.length += data->agr.length;
               }

               ArgusThisFarStatus = ArgusIndexRecord (argus, ArgusThisFarHdrs);

               agr = (struct ArgusAGRStruct *) ArgusThisFarHdrs[ARGUS_AGR_DSR_INDEX];

               fprintf (stdout, "      window.addArgusValue(%2d, %3d, %f, %d)\n", RaSeriesNumber, i - 1,
                                                agr->act.meanval/1000000.0, agr->count);
            }
         }

         obj = (struct ArgusRecordStruct *) obj->qhdr.nxt;
         RaSeriesNumber++;
      }

      fprintf (stdout, "   }\n\n");
      fprintf (stdout, "   function Display() {\n");
      fprintf (stdout, "      window.setTitle(\"Path Statistics\")\n");
      fprintf (stdout, "      window.setSubTitle1(\"%s -> %s\")\n",srcAddrString, dstAddrString);
      fprintf (stdout, "      window.setSubTitle2(\"%s- %s\")\n",sdate, ldate);
      fprintf (stdout, "      window.setXCaption(\"Duration\")\n");
      fprintf (stdout, "      window.setAxis(\"Transactions\")\n");
      fprintf (stdout, "      window.DrawPathTerminus()\n");
      fprintf (stdout, "      window.setCircles()\n");
      fprintf (stdout, "      window.DrawSeriesLine()\n");
      fprintf (stdout, "   }\n\n");
   }
}

void
RaPrintSVGFooter()
{

   fprintf (stdout, "//-->\n");
   fprintf (stdout, "</script>\n");
   fprintf (stdout, "<title>Current Histogram Demo</title></head>\n");
   fprintf (stdout, "<body bgcolor=\"#999999\" onload=\"Run()\">\n");
   fprintf (stdout, "   <embed name=\"histogram\" ");
   fprintf (stdout, "src=\"/histogram_long_multi.svg\" ");
   fprintf (stdout, "wmode=\"transparent\" ");
   fprintf (stdout, "width=\"800\" height=\"190\" ");
   fprintf (stdout, "type=\"image/svg+xml\" ");
   fprintf (stdout, "pluginspage=\"http://www.adobe.com/svg/viewer/install/\">\n");
   fprintf (stdout, "   </embed>\n");
   fprintf (stdout, "</body>\n");
   fprintf (stdout, "</html>\n");
   fflush(stdout);
}


#include <stdio.h>
#include <errno.h>

#define RA_MAXQSCAN  25600
#define RA_MAXQSIZE  250000
 
void
RaProcessQueue(struct ArgusQueueStruct *queue, unsigned char status)
{
   struct ArgusRecordStruct *obj = NULL;
   int cnt = 0;
 
   switch (status) {
      case ARGUS_STOP: {
         if (queue->count > 0) {
            if (RaPrintSVGOutput) {
               if (queue->count == 1)
                  RaPrintSVGHeader();
               else
                  ArgusLog (LOG_ERR, "svg mode and multiple paths: error\n");
            }

            while ((obj = (struct ArgusRecordStruct *) ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
               if (RaPrintSVGOutput) {
                  RaPrintSVGFunctions(obj);
               } else {
                  obj->status |= RA_MODIFIED;
                  RaTimeoutArgusStore(obj);
               }
            }

            if (RaPrintSVGOutput)
               RaPrintSVGFooter();
         }

         break;
      }

      default:
         while (queue->count > RA_MAXQSIZE) {
            obj = (struct ArgusRecordStruct *) RaRemoveFromQueue(ArgusModelerQueue, ArgusModelerQueue->start->prv);
            RaTimeoutArgusStore(obj);
         }

         if ((cnt = ((queue->count > RA_MAXQSCAN) ? RA_MAXQSCAN : queue->count)) != 0) {
            while (cnt--) {
               if ((obj = (struct ArgusRecordStruct *) ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
                  if (RaCheckTimeout(obj, NULL))
                     RaTimeoutArgusStore(obj);
                  else
                     RaAddToQueue(queue, &obj->qhdr, ARGUS_NOLOCK);

               } else
                  cnt++;
            }
         }
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessQueue (0x%x, %d) returning\n", queue, status);
#endif
}


int ArgusSeriesNumber = 0;



unsigned int
RaMapCalcHash (void *obj, int type, int len)
{
   u_char buf[MAX_OBJ_SIZE];
   unsigned int retn = 0;

   switch (type) {
      case RAMAP_ETHER_MAC_ADDR:
          len = 6;
          break;

      case RAMAP_IP_ADDR:
          len = 4;
          break;

      default:
          break;
   }

   bzero (buf, sizeof buf);

   if (RaHashSize <= 0x100) {
      unsigned char hash = 0, *ptr = (unsigned char *) buf;
      int i, nitems = len;

      bcopy ((char *) obj, (char *)&buf, len);

      for (i = 0; i < nitems; i++)
         hash += *ptr++;

      retn = hash;

   } else
   if (RaHashSize <= 0x10000) {
      unsigned short hash = 0, *ptr = (unsigned short *) buf;
      int i, nitems = (len / sizeof(unsigned short)) + 2;

      bcopy ((char *) obj, &buf[1], len);

      for (i = 0; i < nitems; i++)
         hash += *ptr++;

      retn = hash;

   } else {
      unsigned int hash = 0, *ptr = (unsigned int *) buf;
      int i, nitems = (len /sizeof(unsigned int)) + 2;

      bcopy ((char *) obj, &buf[3], len);

      for (i = 0; i < nitems; i++)
         hash += *ptr++;

      retn = hash;
   }

   return (retn);
}



struct RaMapHashTableHeader *
RaMapFindHashObject (struct RaMapHashTableStruct *table, void *obj, int type, int len)
{
   struct RaMapHashTableHeader *retn = NULL, *head = NULL, *target;
   int RaMapHash = 0;

   RaMapHash = RaMapCalcHash (obj, type, len);

   if ((target = table->array[RaMapHash % table->size]) != NULL) {
      head = target;
      do {
         if ((type == target->type) && (len == target->len)) {
            if (!(bcmp ((char *) obj, (char *) target->obj, len))) {
               retn = target;
               break;
            }
         }

         target = target->nxt;
      } while (target != head);
   }

#ifdef TCPCLEANDEBUG
   RaMapDebug (6, "RaMapFindHashEntry () returning 0x%x RaMapHash %d\n", retn, RaMapHash);
#endif
 
   return (retn);
}


struct RaMapHashTableHeader *
RaMapAddHashEntry (struct RaMapHashTableStruct *table, void *oid, int type, int len)
{
   struct RaMapHashTableHeader *retn = NULL, *start = NULL;

   if ((retn = (struct RaMapHashTableHeader *) ArgusCalloc (1, sizeof (struct RaMapHashTableHeader))) != NULL) {
      RaMapHash = RaMapCalcHash (oid, type, len);

      retn->hash = RaMapHash;
      retn->type = type;
      retn->len  = len;

      if ((retn->obj = (void *) ArgusCalloc (1, len)) == NULL)
         ArgusLog (LOG_ERR, "RaMapAddHashEntry: ArgusCalloc error %s\n", strerror(errno));
      else
         bcopy ((char *) oid, (char *)retn->obj, len);
      
      if ((start = table->array[RaMapHash % table->size]) != NULL) {
         retn->nxt = start;
         retn->prv = start->prv;
         retn->prv->nxt = retn;
         retn->nxt->prv = retn;
      } else
         retn->prv = retn->nxt = retn;

      table->array[RaMapHash % table->size] = retn;
   }

#ifdef TCPCLEANDEBUG
   RaMapDebug (3, "RaMapAddHashEntry (0x%x, %d, %d) returning 0x%x\n", oid, type, len, retn);
#endif

   return (retn);
}

 
void
RaMapRemoveHashEntry (struct RaMapHashTableStruct *table, struct RaMapHashTableHeader *htblhdr)
{
   unsigned short hash = htblhdr->hash;

   htblhdr->prv->nxt = htblhdr->nxt;
   htblhdr->nxt->prv = htblhdr->prv;

   if (htblhdr == table->array[hash % table->size]) {
      if (htblhdr == htblhdr->nxt)
         table->array[hash % table->size] = NULL;
      else
         table->array[hash % table->size] = htblhdr->nxt;
   }

   ArgusFree (htblhdr);

#ifdef TCPCLEANDEBUG
   RaMapDebug (6, "RaMapRemoveHashEntry (0x%x) returning\n", htblhdr);
#endif
}

*/

void ArgusWindowClose(void) { } 
