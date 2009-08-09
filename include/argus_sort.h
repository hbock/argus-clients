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
 * $Id: //depot/argus/argus-3.0/clients/include/argus_sort.h#16 $
 * $DateTime: 2006/03/31 13:25:33 $
 * $Change: 793 $
 */

#ifndef ArgusSort_h
#define ArgusSort_h


#define ARGUS_MAX_SORT_ALG		60
#define MAX_SORT_ALG_TYPES		60

struct ArgusSortRecord {
   struct ArgusQueueHeader qhdr;
   struct ArgusRecordStruct *record;
};

struct ArgusSorterStruct {
   int ArgusSortOptionIndex, ArgusReplaceMode;
   struct ArgusQueueStruct *ArgusRecordQueue;
   int (*ArgusSortAlgorithms[ARGUS_MAX_SORT_ALG])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
   int (*ArgusSortAlgorithm)(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
   char *ArgusSOptionStrings[ARGUS_MAX_S_OPTIONS];
   struct nff_program filter;
};

#define ARGUSSORTSTARTTIME		1
#define ARGUSSORTLASTTIME		2
#define ARGUSSORTTRANSACTIONS		3
#define ARGUSSORTDURATION		4
#define ARGUSSORTAVGDURATION		5
#define ARGUSSORTMINDURATION		6
#define ARGUSSORTMAXDURATION		7
#define ARGUSSORTSRCMAC			8
#define ARGUSSORTDSTMAC			9
#define ARGUSSORTSRCADDR		10
#define ARGUSSORTDSTADDR		11
#define ARGUSSORTPROTOCOL		12
#define ARGUSSORTSRCIPID		13
#define ARGUSSORTDSTIPID		14
#define ARGUSSORTSRCPORT		15
#define ARGUSSORTDSTPORT		16
#define ARGUSSORTSRCTOS			17
#define ARGUSSORTDSTTOS			18
#define ARGUSSORTSRCTTL			19
#define ARGUSSORTDSTTTL			20
#define ARGUSSORTBYTECOUNT		21
#define ARGUSSORTSRCBYTECOUNT		22
#define ARGUSSORTDSTBYTECOUNT		23
#define ARGUSSORTPKTSCOUNT		24
#define ARGUSSORTSRCPKTSCOUNT		25
#define ARGUSSORTDSTPKTSCOUNT		26
#define ARGUSSORTAPPBYTECOUNT		27
#define ARGUSSORTSRCAPPBYTECOUNT	28
#define ARGUSSORTDSTAPPBYTECOUNT	29
#define ARGUSSORTLOAD			30
#define ARGUSSORTSRCLOAD		31
#define ARGUSSORTDSTLOAD		32
#define ARGUSSORTLOSS			33
#define ARGUSSORTPERCETLOSS		34
#define ARGUSSORTRATE			35
#define ARGUSSORTSRCRATE		36
#define ARGUSSORTDSTRATE		37
#define ARGUSSORTTRANREF		38
#define ARGUSSORTSEQ			39
#define ARGUSSORTSRCMPLS		40
#define ARGUSSORTDSTMPLS		41
#define ARGUSSORTSRCVLAN		42
#define ARGUSSORTDSTVLAN		43
#define ARGUSSORTSRCID			44
#define ARGUSSORTSRCTCPBASE		45
#define ARGUSSORTDSTTCPBASE		46
#define ARGUSSORTTCPRTT			47
#define ARGUSSORTSRCLOSS		48
#define ARGUSSORTDSTLOSS		49
#define ARGUSSORTPERCENTSRCLOSS		50
#define ARGUSSORTPERCENTDSTLOSS		51
#define ARGUSSORTSRCMAXPKTSIZE		52
#define ARGUSSORTSRCMINPKTSIZE		53
#define ARGUSSORTDSTMAXPKTSIZE		54
#define ARGUSSORTDSTMINPKTSIZE		55
#define ARGUSSORTSRCDSBYTE    		56
#define ARGUSSORTDSTDSBYTE    		57
#define ARGUSSORTSRCCOCODE 		58
#define ARGUSSORTDSTCOCODE    		59
 

#if defined(ArgusSort)

struct ArgusSorterStruct *ArgusSorter = NULL;
int ArgusReverseSortDir = 0;

struct ArgusSorterStruct *ArgusNewSorter (void);
void ArgusProcessSortOptions(void);
void ArgusSortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *); 
int ArgusSortRoutine (const void *, const void *);

int ArgusSortSrcId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortStartTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortLastTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortTransactions (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortAvgDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortMinDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortMaxDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcMac (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstMac (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortProtocol (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcMpls (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstMpls (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcVlan (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstVlan (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcIpId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstIpId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcPort (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstPort (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortPercentLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortTranRef (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSeq (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcTcpBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstTcpBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortTcpRtt (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortPercentSrcLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortPercentDstLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcMaxPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcMinPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstMaxPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstMinPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcCountryCode (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstCountryCode (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int (*ArgusSortAlgorithmTable[MAX_SORT_ALG_TYPES])(struct ArgusRecordStruct *, struct ArgusRecordStruct *) = {
   ArgusSortStartTime,
   ArgusSortStartTime,
   ArgusSortLastTime,
   ArgusSortTransactions,
   ArgusSortDuration,
   ArgusSortAvgDuration,
   ArgusSortMinDuration,
   ArgusSortMaxDuration,
   ArgusSortSrcMac,
   ArgusSortDstMac,
   ArgusSortSrcAddr,
   ArgusSortDstAddr,
   ArgusSortProtocol,
   ArgusSortSrcIpId,
   ArgusSortDstIpId,
   ArgusSortSrcPort,
   ArgusSortDstPort,
   ArgusSortSrcTos,
   ArgusSortDstTos,
   ArgusSortSrcTtl,
   ArgusSortDstTtl,
   ArgusSortByteCount,
   ArgusSortSrcByteCount,
   ArgusSortDstByteCount,
   ArgusSortPktsCount,
   ArgusSortSrcPktsCount,
   ArgusSortDstPktsCount,
   ArgusSortAppByteCount,
   ArgusSortSrcAppByteCount,
   ArgusSortDstAppByteCount,
   ArgusSortLoad,
   ArgusSortSrcLoad,
   ArgusSortDstLoad,
   ArgusSortLoss,
   ArgusSortPercentLoss,
   ArgusSortRate,
   ArgusSortSrcRate,
   ArgusSortDstRate,
   ArgusSortTranRef,
   ArgusSortSeq,
   ArgusSortSrcMpls,
   ArgusSortDstMpls,
   ArgusSortSrcVlan,
   ArgusSortDstVlan,
   ArgusSortSrcId,
   ArgusSortSrcTcpBase,
   ArgusSortDstTcpBase,
   ArgusSortTcpRtt,
   ArgusSortSrcLoss,
   ArgusSortDstLoss,
   ArgusSortPercentSrcLoss,
   ArgusSortPercentDstLoss,
   ArgusSortSrcMaxPktSize,
   ArgusSortSrcMinPktSize,
   ArgusSortDstMaxPktSize,
   ArgusSortDstMinPktSize,
   ArgusSortSrcDSByte,
   ArgusSortDstDSByte,
   ArgusSortSrcCountryCode,
   ArgusSortDstCountryCode,
};

char *ArgusSortKeyWords[MAX_SORT_ALG_TYPES] = {
   "stime",
   "stime",
   "ltime",
   "trans",
   "dur",
   "avgdur",
   "mindur",
   "maxdur",
   "smac",
   "dmac",
   "saddr",
   "daddr",
   "proto",
   "sipid",
   "dipid",
   "sport",
   "dport",
   "stos",
   "dtos",
   "sttl",
   "dttl",
   "bytes",
   "sbytes",
   "dbytes",
   "pkts",
   "spkts",
   "dpkts",
   "appbytes",
   "sappbytes",
   "dappbytes",
   "load",
   "sload",
   "dload",
   "loss",
   "ploss",
   "rate",
   "srate",
   "drate",
   "tranref",
   "seq",
   "smpls",
   "dmpls",
   "svlan",
   "dvlan",
   "srcid",
   "stcpb",
   "dtcpb",
   "tcprtt",
   "sloss",
   "dloss",
   "sploss",
   "dploss",
   "smaxsz",
   "sminsz",
   "dmaxsz",
   "dminsz",
   "sdsb",
   "ddsb",
   "sco",
   "dco",
};

#else


extern struct ArgusSorterStruct *ArgusSorter;
extern int ArgusReverseSortDir;

extern struct ArgusSorterStruct *ArgusNewSorter (void);
extern void ArgusProcessSortOptions(void);
extern void ArgusSortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *); 
extern int ArgusSortRoutine (const void *, const void *);
 
extern int ArgusSortSrcId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortStartTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortLastTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortTransactions (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortAvgDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortMinDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortMaxDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortProtocol (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortIpId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcPort (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstPort (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortPercentLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortTranRef (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSeq (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcTcpBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstTcpBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortTcpRtt (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

extern int (*ArgusSortAlgorithmTable[MAX_SORT_ALG_TYPES])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern char *ArgusSortKeyWords[MAX_SORT_ALG_TYPES];
#endif


#endif

