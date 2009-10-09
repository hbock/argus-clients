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
 * $Id: //depot/argus/argus-3.0/clients/include/argus_sort.h#14 $
 * $DateTime: 2005/12/27 13:50:56 $
 * $Change: 504 $
 */

#ifndef ArgusMetric_h
#define ArgusMetric_h

#define ARGUS_MAX_METRIC_ALG		97
#define MAX_METRIC_ALG_TYPES		97

#define ARGUSMETRICSRCID		0
#define ARGUSMETRICSTARTTIME		1
#define ARGUSMETRICLASTTIME		2
#define ARGUSMETRICTRANSACTIONS		3
#define ARGUSMETRICCOUNT		4
#define ARGUSMETRICDURATION		5
#define ARGUSMETRICMEAN			6
#define ARGUSMETRICMIN			7
#define ARGUSMETRICMAX			8
#define ARGUSMETRICSRCMAC		9
#define ARGUSMETRICDSTMAC		10
#define ARGUSMETRICSRCADDR		11
#define ARGUSMETRICDSTADDR		12
#define ARGUSMETRICPROTOCOL		13
#define ARGUSMETRICIPID			14
#define ARGUSMETRICSRCPORT		15
#define ARGUSMETRICDSTPORT		16
#define ARGUSMETRICSRCTOS		17
#define ARGUSMETRICDSTTOS		18
#define ARGUSMETRICSRCTTL		19
#define ARGUSMETRICDSTTTL		20
#define ARGUSMETRICBYTECOUNT		21
#define ARGUSMETRICSRCBYTECOUNT		22
#define ARGUSMETRICDSTBYTECOUNT		23
#define ARGUSMETRICPKTSCOUNT		24
#define ARGUSMETRICSRCPKTSCOUNT		24
#define ARGUSMETRICDSTPKTSCOUNT		26
#define ARGUSMETRICAPPBYTECOUNT		27
#define ARGUSMETRICSRCAPPBYTECOUNT	28
#define ARGUSMETRICDSTAPPBYTECOUNT	29
#define ARGUSMETRICLOAD			30
#define ARGUSMETRICSRCLOAD		31
#define ARGUSMETRICDSTLOAD		32
#define ARGUSMETRICLOSS			33
#define ARGUSMETRICPERCENTLOSS		34
#define ARGUSMETRICRATE			35
#define ARGUSMETRICSRCRATE		36
#define ARGUSMETRICDSTRATE		37
#define ARGUSMETRICTRANREF		38
#define ARGUSMETRICSEQ			39
#define ARGUSMETRICSRCMPLS		40
#define ARGUSMETRICDSTMPLS		41
#define ARGUSMETRICSRCVLAN		42
#define ARGUSMETRICDSTVLAN		43
#define ARGUSMETRICSRCTCPBASE		44
#define ARGUSMETRICDSTTCPBASE		45
#define ARGUSMETRICTCPRTT		46
#define ARGUSMETRICTCPSYNACK		47
#define ARGUSMETRICTCPACKDAT		48
#define ARGUSMETRICSRCLOSS		49
#define ARGUSMETRICDSTLOSS		50
#define ARGUSMETRICPERCENTSRCLOSS	51
#define ARGUSMETRICPERCENTDSTLOSS	52
#define ARGUSMETRICSRCINTPKT		53
#define ARGUSMETRICDSTINTPKT		54
#define ARGUSMETRICSRCDURATION		55
#define ARGUSMETRICDSTDURATION		56
#define ARGUSMETRICSRCTCPMAX		57
#define ARGUSMETRICDSTTCPMAX		58
#define ARGUSMETRICSRCINTPKTACT		59
#define ARGUSMETRICSRCINTPKTIDL		60
#define ARGUSMETRICDSTINTPKTACT		61
#define ARGUSMETRICDSTINTPKTIDL		62
#define ARGUSMETRICSRCWINDOW		63
#define ARGUSMETRICDSTWINDOW		64
#define ARGUSMETRICDELTADUR		65
#define ARGUSMETRICDELTASTARTTIME	66
#define ARGUSMETRICDELTALASTTIME	67
#define ARGUSMETRICDELTASRCPKTS		68
#define ARGUSMETRICDELTADSTPKTS		69
#define ARGUSMETRICSRCHOPCOUNT		70
#define ARGUSMETRICDSTHOPCOUNT   	71
#define ARGUSMETRICRETRANS		72
#define ARGUSMETRICSRCRETRANS		73
#define ARGUSMETRICDSTRETRANS		74
#define ARGUSMETRICPERCENTRETRANS	75
#define ARGUSMETRICPERCENTSRCRETRANS	76
#define ARGUSMETRICPERCENTDSTRETRANS	77
#define ARGUSMETRICNACKS		78
#define ARGUSMETRICSRCNACKS		79
#define ARGUSMETRICDSTNACKS		80
#define ARGUSMETRICPERCENTNACKS		81
#define ARGUSMETRICPERCENTSRCNACKS	82
#define ARGUSMETRICPERCENTDSTNACKS	83
#define ARGUSMETRICSOLO			84
#define ARGUSMETRICSRCSOLO		85
#define ARGUSMETRICDSTSOLO		86
#define ARGUSMETRICPERCENTSOLO		87
#define ARGUSMETRICPERCENTSRCSOLO	88
#define ARGUSMETRICPERCENTDSTSOLO	89
#define ARGUSMETRICFIRST		90
#define ARGUSMETRICSRCFIRST		91
#define ARGUSMETRICDSTFIRST		92
#define ARGUSMETRICPERCENTFIRST		93
#define ARGUSMETRICPERCENTSRCFIRST	94
#define ARGUSMETRICPERCENTDSTFIRST	95


#if defined(ArgusMetric)

long long ArgusFetchStartuSecTime (struct ArgusRecordStruct *ns);
long long ArgusFetchLastuSecTime (struct ArgusRecordStruct *ns);

double ArgusFetchSrcId (struct ArgusRecordStruct *ns);
double ArgusFetchStartTime (struct ArgusRecordStruct *ns);
double ArgusFetchLastTime (struct ArgusRecordStruct *ns);
double ArgusFetchMean (struct ArgusRecordStruct *ns);
double ArgusFetchMin (struct ArgusRecordStruct *ns);
double ArgusFetchMax (struct ArgusRecordStruct *ns);
double ArgusFetchSrcDuration (struct ArgusRecordStruct *ns);
double ArgusFetchDstDuration (struct ArgusRecordStruct *ns);
double ArgusFetchDuration (struct ArgusRecordStruct *ns);
double ArgusFetchuSecDuration (struct ArgusRecordStruct *ns);
double ArgusFetchSrcMac (struct ArgusRecordStruct *ns);
double ArgusFetchDstMac (struct ArgusRecordStruct *ns);
double ArgusFetchSrcAddr (struct ArgusRecordStruct *ns);
double ArgusFetchDstAddr (struct ArgusRecordStruct *ns);
double ArgusFetchProtocol (struct ArgusRecordStruct *ns);
double ArgusFetchIpId (struct ArgusRecordStruct *ns);
double ArgusFetchSrcPort (struct ArgusRecordStruct *ns);
double ArgusFetchDstPort (struct ArgusRecordStruct *ns);
double ArgusFetchSrcMpls (struct ArgusRecordStruct *ns);
double ArgusFetchDstMpls (struct ArgusRecordStruct *ns);
double ArgusFetchSrcVlan (struct ArgusRecordStruct *ns);
double ArgusFetchDstVlan (struct ArgusRecordStruct *ns);
double ArgusFetchSrcIpId (struct ArgusRecordStruct *ns);
double ArgusFetchDstIpId (struct ArgusRecordStruct *ns);
double ArgusFetchSrcTos (struct ArgusRecordStruct *ns);
double ArgusFetchDstTos (struct ArgusRecordStruct *ns);
double ArgusFetchSrcTtl (struct ArgusRecordStruct *ns);
double ArgusFetchDstTtl (struct ArgusRecordStruct *ns);
double ArgusFetchTransactions (struct ArgusRecordStruct *ns);
double ArgusFetchSrcLoad (struct ArgusRecordStruct *ns);
double ArgusFetchDstLoad (struct ArgusRecordStruct *ns);
double ArgusFetchLoad (struct ArgusRecordStruct *ns);
double ArgusFetchLoss (struct ArgusRecordStruct *ns);
double ArgusFetchSrcLoss (struct ArgusRecordStruct *ns);
double ArgusFetchDstLoss (struct ArgusRecordStruct *ns);
double ArgusFetchPercentLoss (struct ArgusRecordStruct *ns);
double ArgusFetchPercentSrcLoss (struct ArgusRecordStruct *ns);
double ArgusFetchPercentDstLoss (struct ArgusRecordStruct *ns);
double ArgusFetchPercentRetrans (struct ArgusRecordStruct *ns);
double ArgusFetchPercentSrcRetrans (struct ArgusRecordStruct *ns);
double ArgusFetchPercentDstRetrans (struct ArgusRecordStruct *ns);
double ArgusFetchSrcRate (struct ArgusRecordStruct *ns);
double ArgusFetchDstRate (struct ArgusRecordStruct *ns);
double ArgusFetchRate (struct ArgusRecordStruct *ns);
double ArgusFetchTranRef (struct ArgusRecordStruct *ns);
double ArgusFetchSeq (struct ArgusRecordStruct *ns);
double ArgusFetchByteCount (struct ArgusRecordStruct *ns);
double ArgusFetchSrcByteCount (struct ArgusRecordStruct *ns);
double ArgusFetchDstByteCount (struct ArgusRecordStruct *ns);
double ArgusFetchPktsCount (struct ArgusRecordStruct *ns);
double ArgusFetchSrcPktsCount (struct ArgusRecordStruct *ns);
double ArgusFetchDstPktsCount (struct ArgusRecordStruct *ns);
double ArgusFetchAppByteCount (struct ArgusRecordStruct *ns);
double ArgusFetchSrcAppByteCount (struct ArgusRecordStruct *ns);
double ArgusFetchDstAppByteCount (struct ArgusRecordStruct *ns);
double ArgusFetchSrcTcpBase (struct ArgusRecordStruct *ns);
double ArgusFetchDstTcpBase (struct ArgusRecordStruct *ns);
double ArgusFetchTcpRtt (struct ArgusRecordStruct *ns);
double ArgusFetchTcpSynAck (struct ArgusRecordStruct *ns);
double ArgusFetchTcpAckDat (struct ArgusRecordStruct *ns);
double ArgusFetchSrcTcpMax (struct ArgusRecordStruct *ns);
double ArgusFetchDstTcpMax (struct ArgusRecordStruct *ns);
double ArgusFetchSrcIntPkt (struct ArgusRecordStruct *ns);
double ArgusFetchSrcIntPktAct (struct ArgusRecordStruct *ns);
double ArgusFetchSrcIntPktIdl (struct ArgusRecordStruct *ns);
double ArgusFetchDstIntPkt (struct ArgusRecordStruct *ns);
double ArgusFetchDstIntPktAct (struct ArgusRecordStruct *ns);
double ArgusFetchDstIntPktIdl (struct ArgusRecordStruct *ns);
double ArgusFetchSrcWindow (struct ArgusRecordStruct *ns);
double ArgusFetchDstWindow (struct ArgusRecordStruct *ns);
double ArgusFetchDeltaDuration (struct ArgusRecordStruct *ns);
double ArgusFetchDeltaStartTime (struct ArgusRecordStruct *ns);
double ArgusFetchDeltaLastTime (struct ArgusRecordStruct *ns);
double ArgusFetchDeltaSrcPkts (struct ArgusRecordStruct *ns);
double ArgusFetchDeltaDstPkts (struct ArgusRecordStruct *ns);
double ArgusFetchSrcHopCount (struct ArgusRecordStruct *ns);
double ArgusFetchDstHopCount (struct ArgusRecordStruct *ns);
double ArgusFetchRetrans (struct ArgusRecordStruct *ns);
double ArgusFetchSrcRetrans (struct ArgusRecordStruct *ns);
double ArgusFetchDstRetrans (struct ArgusRecordStruct *ns);
double ArgusFetchNacks (struct ArgusRecordStruct *ns);
double ArgusFetchSrcNacks (struct ArgusRecordStruct *ns);
double ArgusFetchDstNacks (struct ArgusRecordStruct *ns);
double ArgusFetchPercentNacks (struct ArgusRecordStruct *ns);
double ArgusFetchPercentSrcNacks (struct ArgusRecordStruct *ns);
double ArgusFetchPercentDstNacks (struct ArgusRecordStruct *ns);
double ArgusFetchSolo (struct ArgusRecordStruct *ns);
double ArgusFetchSrcSolo (struct ArgusRecordStruct *ns);
double ArgusFetchDstSolo (struct ArgusRecordStruct *ns);
double ArgusFetchPercentSolo (struct ArgusRecordStruct *ns);
double ArgusFetchPercentSrcSolo (struct ArgusRecordStruct *ns);
double ArgusFetchPercentDstSolo (struct ArgusRecordStruct *ns);
double ArgusFetchFirst (struct ArgusRecordStruct *ns);
double ArgusFetchSrcFirst (struct ArgusRecordStruct *ns);
double ArgusFetchDstFirst (struct ArgusRecordStruct *ns);
double ArgusFetchPercentFirst (struct ArgusRecordStruct *ns);
double ArgusFetchPercentSrcFirst (struct ArgusRecordStruct *ns);
double ArgusFetchPercentDstFirst (struct ArgusRecordStruct *ns);

double (*ArgusFetchAlgorithmTable[MAX_METRIC_ALG_TYPES])(struct ArgusRecordStruct *) = {
   ArgusFetchSrcId,
   ArgusFetchStartTime,
   ArgusFetchLastTime,
   ArgusFetchTransactions,
   ArgusFetchTransactions,
   ArgusFetchDuration,
   ArgusFetchMean,
   ArgusFetchMin,
   ArgusFetchMax,
   ArgusFetchSrcMac,
   ArgusFetchDstMac,
   ArgusFetchSrcAddr,
   ArgusFetchDstAddr,
   ArgusFetchProtocol,
   ArgusFetchIpId,
   ArgusFetchSrcPort,
   ArgusFetchDstPort,
   ArgusFetchSrcTos,
   ArgusFetchDstTos,
   ArgusFetchSrcTtl,
   ArgusFetchDstTtl,
   ArgusFetchByteCount,
   ArgusFetchSrcByteCount,
   ArgusFetchDstByteCount,
   ArgusFetchPktsCount,
   ArgusFetchSrcPktsCount,
   ArgusFetchDstPktsCount,
   ArgusFetchAppByteCount,
   ArgusFetchSrcAppByteCount,
   ArgusFetchDstAppByteCount,
   ArgusFetchLoad,
   ArgusFetchSrcLoad,
   ArgusFetchDstLoad,
   ArgusFetchLoss,
   ArgusFetchPercentLoss,
   ArgusFetchRate,
   ArgusFetchSrcRate,
   ArgusFetchDstRate,
   ArgusFetchTranRef,
   ArgusFetchSeq,
   ArgusFetchSrcMpls,
   ArgusFetchDstMpls,
   ArgusFetchSrcVlan,
   ArgusFetchDstVlan,
   ArgusFetchSrcTcpBase,
   ArgusFetchDstTcpBase,
   ArgusFetchTcpRtt,
   ArgusFetchTcpSynAck,
   ArgusFetchTcpAckDat,
   ArgusFetchSrcLoss,
   ArgusFetchDstLoss,
   ArgusFetchPercentSrcLoss,
   ArgusFetchPercentDstLoss,
   ArgusFetchSrcIntPkt,
   ArgusFetchDstIntPkt,
   ArgusFetchSrcDuration,
   ArgusFetchDstDuration,
   ArgusFetchSrcTcpMax,
   ArgusFetchDstTcpMax,
   ArgusFetchSrcIntPktAct,
   ArgusFetchSrcIntPktIdl,
   ArgusFetchDstIntPktAct,
   ArgusFetchDstIntPktIdl,
   ArgusFetchSrcWindow,
   ArgusFetchDstWindow,
   ArgusFetchDeltaDuration,
   ArgusFetchDeltaStartTime,
   ArgusFetchDeltaLastTime,
   ArgusFetchDeltaSrcPkts,
   ArgusFetchDeltaDstPkts,
   ArgusFetchSrcHopCount,
   ArgusFetchDstHopCount,
   ArgusFetchRetrans,
   ArgusFetchSrcRetrans,
   ArgusFetchDstRetrans,
   ArgusFetchPercentRetrans,
   ArgusFetchPercentSrcRetrans,
   ArgusFetchPercentDstRetrans,
   ArgusFetchNacks,
   ArgusFetchSrcNacks,
   ArgusFetchDstNacks,
   ArgusFetchPercentNacks,
   ArgusFetchPercentSrcNacks,
   ArgusFetchPercentDstNacks,
   ArgusFetchSolo,
   ArgusFetchSrcSolo,
   ArgusFetchDstSolo,
   ArgusFetchPercentSolo,
   ArgusFetchPercentSrcSolo,
   ArgusFetchPercentDstSolo,
   ArgusFetchFirst,
   ArgusFetchSrcFirst,
   ArgusFetchDstFirst,
   ArgusFetchPercentFirst,
   ArgusFetchPercentSrcFirst,
   ArgusFetchPercentDstFirst,
};

char *ArgusMetricKeyWords[MAX_METRIC_ALG_TYPES] = {
   "srcid",
   "stime",
   "ltime",
   "trans",
   "count",
   "dur",

   "mean",
   "min",
   "max",
   "smac",
   "dmac",

   "saddr",
   "daddr",
   "proto",
   "ipid",
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
   "stcpb",
   "dtcpb",

   "tcprtt",
   "synack",
   "ackdat",
   "sloss",
   "dloss",

   "psloss",
   "pdloss",
   "sintpkt",
   "dintpkt",
   "sdur",

   "ddur",
   "stcpmax",
   "dtcpmax",
   "sintpktact",
   "sintpktidl",

   "dintpktact",
   "dintpktidl",
   "swin",
   "dwin",
   "deldur",

   "dlstime",
   "dlltime",
   "dlspkt",
   "dldpkt",
   "shops",

   "dhops",
   "retrans",
   "sretrans",
   "dretrans",
   "pretrans",

   "psretrans",
   "pdretrans",
   "nacks",
   "snacks",
   "dnacks",

   "pnacks",
   "psnacks",
   "pdnacks",
   "solo",
   "ssolo",

   "dsolo",
   "psolo",
   "pssolo",
   "pdsolo",
   "first",

   "sfirst",
   "dfirst",
   "pfirst",
   "psfirst",
   "pdfirst",
};

#else

extern double (*ArgusFetchAlgorithmTable[])(struct ArgusRecordStruct *);

extern double ArgusFetchSrcId (struct ArgusRecordStruct *ns);
extern long long ArgusFetchStartuSecTime (struct ArgusRecordStruct *ns);
extern double ArgusFetchStartTime (struct ArgusRecordStruct *ns);
extern long long ArgusFetchLastuSecTime (struct ArgusRecordStruct *ns);
extern double ArgusFetchLastTime (struct ArgusRecordStruct *ns);
extern double ArgusFetchMean (struct ArgusRecordStruct *ns);
extern double ArgusFetchMin (struct ArgusRecordStruct *ns);
extern double ArgusFetchMax (struct ArgusRecordStruct *ns);
extern double ArgusFetchDuration (struct ArgusRecordStruct *ns);
extern double ArgusFetchuSecDuration (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcMac (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstMac (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcAddr (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstAddr (struct ArgusRecordStruct *ns);
extern double ArgusFetchProtocol (struct ArgusRecordStruct *ns);
extern double ArgusFetchIpId (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcPort (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstPort (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcMpls (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstMpls (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcVlan (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstVlan (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcIpId (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstIpId (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcTos (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstTos (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcTtl (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstTtl (struct ArgusRecordStruct *ns);
extern double ArgusFetchTransactions (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcLoad (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstLoad (struct ArgusRecordStruct *ns);
extern double ArgusFetchLoad (struct ArgusRecordStruct *ns);
extern double ArgusFetchLoss (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcLoss (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstLoss (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentLoss (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentSrcLoss (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentDstLoss (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcRate (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstRate (struct ArgusRecordStruct *ns);
extern double ArgusFetchRate (struct ArgusRecordStruct *ns);
extern double ArgusFetchTranRef (struct ArgusRecordStruct *ns);
extern double ArgusFetchSeq (struct ArgusRecordStruct *ns);
extern double ArgusFetchByteCount (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcByteCount (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstByteCount (struct ArgusRecordStruct *ns);
extern double ArgusFetchPktsCount (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcPktsCount (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstPktsCount (struct ArgusRecordStruct *ns);
extern double ArgusFetchAppByteCount (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcAppByteCount (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstAppByteCount (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcTcpBase (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstTcpBase (struct ArgusRecordStruct *ns);
extern double ArgusFetchTcpRtt (struct ArgusRecordStruct *ns);
extern double ArgusFetchTcpMax (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcWindow (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstWindow (struct ArgusRecordStruct *ns);
extern double ArgusFetchDeltaDuration (struct ArgusRecordStruct *ns);
extern double ArgusFetchDeltaStartTime (struct ArgusRecordStruct *ns);
extern double ArgusFetchDeltaLastTime (struct ArgusRecordStruct *ns);
extern double ArgusFetchDeltaSrcPkts (struct ArgusRecordStruct *ns);
extern double ArgusFetchDeltaDstPkts (struct ArgusRecordStruct *ns);
extern double ArgusFetchRetrans (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcRetrans (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstRetrans (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentRetrans (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentSrcRetrans (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentDstRetrans (struct ArgusRecordStruct *ns);
extern double ArgusFetchNacks (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcNacks (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstNacks (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentNacks (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentSrcNacks (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentDstNacks (struct ArgusRecordStruct *ns);
extern double ArgusFetchSolo (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcSolo (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstSolo (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentSolo (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentSrcSolo (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentDstSolo (struct ArgusRecordStruct *ns);
extern double ArgusFetchFirst (struct ArgusRecordStruct *ns);
extern double ArgusFetchSrcFirst (struct ArgusRecordStruct *ns);
extern double ArgusFetchDstFirst (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentFirst (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentSrcFirst (struct ArgusRecordStruct *ns);
extern double ArgusFetchPercentDstFirst (struct ArgusRecordStruct *ns);
 
extern int (*ArgusMetricAlgorithmTable[MAX_METRIC_ALG_TYPES])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern char *ArgusMetricKeyWords[MAX_METRIC_ALG_TYPES];
#endif
#endif

