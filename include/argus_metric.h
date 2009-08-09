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

#define ARGUS_MAX_METRIC_ALG		96
#define MAX_METRIC_ALG_TYPES		96

#define ARGUSMETRICSRCID		0
#define ARGUSMETRICSTARTTIME		1
#define ARGUSMETRICLASTTIME		2
#define ARGUSMETRICTRANSACTIONS		3
#define ARGUSMETRICDURATION		4
#define ARGUSMETRICAVGDURATION		5
#define ARGUSMETRICMINDURATION		6
#define ARGUSMETRICMAXDURATION		7
#define ARGUSMETRICSRCMAC		8
#define ARGUSMETRICDSTMAC		9
#define ARGUSMETRICSRCADDR		10
#define ARGUSMETRICDSTADDR		11
#define ARGUSMETRICPROTOCOL		12
#define ARGUSMETRICIPID			13
#define ARGUSMETRICSRCPORT		14
#define ARGUSMETRICDSTPORT		15
#define ARGUSMETRICSRCTOS		16
#define ARGUSMETRICDSTTOS		17
#define ARGUSMETRICSRCTTL		18
#define ARGUSMETRICDSTTTL		19
#define ARGUSMETRICBYTECOUNT		20
#define ARGUSMETRICSRCBYTECOUNT		21
#define ARGUSMETRICDSTBYTECOUNT		22
#define ARGUSMETRICPKTSCOUNT		23
#define ARGUSMETRICSRCPKTSCOUNT		24
#define ARGUSMETRICDSTPKTSCOUNT		25
#define ARGUSMETRICAPPBYTECOUNT		26
#define ARGUSMETRICSRCAPPBYTECOUNT	27
#define ARGUSMETRICDSTAPPBYTECOUNT	28
#define ARGUSMETRICLOAD			29
#define ARGUSMETRICSRCLOAD		30
#define ARGUSMETRICDSTLOAD		31
#define ARGUSMETRICLOSS			32
#define ARGUSMETRICPERCENTLOSS		33
#define ARGUSMETRICRATE			34
#define ARGUSMETRICSRCRATE		35
#define ARGUSMETRICDSTRATE		36
#define ARGUSMETRICTRANREF		37
#define ARGUSMETRICSEQ			38
#define ARGUSMETRICSRCMPLS		39
#define ARGUSMETRICDSTMPLS		40
#define ARGUSMETRICSRCVLAN		41
#define ARGUSMETRICDSTVLAN		42
#define ARGUSMETRICSRCTCPBASE		43
#define ARGUSMETRICDSTTCPBASE		44
#define ARGUSMETRICTCPRTT		45
#define ARGUSMETRICTCPSYNACK		46
#define ARGUSMETRICTCPACKDAT		47
#define ARGUSMETRICSRCLOSS		48
#define ARGUSMETRICDSTLOSS		49
#define ARGUSMETRICPERCENTSRCLOSS	50
#define ARGUSMETRICPERCENTDSTLOSS	51
#define ARGUSMETRICSRCINTPKT		52
#define ARGUSMETRICDSTINTPKT		53
#define ARGUSMETRICSRCDURATION		54
#define ARGUSMETRICDSTDURATION		55
#define ARGUSMETRICSRCTCPMAX		56
#define ARGUSMETRICDSTTCPMAX		57
#define ARGUSMETRICSRCINTPKTACT		58
#define ARGUSMETRICSRCINTPKTIDL		59
#define ARGUSMETRICDSTINTPKTACT		60
#define ARGUSMETRICDSTINTPKTIDL		61
#define ARGUSMETRICSRCWINDOW		62
#define ARGUSMETRICDSTWINDOW		63
#define ARGUSMETRICDELTADUR		64
#define ARGUSMETRICDELTASTARTTIME	65
#define ARGUSMETRICDELTALASTTIME	66
#define ARGUSMETRICDELTASRCPKTS		67
#define ARGUSMETRICDELTADSTPKTS		68
#define ARGUSMETRICSRCHOPCOUNT		69
#define ARGUSMETRICDSTHOPCOUNT   	70
#define ARGUSMETRICRETRANS		71
#define ARGUSMETRICSRCRETRANS		72
#define ARGUSMETRICDSTRETRANS		73
#define ARGUSMETRICPERCENTRETRANS	74
#define ARGUSMETRICPERCENTSRCRETRANS	75
#define ARGUSMETRICPERCENTDSTRETRANS	76
#define ARGUSMETRICNACKS		77
#define ARGUSMETRICSRCNACKS		78
#define ARGUSMETRICDSTNACKS		79
#define ARGUSMETRICPERCENTNACKS		80
#define ARGUSMETRICPERCENTSRCNACKS	81
#define ARGUSMETRICPERCENTDSTNACKS	82
#define ARGUSMETRICSOLO			83
#define ARGUSMETRICSRCSOLO		84
#define ARGUSMETRICDSTSOLO		85
#define ARGUSMETRICPERCENTSOLO		86
#define ARGUSMETRICPERCENTSRCSOLO	87
#define ARGUSMETRICPERCENTDSTSOLO	88
#define ARGUSMETRICFIRST		89
#define ARGUSMETRICSRCFIRST		90
#define ARGUSMETRICDSTFIRST		91
#define ARGUSMETRICPERCENTFIRST		92
#define ARGUSMETRICPERCENTSRCFIRST	93
#define ARGUSMETRICPERCENTDSTFIRST	94


#if defined(ArgusMetric)

long long ArgusFetchStartuSecTime (struct ArgusRecordStruct *ns);
long long ArgusFetchLastuSecTime (struct ArgusRecordStruct *ns);

double ArgusFetchSrcId (struct ArgusRecordStruct *ns);
double ArgusFetchStartTime (struct ArgusRecordStruct *ns);
double ArgusFetchLastTime (struct ArgusRecordStruct *ns);
double ArgusFetchAvgDuration (struct ArgusRecordStruct *ns);
double ArgusFetchMinDuration (struct ArgusRecordStruct *ns);
double ArgusFetchMaxDuration (struct ArgusRecordStruct *ns);
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
   ArgusFetchDuration,
   ArgusFetchAvgDuration,
   ArgusFetchMinDuration,
   ArgusFetchMaxDuration,
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
   "dur",

   "avgdur",
   "mindur",
   "maxdur",
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
extern double ArgusFetchAvgDuration (struct ArgusRecordStruct *ns);
extern double ArgusFetchMinDuration (struct ArgusRecordStruct *ns);
extern double ArgusFetchMaxDuration (struct ArgusRecordStruct *ns);
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

