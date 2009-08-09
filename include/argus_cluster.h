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
 * $Id: //depot/argus/argus-3.0/clients/include/argus_cluster.h#27 $
 * $DateTime: 2006/03/31 13:25:33 $
 * $Change: 793 $
 */

#ifndef ArgusCluster_h
#define ArgusCluster_h

#include <regex.h>

struct RaFlowModelStruct {
   char *desc;  
   int pindex, mindex; 
   int preserve, report, autocorrect;
   int *histotimevalues;
   int histostart, histoend, histobins;
   int histotimeseries;
    
   struct RaPolicyStruct **policy; 
   struct RaPolicyStruct **model; 
};
 
struct RaPolicyStruct {
   u_int RaEntryType, RaPolicyId;
   u_int RaModelId, ArgusTimeout, ArgusIdleTimeout;
   struct ArgusFlow flow;
   char *str; 
};  

struct ArgusIPAddrStruct {
   union {
      u_int ipv4;
      u_int ipv6[4];
   } addr_un;
};

#define ARGUS_AGGREGATOR_DIRTY	1
#define ARGUS_CREATE_AUTOID	2
 
struct ArgusAggregatorStruct {
   struct ArgusAggregatorStruct *nxt;
   char *name, *pres, *report, *correct;
   int status, statusint, idleint;

   char *modeStr;

   long long ArgusTotalNewFlows;
   long long ArgusTotalClosedFlows;
   long long ArgusTotalSends;
   long long ArgusTotalBadSends;
   long long ArgusTotalUpdates;
   long long ArgusTotalCacheHits;

   struct ArgusRecordStruct *argus;

   long long mask, cont;
   short saddrlen, daddrlen;
   struct ArgusIPAddrStruct smask, dmask;

   struct RaPolicyStruct *drap, *rap;
   struct RaFlowModelStruct *fmodel;
   struct ArgusModeStruct *ArgusModeList, *ArgusMaskList;
   struct ArgusMaskStruct *ArgusMaskDefs;
   struct ArgusQueueStruct *queue;
   struct ArgusHashTable *htable;
   struct ArgusHashStruct hstruct;
   struct ArgusSystemFlow fstruct;

   char *filterstr;
   struct nff_program filter;

   char *labelstr;
   regex_t lpreg;

   char *estr;
   regex_t upreg;

   double (*RaMetricFetchAlgorithm)(struct ArgusRecordStruct *);

   char ArgusMatrixMode, ArgusRmonMode, ArgusAgMode;
};


#define NLI			-1

#define ARGUS_MAX_MASK_LIST	35

#define ARGUS_MASK_SRCID	0
 
#define ARGUS_MASK_SMPLS	1
#define ARGUS_MASK_DMPLS	2
#define ARGUS_MASK_SVLAN	3
#define ARGUS_MASK_DVLAN	4
 
#define ARGUS_MASK_PROTO	5
#define ARGUS_MASK_SADDR	6
#define ARGUS_MASK_SPORT	7
#define ARGUS_MASK_DADDR	8
#define ARGUS_MASK_DPORT	9
 
#define ARGUS_MASK_SNET		10
#define ARGUS_MASK_DNET		11
 
#define ARGUS_MASK_STOS		12
#define ARGUS_MASK_DTOS		13
#define ARGUS_MASK_STTL		14
#define ARGUS_MASK_DTTL		15
#define ARGUS_MASK_SIPID	16
#define ARGUS_MASK_DIPID	17
 
#define ARGUS_MASK_STCPB	18
#define ARGUS_MASK_DTCPB	19

#define ARGUS_MASK_SMAC		20
#define ARGUS_MASK_DMAC		21

#define ARGUS_MASK_SVID		22
#define ARGUS_MASK_DVID		23
#define ARGUS_MASK_SVPRI	24
#define ARGUS_MASK_DVPRI	25
#define ARGUS_MASK_SVC		26
 
#define ARGUS_MASK_ICMP		27

#define ARGUS_MASK_SDSB		28
#define ARGUS_MASK_DDSB		29
#define ARGUS_MASK_SCO 		30
#define ARGUS_MASK_DCO 		31
#define ARGUS_MASK_SAS 		32
#define ARGUS_MASK_DAS 		33
#define ARGUS_MASK_IAS 		34


#define ARGUS_MASK_SRCID_INDEX	(0x1 << ARGUS_MASK_SRCID)
 
#define ARGUS_MASK_SMPLS_INDEX	(0x1 << ARGUS_MASK_SMPLS)
#define ARGUS_MASK_DMPLS_INDEX	(0x1 << ARGUS_MASK_DMPLS)
#define ARGUS_MASK_SVLAN_INDEX	(0x1 << ARGUS_MASK_SVLAN)
#define ARGUS_MASK_DVLAN_INDEX	(0x1 << ARGUS_MASK_DVLAN)
 
#define ARGUS_MASK_PROTO_INDEX	(0x1 << ARGUS_MASK_PROTO)
#define ARGUS_MASK_SADDR_INDEX	(0x1 << ARGUS_MASK_SADDR)
#define ARGUS_MASK_SPORT_INDEX	(0x1 << ARGUS_MASK_SPORT)
#define ARGUS_MASK_DADDR_INDEX	(0x1 << ARGUS_MASK_DADDR)
#define ARGUS_MASK_DPORT_INDEX	(0x1 << ARGUS_MASK_DPORT)
 
#define ARGUS_MASK_SNET_INDEX	(0x1 << ARGUS_MASK_SNET)
#define ARGUS_MASK_DNET_INDEX	(0x1 << ARGUS_MASK_DNET)
 
#define ARGUS_MASK_STOS_INDEX	(0x1 << ARGUS_MASK_STOS)
#define ARGUS_MASK_DTOS_INDEX	(0x1 << ARGUS_MASK_DTOS)
#define ARGUS_MASK_STTL_INDEX	(0x1 << ARGUS_MASK_STTL)
#define ARGUS_MASK_DTTL_INDEX	(0x1 << ARGUS_MASK_DTTL)
#define ARGUS_MASK_SIPID_INDEX	(0x1 << ARGUS_MASK_SIPID)
#define ARGUS_MASK_DIPID_INDEX	(0x1 << ARGUS_MASK_DIPID)
 
#define ARGUS_MASK_STCPB_INDEX	(0x1 << ARGUS_MASK_STCPB)
#define ARGUS_MASK_DTCPB_INDEX	(0x1 << ARGUS_MASK_DTCPB)

#define ARGUS_MASK_SDSB_INDEX	(0x1 << ARGUS_MASK_SDSB)
#define ARGUS_MASK_DDSB_INDEX	(0x1 << ARGUS_MASK_DDSB)

#define ARGUS_MASK_SVC_INDEX	(0x1 << ARGUS_MASK_SVC)
#define ARGUS_MASK_ICMP_INDEX	(0x1 << ARGUS_MASK_ICMP)

#define ARGUS_MASK_SCO_INDEX	(0x1 << ARGUS_MASK_SCO)
#define ARGUS_MASK_DCO_INDEX	(0x1 << ARGUS_MASK_DCO)

#define ARGUS_MASK_SAS_INDEX	(0x1 << ARGUS_MASK_SAS)
#define ARGUS_MASK_DAS_INDEX	(0x1 << ARGUS_MASK_DAS)


struct ArgusMaskStruct {
   char *name, slen;
   int dsr, offset, len, index;
};

#if defined(ARGUS_MAIN)
struct ArgusMaskStruct ArgusIpV4MaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
};

struct ArgusMaskStruct ArgusIpV4RevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  2, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
};

struct ArgusMaskStruct ArgusIpV6MaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4, 16, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      40,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      20, 16, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      42,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
};
 
struct ArgusMaskStruct ArgusIpV6RevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4, 16, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      40,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      20, 16, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      42,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5, 372,  4, 1},
   {"dmpls", 5, 368,  4, 1},
   {"svlan", 5, 362,  2, 1},
   {"dvlan", 5, 360,  2, 1},
   {"proto", 5,  43,  1, 1},
   {"saddr", 5,  24, 16, 1},
   {"sport", 5,  46,  2, 1},
   {"daddr", 5,   8, 16, 1},
   {"dport", 5,  44,  2, 1},
   {"snet",  4,  24, 16, 1},
   {"dnet",  4,   8, 16, 1},
   {"stos",  4, 157,  1, 1},
   {"dtos",  4, 149,  1, 1},
   {"sttl",  4, 156,  1, 1},
   {"dttl",  4, 148,  1, 1},
   {"sipid", 4, 158,  2, 1},
   {"dipid", 4, 158,  2, 1},
   {"stcpb", 5, 300,  4, 1},
   {"dtcpb", 5, 252,  4, 1},
   {"smac",  4, 340,  6, 1},
   {"dmac",  4, 346,  6, 1},
   {"svid",  4, 316,  2, 1},
   {"dvid",  4, 316,  2, 1},
   {"svpri", 5, 316,  1, 1},
   {"dvpri", 5, 316,  1, 1},
   {"svc",   3, 396, 16, 1},
   {"inode", 5, 224, 16, 1},
   {"sdsb",  4, 157,  1, 1},
   {"ddsb",  4, 149,  1, 1},
   {"sco",   3, 590,  2, 1},
   {"dco",   3, 588,  2, 1},
*/
};


struct ArgusMaskStruct ArgusIBLocalMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5,   0,  0, 1},
   {"dmpls", 5,   0,  0, 1},
   {"svlan", 5,   0,  0, 1},
   {"dvlan", 5,   0,  0, 1},
   {"proto", 5,  16,  1, 1},
   {"saddr", 5,   8,  2, 1},
   {"sport", 5,  24,  4, 1},
   {"daddr", 5,  10,  2, 1},
   {"dport", 5,  20,  4, 1},
   {"snet",  4,   0,  0, 1},
   {"dnet",  4,   0,  0, 1},
   {"stos",  4,   0,  0, 1},
   {"dtos",  4,   0,  0, 1},
   {"sttl",  4,   0,  0, 1},
   {"dttl",  4,   0,  0, 1},
   {"sipid", 4,   0,  0, 1},
   {"dipid", 4,   0,  0, 1},
   {"stcpb", 5,   0,  0, 1},
   {"dtcpb", 5,   0,  0, 1},
   {"smac",  4, 346,  2, 1},
   {"dmac",  4, 342,  2, 1},
   {"svid",  4,   0,  0, 1},
   {"dvid",  4,   0,  0, 1},
   {"svpri", 5,   0,  0, 1},
   {"dvpri", 5,   0,  0, 1},
   {"svc",   3,   0,  0, 1},
   {"inode", 5,   0,  0, 1},
   {"sdsb",  4,   0,  0, 1},
   {"ddsb",  4,   0,  0, 1},
   {"sco",   3,   0,  0, 1},
   {"dco",   3,   0,  0, 1},
*/
};
 
struct ArgusMaskStruct ArgusIBLocalRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5,   0,  0, 1},
   {"dmpls", 5,   0,  0, 1},
   {"svlan", 5,   0,  0, 1},
   {"dvlan", 5,   0,  0, 1},
   {"proto", 5,  16,  1, 1},
   {"saddr", 5,  10,  2, 1},
   {"sport", 5,  20,  4, 1},
   {"daddr", 5,   8,  2, 1},
   {"dport", 5,  24,  4, 1},
   {"snet",  4,   0,  0, 1},
   {"dnet",  4,   0,  0, 1},
   {"stos",  4,   0,  0, 1},
   {"dtos",  4,   0,  0, 1},
   {"sttl",  4,   0,  0, 1},
   {"dttl",  4,   0,  0, 1},
   {"sipid", 4,   0,  0, 1},
   {"dipid", 4,   0,  0, 1},
   {"stcpb", 5,   0,  0, 1},
   {"dtcpb", 5,   0,  0, 1},
   {"smac",  4, 342,  2, 1},
   {"dmac",  4, 346,  2, 1},
   {"svid",  4,   0,  0, 1},
   {"dvid",  4,   0,  0, 1},
   {"svpri", 5,   0,  0, 1},
   {"dvpri", 5,   0,  0, 1},
   {"svc",   3,   0,  0, 1},
   {"inode", 5,   0,  0, 1},
   {"sdsb",  4,   0,  0, 1},
   {"ddsb",  4,   0,  0, 1},
   {"sco",   3,   0,  0, 1},
   {"dco",   3,   0,  0, 1},
*/
};

struct ArgusMaskStruct ArgusIBGlobalMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5,   0,  0, 1},
   {"dmpls", 5,   0,  0, 1},
   {"svlan", 5,   0,  0, 1},
   {"dvlan", 5,   0,  0, 1},
   {"proto", 5,  43,  1, 1},
   {"saddr", 5,  44,  2, 1},
   {"sport", 5,   0,  0, 1},
   {"daddr", 5,  46,  2, 1},
   {"dport", 5,  48,  4, 1},
   {"snet",  4,  44,  2, 1},
   {"dnet",  4,  46,  2, 1},
   {"stos",  4,   0,  0, 1},
   {"dtos",  4,   0,  0, 1},
   {"sttl",  4,   0,  0, 1},
   {"dttl",  4,   0,  0, 1},
   {"sipid", 4,   0,  2, 1},
   {"dipid", 4,   0,  2, 1},
   {"stcpb", 5,   0,  0, 1},
   {"dtcpb", 5,   0,  0, 1},
   {"smac",  4, 346,  6, 1},
   {"dmac",  4, 340,  6, 1},
   {"svid",  4, 316,  2, 1},
   {"dvid",  4, 316,  2, 1},
   {"svpri", 5, 316,  1, 1},
   {"dvpri", 5, 316,  1, 1},
   {"svc",   3,   0,  0, 1},
   {"inode", 5,   0,  0, 1},
   {"sdsb",  4,   0,  0, 1},
   {"ddsb",  4,   0,  0, 1},
   {"sco",   3,   0,  0, 1},
   {"dco",   3,   0,  0, 1},
*/
};
 
struct ArgusMaskStruct ArgusIBGlobalRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5, 372,  4, 1},
   {"dmpls", 5, 368,  4, 1},
   {"svlan", 5, 362,  2, 1},
   {"dvlan", 5, 360,  2, 1},
   {"proto", 5,  43,  1, 1},
   {"saddr", 5,  46,  2, 1},
   {"sport", 5,   0,  0, 1},
   {"daddr", 5,  44,  2, 1},
   {"dport", 5,  48,  4, 1},
   {"snet",  4,  46,  2, 1},
   {"dnet",  4,  44,  2, 1},
   {"stos",  4,   0,  0, 1},
   {"dtos",  4,   0,  0, 1},
   {"sttl",  4,   0,  0, 1},
   {"dttl",  4,   0,  0, 1},
   {"sipid", 4,   0,  0, 1},
   {"dipid", 4,   0,  0, 1},
   {"stcpb", 5,   0,  0, 1},
   {"dtcpb", 5,   0,  0, 1},
   {"smac",  4, 340,  6, 1},
   {"dmac",  4, 346,  6, 1},
   {"svid",  4, 316,  2, 1},
   {"dvid",  4, 316,  2, 1},
   {"svpri", 5, 316,  1, 1},
   {"dvpri", 5, 316,  1, 1},
   {"svc",   3,   0,  0, 1},
   {"inode", 5,   0,  0, 1},
   {"sdsb",  4,   0,  0, 1},
   {"ddsb",  4,   0,  0, 1},
   {"sco",   3,   0,  0, 1},
   {"dco",   3,   0,  0, 1},
*/
};


struct ArgusMaskStruct ArgusArpMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5, 368,  4, 1},
   {"dmpls", 5, 372,  4, 1},
   {"svlan", 5, 360,  2, 1},
   {"dvlan", 5, 362,  2, 1},
   {"proto", 5,  10,  2, 1},
   {"saddr", 5,  16,  4, 1},
   {"sport", 5,   0,  0, 1},
   {"daddr", 5,  20,  4, 1},
   {"dport", 5,   0,  0, 1},
   {"snet",  4,   0,  0, 1},
   {"dnet",  4,   0,  0, 1},
   {"stos",  4,   0,  0, 1},
   {"dtos",  4,   0,  0, 1},
   {"sttl",  4,   0,  0, 1},
   {"dttl",  4,   0,  0, 1},
   {"sipid", 4,   0,  0, 1},
   {"dipid", 4,   0,  0, 1},
   {"stcpb", 5,   0,  0, 1},
   {"dtcpb", 5,   0,  0, 1},
   {"smac",  4, 346,  6, 1},
   {"dmac",  4, 340,  6, 1},
   {"svid", 316,2},
   {"dvid", 316,2},
   {"svpri", 316,1},
   {"dvpri", 316,1},
   {"svc", 396,16},
   {"sdsb",  4, 149,  0, 1},
   {"ddsb",  4, 157,  0, 1},
   {"sco",   3,   0,  0, 1},
   {"dco",   3,   0,  0, 1},
*/
};

struct ArgusMaskStruct ArgusArpRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  2, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5, 372,  4, 1},
   {"dmpls", 5, 368,  4, 1},
   {"svlan", 5, 362,  2, 1},
   {"dvlan", 5, 360,  2, 1},
   {"proto", 5,  10,  2, 1},
   {"saddr", 5,  20,  4, 1},
   {"sport", 5,  22,  0, 1},
   {"daddr", 5,  16,  4, 1},
   {"dport", 5,  23,  0, 1},
   {"snet",  4,   0,  0, 1},
   {"dnet",  4,   0,  0, 1},
   {"stos",  4,   0,  0, 1},
   {"dtos",  4,   0,  0, 1},
   {"sttl",  4,   0,  0, 1},
   {"dttl",  4,   0,  0, 1},
   {"sipid", 4,   0,  0, 1},
   {"dipid", 4,   0,  0, 1},
   {"stcpb", 5,   0,  0, 1},
   {"dtcpb", 5,   0,  0, 1},
   {"smac",  4, 340,  6, 1},
   {"dmac",  4, 346,  6, 1},
*/
};


struct ArgusMaskStruct ArgusRarpMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5, 368,  4, 1},
   {"dmpls", 5, 372,  4, 1},
   {"svlan", 5, 360,  2, 1},
   {"dvlan", 5, 362,  2, 1},
   {"proto", 5, NLI,  2, 2054},
   {"saddr", 5,  20,  6, 1},
   {"sport", 5,   0,  0, 1},
   {"daddr", 5,  52,  6, 1},
   {"dport", 5,   0,  0, 1},
   {"snet",  4,   0,  0, 1},
   {"dnet",  4,   0,  0, 1},
   {"stos",  4,   0,  0, 1},
   {"dtos",  4,   0,  0, 1},
   {"sttl",  4,   0,  0, 1},
   {"dttl",  4,   0,  0, 1},
   {"sipid", 4,   0,  0, 1},
   {"dipid", 4,   0,  0, 1},
   {"stcpb", 5,   0,  0, 1},
   {"dtcpb", 5,   0,  0, 1},
   {"smac",  4, 346,  6, 1},
   {"dmac",  4, 340,  6, 1},
   {"svid", 316,2},
   {"dvid", 316,2},
   {"svpri", 316,1},
   {"dvpri", 316,1},
   {"svc", 396,16},
*/
};

struct ArgusMaskStruct ArgusRarpRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5, 372,  4, 1},
   {"dmpls", 5, 368,  4, 1},
   {"svlan", 5, 362,  2, 1},
   {"dvlan", 5, 360,  2, 1},
   {"proto", 5, NLI,  2, 2054},
   {"saddr", 5,  52,  6, 1},
   {"sport", 5,  22,  0, 1},
   {"daddr", 5,  20,  6, 1},
   {"dport", 5,  23,  0, 1},
   {"snet",  4,   0,  0, 1},
   {"dnet",  4,   0,  0, 1},
   {"stos",  4,   0,  0, 1},
   {"dtos",  4,   0,  0, 1},
   {"sttl",  4,   0,  0, 1},
   {"dttl",  4,   0,  0, 1},
   {"sipid", 4,   0,  0, 1},
   {"dipid", 4,   0,  0, 1},
   {"stcpb", 5,   0,  0, 1},
   {"dtcpb", 5,   0,  0, 1},
   {"smac",  4, 340,  6, 1},
   {"dmac",  4, 346,  6, 1},
*/
};

struct ArgusMaskStruct ArgusEtherMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5, 368,  4, 1},
   {"dmpls", 5, 372,  4, 1},
   {"svlan", 5, 360,  2, 1},
   {"dvlan", 5, 362,  2, 1},
   {"proto", 5,  20,  2, 1},
   {"saddr", 5,  14,  6, 1},
   {"sport", 5,  23,  0, 1},
   {"daddr", 5,   8,  6, 1},
   {"dport", 5,  22,  0, 1},
   {"snet",  4,   0,  0, 1},
   {"dnet",  4,   0,  0, 1},
   {"stos",  4,   0,  0, 1},
   {"dtos",  4,   0,  0, 1},
   {"sttl",  4,   0,  0, 1},
   {"dttl",  4,   0,  0, 1},
   {"sipid", 4,   0,  0, 1},
   {"dipid", 4,   0,  0, 1},
   {"stcpb", 5,   0,  0, 1},
   {"dtcpb", 5,   0,  0, 1},
   {"smac",  4, 346,  6, 1},
   {"dmac",  4, 340,  6, 1},
   {"svid", 316,2},
   {"dvid", 316,2},
   {"svpri", 316,1},
   {"dvpri", 316,1},
   {"svc", 396,16},
*/
};
 
struct ArgusMaskStruct ArgusEtherRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4,  4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
/*
   {"srcid", 5,  88,  4, 1},
   {"smpls", 5, 372,  4, 1},
   {"dmpls", 5, 368,  4, 1},
   {"svlan", 5, 362,  2, 1},
   {"dvlan", 5, 360,  2, 1},
   {"proto", 5,  20,  2, 1},
   {"saddr", 5,   8,  6, 1},
   {"sport", 5,  22,  0, 1},
   {"daddr", 5,  14,  6, 1},
   {"dport", 5,  23,  0, 1},
   {"snet",  4,   0,  0, 1},
   {"dnet",  4,   0,  0, 1},
   {"stos",  4,   0,  0, 1},
   {"dtos",  4,   0,  0, 1},
   {"sttl",  4,   0,  0, 1},
   {"dttl",  4,   0,  0, 1},
   {"sipid", 4,   0,  0, 1},
   {"dipid", 4,   0,  0, 1},
   {"stcpb", 5,   0,  0, 1},
   {"dtcpb", 5,   0,  0, 1},
   {"smac",  4, 340,  6, 1},
   {"dmac",  4, 346,  6, 1},
*/
};

struct ArgusAggregatorStruct *ArgusNewAggregator (struct ArgusParserStruct *, char *);
void ArgusDeleteAggregator (struct ArgusParserStruct *, struct ArgusAggregatorStruct *);
struct RaPolicyStruct *RaFlowModelOverRides(struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);
void ArgusGenerateNewFlow(struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);
 
unsigned int ArgusMergeAddress(unsigned int *, unsigned int *, int, int);
void ArgusMergeRecords (struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);
void ArgusIntersectRecords (struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);

#else
extern struct ArgusMaskStruct ArgusIpV4MaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusIpV6MaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusEtherMaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusArpMaskDefs[ARGUS_MAX_MASK_LIST];

extern struct ArgusMaskStruct ArgusIpV4RevMaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusIpV6RevMaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusEtherRevMaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusArpRevMaskDefs[ARGUS_MAX_MASK_LIST];

extern struct ArgusAggregatorStruct *ArgusNewAggregator (struct ArgusParserStruct *, char *);
extern void ArgusDeleteAggregator (struct ArgusParserStruct *, struct ArgusAggregatorStruct *);
extern struct RaPolicyStruct *RaFlowModelOverRides(struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);
extern void ArgusGenerateNewFlow(struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);
 
extern unsigned int ArgusMergeAddress(unsigned int *, unsigned int *, int, int);
extern void ArgusMergeRecords (struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern void ArgusIntersectRecords (struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);

#endif
#endif


