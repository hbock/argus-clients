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
 * $Id: //depot/argus/argus-3.0/clients/include/argus_client.h#41 $
 * $DateTime: 2006/03/31 14:25:35 $
 * $Change: 795 $
 */


#ifndef ArgusClient_h
#define ArgusClient_h

#include <unistd.h>

#include <sys/types.h>
#include <stdio.h>

#include <errno.h>
#include <fcntl.h>

#include <string.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <string.h>
#include <sys/stat.h>

#include <compat.h>

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif

#ifdef ARGUS_SASL
#include <sasl/sasl.h>
#endif

#include <argus_debug.h>
#include <argus_label.h>
#include <argus_def.h>
#include <argus_out.h>
#include <argus_int.h>
#include <argus_histo.h>


#define RA_TRANSDURATION        1
#define RA_AVGDURATION          2
#define RA_DELTADURATION        3

#define RA_MODELNAMETAGSTR	"RACLUSTER_MODEL_NAME="
#define RA_PRESERVETAGSTR	"RACLUSTER_PRESERVE_FIELDS="
#define RA_REPORTTAGSTR		"RACLUSTER_REPORT_AGGREGATION="
#define RA_AUTOCORRECTSTR	"RACLUSTER_AUTO_CORRECTION="
#define RA_HISTOGRAM		"RACLUSTER_HISTOGRAM="

#define RA_MODELIST		1
#define RA_FLOWLIST		2

#define RA_FLOWPOLICYFIELDNUM	11
#define RA_MODELPOLICYFIELDNUM	8
  
#define RA_LABELSTRING		0
#define RA_POLICYID		1
#define RA_POLICYTYPE		2
#define RA_POLICYSRCADDR	3
#define RA_POLICYDSTADDR	4
#define RA_POLICYPROTO		5
#define RA_POLICYSRCPORT	6
#define RA_POLICYDSTPORT	7
#define RA_POLICYMODELST	8
#define RA_POLICYTIMEOUT	9
#define RA_POLICYIDLETIMEOUT	10

#define RA_MODIFIED		0x10000000

#define RA_CON			1
#define RA_DONE			2

#define RA_HASHTABLESIZE	0x10000
#define RA_SVCPASSED		0x010000
#define RA_SVCFAILED		0x020000
#define RA_SVCINCOMPLETE        0x040000
#define RA_SVCTEST		(RA_SVCFAILED|RA_SVCPASSED|RA_SVCINCOMPLETE)
#define RA_SVCDISCOVERY		0x080000
#define RA_SVCMULTICAST		0x100000


#define ARGUS_FAR_SRCADDR_MODIFIED      0x0100
#define ARGUS_FAR_DSTADDR_MODIFIED      0x0200
#define ARGUS_FAR_PROTO_MODIFIED        0x0400
#define ARGUS_FAR_SRCPORT_MODIFIED      0x0800
#define ARGUS_FAR_DSTPORT_MODIFIED      0x1000
#define ARGUS_FAR_TPVAL_MODIFIED        0x2000

#define ARGUS_FAR_RECORDREVERSE		0x4000

#define ARGUS_MAX_STREAM		1048576

#define ARGUS_READINGPREHDR	1
#define ARGUS_READINGHDR	2
#define ARGUS_READINGBLOCK	4
#define ARGUS_READINGDATAGRAM	8


#define TSEQ_HASHSIZE		9029
#define HASHNAMESIZE		4096

#define RASIGLENGTH		32
   
#define RA_SRV_ROOT		0
#define RA_SRV_LEFT		1
#define RA_SRV_RIGHT		2
    
#define ARGUSMAXSIGFILE		2048
#define RA_SRC_SERVICES		0
#define RA_DST_SERVICES		1
 
#define RA_SVC_WILDCARD		4



typedef struct ArgusRecord * (*ArgusNetFlowHandler)(struct ArgusInput *, u_char **);

struct ArgusInput {
   struct ArgusQueueHeader qhdr;
   struct ArgusQueueStruct *queue;

#if defined(ARGUS_THREADS)
   pthread_t tid;
   pthread_mutex_t lock;
#endif

   int index, mode, fd, in, out, offset;
   int major_version, minor_version;
   unsigned int status;
#if defined(HAVE_GETADDRINFO)
   struct addrinfo *host;
#else
   struct hostent *host;
#endif
   struct in_addr addr;
   long long ostart, ostop;
   unsigned short portnum;
   char *hostname, *filename;
   FILE *file, *pipe;
   unsigned int ArgusLocalNet, ArgusNetMask;
   unsigned int ArgusID, ArgusIDType;
   struct timeval ArgusStartTime, ArgusLastTime;
   long long ArgusTimeDrift;
   int ArgusMarInterval;
   struct stat statbuf;
   int ArgusBufferLen;
   unsigned char *ArgusReadBuffer, *ArgusConvBuffer;
   unsigned char *ArgusReadPtr, *ArgusConvPtr, *ArgusReadBlockPtr;
   int ArgusReadSocketCnt, ArgusReadSocketSize;
   int ArgusReadSocketState, ArgusReadCiscoVersion;
   int ArgusReadSocketNum, ArgusReadSize;
   ArgusNetFlowHandler ArgusCiscoNetFlowParse;

#ifdef ARGUS_SASL
   sasl_conn_t *sasl_conn;
   int ArgusSaslBufCnt;
   unsigned char *ArgusSaslBuffer;
#endif

   struct ArgusRecord ArgusInitCon, ArgusManStart;
   struct ArgusRecord *ArgusOriginal;

   struct ArgusCanonRecord  ArgusGenerateRecordCanonBuf;
   struct ArgusRecordStruct ArgusGenerateRecordStructBuf;
   char ArgusGenerateRecordLabelBuf[MAXSTRLEN];

   char ArgusOriginalBuffer[MAXARGUSRECORD];

   char ArgusSrcUserData[0x10000];
   char ArgusDstUserData[0x10000];

   unsigned char ArgusSrcActDist[256];
   unsigned char ArgusSrcIdleDist[256];
   unsigned char ArgusDstActDist[256];
   unsigned char ArgusDstIdleDist[256];
};


#define RASIGLENGTH             32

#define RA_SRV_ROOT             0
#define RA_SRV_LEFT             1
#define RA_SRV_RIGHT            2

#define NTAMMAXSIGFILE          2048
#define RA_SRC_SERVICES         0
#define RA_DST_SERVICES         1

#define RA_SVC_WILDCARD         4


struct ArgusServiceRecord {
   u_int status;
   struct ArgusRecordStruct *argus;
   struct RaSrvSignature *sig;
};


struct RaSrvSignature {
   struct ArgusQueueHeader qhdr;
   char *name;
   unsigned char proto;
   unsigned short port;
   int count, status;
   unsigned int srcmask, dstmask;
   unsigned char src[RASIGLENGTH], dst[RASIGLENGTH];
};

struct RaSrvTreeNode {
   struct RaSrvTreeNode *l, *r;
   struct RaSrvSignature *srv;
};



#define ARGUSMONITOR_EQUAL      0x01000000
#define ARGUSMONITOR_NOTEQUAL   0x02000000


#ifndef NFC_AGGREGATIONDEFINITION_H
#define NFC_AGGREGATIONDEFINITION_H
/* 
 * AGGREGATION_DEFINITION describes the "Key" and "Value" fields seen in
 * the datafile. The definition comprise of keywords and delimiters. 
 * By reading the AGGREGATION_DEFINITION, one can interpret what and in what
 * order are the "Key" and "Value" fields being presented in the datafile.
 * Datafile consumers can also deduce what aggregation scheme is used 
 * by parsing AGGREGATION_DEFINITION..
 *
 * The order of keywords seen in the AGGREGATION_DEFINITION represents the true
 * order of the "Key" and "Value" fields presented in the datafile. Each 
 * keyword is delimited by either '|' or ','.
 *
 * As part of the new changes to the datafile header, the FORMAT field
 * will have a value of "B". Please note that the FORMAT may change 
 * if there is any change to any of the existing keywords, definition format,
 * adding new keyword, or any other header changes.
 * Also, the delimiter used in the datafile will be prepended at the 
 * beginning of each header. Since AGGREGATION_DEFINITION becomes the 2nd 
 * line of the header, the 1st line of the header will append a 
 * new field, namely "Header", which describes the total number of 
 * lines in the header.
 * 
 * The AGGREGATION_DEFINITION keywords have the following assignemnts ...
 *
 *      keyword           Description
 *      -------           -----------------------
 *      srcaddr           Source IP Address
 *      dstaddr           Destination IP Address
 *      src_subnet        Source SubNet
 *      dst_subnet        Destination SubNet
 *      src_mask          Source SubNet Mask 
 *      dst_mask          Destination SubNet Mask 
 *      src_user_subnet   Source User SubNet
 *      dst_user_subnet   Destination User SubNet
 *      src_as            Source AS
 *      dst_as            Destination AS
 *      srcport           Source Port
 *      dstport           Destination Port
 *      prot              Prot field
 *      protocol          Protocol (srcport, dstport, and prot lookup)
 *      input             Input Interface 
 *      output            Output Interface
 *      tos               Type of Service
 *      nexthop           Next Hop IP Address
 *
 *      pkts              Packets
 *      octets            Octets
 *      flows             Flow Count
 *      starttime         First Flow Stamp (UTC sec)
 *      endtime           Last Flow Stamp (UTC sec)
 *      activetime        Total Active Time (msec)
 */

/* Key Fields */
#define SRC_ADDR                      "srcaddr"
#define DST_ADDR                      "dstaddr"
#define SRC_SUBNET                    "src_subnet"
#define DST_SUBNET                    "dst_subnet"
#define SRC_SUBNET_MASK               "src_mask"
#define DST_SUBNET_MASK               "dst_mask"
#define SRC_USER_SUBNET               "src_user_subnet"
#define DST_USER_SUBNET               "dst_user_subnet"
#define SRC_AS                        "src_as"
#define DST_AS                        "dst_as"
#define SRC_PORT                      "srcport"
#define DST_PORT                      "dstport"
#define PROT                          "prot"
#define PROTOCOL_KEY                  "protocol"
#define IN_INTF                       "input"
#define OUT_INTF                      "output"
#define TOS_BIT                       "tos"
#define NEXT_HOP                      "nexthop"

/* Value Fields */
#define PACKET                        "pkts"
#define OCTET                         "octets"
#define FLOW_CNT                      "flows"
#define F_FLOW_STAMP                  "starttime"
#define L_FLOW_STAMP                  "endtime"
#define TOT_ACTIVE_TIME               "activetime"

/* Delimiter */                       /* Could be either "|" or "," */
#define DEL                           "%c" 

#ifdef ArgusClient
/* Aggregation Mask */
const char * const SourceNodeDef        = SRC_ADDR DEL 
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const DestNodeDef          = DST_ADDR DEL 
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const HostMatrixDef        = SRC_ADDR DEL 
                                          DST_ADDR DEL 
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const SourcePortDef        = SRC_PORT DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const DestPortDef          = DST_PORT DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const ProtocolDef          = PROTOCOL_KEY DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const DetailSourceNodeDef  = SRC_ADDR DEL 
                                          SRC_PORT DEL 
                                          DST_PORT DEL
                                          PROTOCOL_KEY DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const DetailDestNodeDef    = DST_ADDR DEL 
                                          SRC_PORT DEL 
                                          DST_PORT DEL
                                          PROTOCOL_KEY DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const DetailHostMatrixDef  = SRC_ADDR DEL 
                                          DST_ADDR DEL 
                                          SRC_PORT DEL 
                                          DST_PORT DEL
                                          PROTOCOL_KEY DEL
                                          PACKET DEL OCTET DEL FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP;

const char * const DetailInterfaceDef   = SRC_ADDR DEL
                                          DST_ADDR DEL
                                          IN_INTF DEL
                                          OUT_INTF DEL
                                          NEXT_HOP DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const CallRecordDef        = SRC_ADDR DEL  
                                          DST_ADDR DEL  
                                          SRC_PORT DEL  
                                          DST_PORT DEL  
                                          PROT DEL  
                                          TOS_BIT DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const ASMatrixDef          = SRC_AS DEL  
                                          DST_AS DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT; 

const char * const DetailASMatrixDef    = SRC_ADDR DEL
                                          DST_ADDR DEL
                                          SRC_AS DEL  
                                          DST_AS DEL  
                                          IN_INTF DEL  
                                          OUT_INTF DEL  
                                          SRC_PORT DEL
                                          DST_PORT DEL
                                          PROTOCOL_KEY DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT;

const char * const NetMatrixDef         = SRC_SUBNET DEL  
                                          SRC_SUBNET_MASK DEL  
                                          IN_INTF DEL  
                                          DST_SUBNET DEL  
                                          DST_SUBNET_MASK DEL  
                                          OUT_INTF DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT;

const char * const ASHostMatrixDef      = SRC_ADDR DEL  
                                          DST_ADDR DEL  
                                          SRC_AS DEL  
                                          DST_AS DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const HostMatrixInterfaceDef
                                        = SRC_ADDR DEL  
                                          DST_ADDR DEL  
                                          IN_INTF DEL  
                                          OUT_INTF DEL  
                                          PROTOCOL_KEY DEL
                                          PACKET DEL  OCTET DEL  FLOW_CNT;

const char * const DetailCallRecordDef  = SRC_ADDR DEL  
                                          DST_ADDR DEL  
                                          SRC_PORT DEL  
                                          DST_PORT DEL  
                                          IN_INTF DEL  
                                          OUT_INTF DEL  
                                          PROTOCOL_KEY DEL  
                                          TOS_BIT DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const RouterASDef          = SRC_AS DEL  
                                          DST_AS DEL  
                                          IN_INTF DEL  
                                          OUT_INTF DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const RouterProtoPortDef   = SRC_PORT DEL  
                                          DST_PORT DEL  
                                          PROT DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const RouterSrcPrefixDef   = SRC_SUBNET DEL  
                                          SRC_SUBNET_MASK DEL  
                                          IN_INTF DEL  
                                          SRC_AS DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const RouterDstPrefixDef   = DST_SUBNET DEL  
                                          DST_SUBNET_MASK DEL  
                                          OUT_INTF DEL  
                                          DST_AS DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const RouterPrefixDef      = SRC_SUBNET DEL  
                                          DST_SUBNET DEL  
                                          SRC_SUBNET_MASK DEL  
                                          DST_SUBNET_MASK DEL  
                                          IN_INTF DEL  
                                          OUT_INTF DEL  
                                          SRC_AS DEL  
                                          DST_AS DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;
#endif /*ArgusClient*/
#endif


#ifndef NFC_DATAFILE_H
#define NFC_DATAFILE_H

#define LABEL_LEN         16
#define IP_LEN            15
#define ASCII_HEADER_LEN  511
#define BIN_FILE_SUFFIX   ".bin"


#ifndef __NFC__
enum Aggregation
{
  noAgg,             /* reserved */
  RawFlows,          /* Not supported in binary files */
  SourceNode,
  DestNode,
  HostMatrix,
  SourcePort,
  DestPort,
  Protocol,
  DetailDestNode,
  DetailHostMatrix,
  DetailInterface,
  CallRecord,
  ASMatrix,
  NetMatrix,
  DetailSourceNode,
  DetailASMatrix,
  ASHostMatrix,
  HostMatrixInterface,
  DetailCallRecord,
  RouterAS,
  RouterProtoPort,
  RouterSrcPrefix,
  RouterDstPrefix,
  RouterPrefix
};
#endif


typedef struct {
    u_short format;             /* Header format, it is 2 in this round */
    char    newline;            /* Newline character, '\n' */
    char    ascii_header[ASCII_HEADER_LEN];  /* Header in ASCII */
    u_char  aggregation;        /* Aggregation scheme used */
    u_char  agg_version;        /* Version of the aggregation scheme used */
    char    source[IP_LEN];     /* Source IP/Name */
    u_char  period;             /* Aggregation period, 0 means PARTIAL */
    u_long  starttime;          /* Beginning of aggregation period */
    u_long  endtime;            /* End of aggregation period */
    u_long  flows;              /* Number of flows aggregated */
    int     missed;             /* Number of flows missed, -1 means not avail*/
    u_long  records;            /* Number of records in this datafile */
} BinaryHeaderF2;

#define HEADER_FORMAT_2 2


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */

} BinaryRecord_SourceNode_V1;

#define SOURCENODE_V1 1


typedef struct {
                                /* Keys */
    u_long  dstaddr;            /* Destination IP */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DestNode_V1;

#define DESTNODE_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_HostMatrix_V1;

#define HOSTMATRIX_V1 1


typedef struct {
                                /* Keys */
    char    srcport[LABEL_LEN]; /* Source Port Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_SourcePort_V1;

#define SOURCEPORT_V1 1


typedef struct {
                                /* Keys */
    char    dstport[LABEL_LEN]; /* Destination Port Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DestPort_V1;

#define DESTPORT_V1 1


typedef struct {
                                /* Keys */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_Protocol_V1;

#define PROTOCOL_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DetailSourceNode_V1;

#define DETAIL_SOURCENODE_V1 1


typedef struct {
                                /* Keys */
    u_long  dstaddr;            /* Destination IP */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DetailDestNode_V1;

#define DETAIL_DESTNODE_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
} BinaryRecord_DetailHostMatrix_V1;

#define DETAIL_HOSTMATRIX_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */
    u_long  nexthop;            /* Next Hop IP */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DetailInterface_V1;

#define DETAIL_INTERFACE_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    u_short srcport;            /* Source Port Number */
    u_short dstport;            /* Destination Port Number */
    u_char  prot;               /* Protocol Number */
    u_char  tos;                /* Type of Service */
    u_short reserved;           /* Data alignment */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_CallRecord_V1;

#define CALLRECORD_V1 1


typedef struct {
                                /* Keys */
    char    src_as[LABEL_LEN];  /* Source AS */
    char    dst_as[LABEL_LEN];  /* Destination AS */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_ASMatrix_V1;

#define ASMATRIX_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    char    src_as[LABEL_LEN];  /* Source AS */
    char    dst_as[LABEL_LEN];  /* Destination AS */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DetailASMatrix_V1;

#define DETAIL_ASMATRIX_V1 1


typedef struct {
                                /* Keys */
    u_long  src_subnet;         /* Source SubNet */
    u_short src_mask;           /* Source SubNet Mask */
    u_short input;              /* Input Interface Number */
    u_long  dst_subnet;         /* Destination SubNet */
    u_short dst_mask;           /* Destination SubNet Mask */
    u_short output;             /* Output Interface Number */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_NetMatrix_V1;

#define NETMATRIX_V1 1


typedef struct {
                                /* Keys */
    char    src_as[LABEL_LEN];  /* Source AS */
    char    dst_as[LABEL_LEN];  /* Destination AS */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_RouterAS_V1;

#define ROUTERAS_V1 1


typedef struct {
                                /* Keys */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    u_char  prot;               /* Protocol Number */
    u_char  pad;                /* Data alignment */
    u_short reserved;           /* Data alignment */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_RouterProtoPort_V1;

#define ROUTERPROTOPORT_V1 1


typedef struct {
                                /* Keys */
    u_long  src_subnet;         /* Source SubNet */
    u_short src_mask;           /* Source SubNet Mask */
    u_short input;              /* Input Interface Number */
    char    src_as[LABEL_LEN];  /* Source AS */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_RouterSrcPrefix_V1;

#define ROUTERSRCPREFIX_V1 1


typedef struct {
                                /* Keys */
    u_long  dst_subnet;         /* Destination SubNet */
    u_short dst_mask;           /* Destination SubNet Mask */
    u_short output;             /* Output Interface Number */
    char    dst_as[LABEL_LEN];  /* Destination AS */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_RouterDstPrefix_V1;

#define ROUTERDSTPREFIX_V1 1


typedef struct {
                                /* Keys */
    u_long  src_subnet;         /* Source SubNet */
    u_long  dst_subnet;         /* Destination SubNet */
    u_short src_mask;           /* Source SubNet Mask */
    u_short dst_mask;           /* Destination SubNet Mask */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */
    char    src_as[LABEL_LEN];  /* Source AS */
    char    dst_as[LABEL_LEN];  /* Destination AS */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_RouterPrefix_V1;

#define ROUTERPREFIX_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    char    src_as[LABEL_LEN];  /* Source AS */
    char    dst_as[LABEL_LEN];  /* Destination AS */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_ASHostMatrix_V1;

#define ASHOSTMATRIX_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_HostMatrixInterface_V1;

#define HOSTMATRIXINTERFACE_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */
    char    protocol[LABEL_LEN];/* Protocol Key */
    u_char  tos;                /* Type of Service */
    u_char  pad;                /* Data alignment */
    u_short reserved;           /* Data alignment */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_DetailCallRecord_V1;

#define DETAILCALLRECORD_V1 1


typedef struct {
    BinaryHeaderF2 header;
    union {
            BinaryRecord_SourceNode_V1          * srcnode;
            BinaryRecord_DestNode_V1            * dstnode;
            BinaryRecord_HostMatrix_V1          * hostmatrix;
            BinaryRecord_SourcePort_V1          * srcport;
            BinaryRecord_DestPort_V1            * dstport;
            BinaryRecord_Protocol_V1            * protocol;
            BinaryRecord_DetailSourceNode_V1    * detailsrcnode;
            BinaryRecord_DetailDestNode_V1      * detaildstnode;
            BinaryRecord_DetailHostMatrix_V1    * detailhostmatix;
            BinaryRecord_DetailInterface_V1     * detailinterface;
            BinaryRecord_CallRecord_V1          * callrecord;
            BinaryRecord_ASMatrix_V1            * asmatrix;
            BinaryRecord_DetailASMatrix_V1      * detailasmatrix;
            BinaryRecord_NetMatrix_V1           * netmatrix;
            BinaryRecord_ASHostMatrix_V1        * ashostmatrix;
            BinaryRecord_HostMatrixInterface_V1 * hostmatrixinterface;
            BinaryRecord_DetailCallRecord_V1    * detailcallrecord;
            BinaryRecord_RouterAS_V1            * routeras;
            BinaryRecord_RouterProtoPort_V1     * routerprotoport;
            BinaryRecord_RouterSrcPrefix_V1     * routersrcprefix;
            BinaryRecord_RouterDstPrefix_V1     * routerdstprefix;
            BinaryRecord_RouterPrefix_V1        * routerprefix;
    } record;
} BinaryDatafile;


#define MAX_BINARY_HEADER_F2 \
            (sizeof(BinaryHeaderF2))

#define MAX_BINARY_RECORD_SOURCE_NODE_SIZE \
            (sizeof(BinaryRecord_SourceNode_V1))

#define MAX_BINARY_RECORD_DESTINATION_NODE_SIZE \
            (sizeof(BinaryRecord_DestNode_V1))

#define MAX_BINARY_RECORD_HOST_MATRIX_SIZE \
            (sizeof(BinaryRecord_HostMatrix_V1))

#define MAX_BINARY_RECORD_SOURCE_PORT_SIZE \
            (sizeof(BinaryRecord_SourcePort_V1))

#define MAX_BINARY_RECORD_DESTINATION_PORT_SIZE \
            (sizeof(BinaryRecord_DestPort_V1))

#define MAX_BINARY_RECORD_PROTOCOL_SIZE \
            (sizeof(BinaryRecord_Protocol_V1))

#define MAX_BINARY_RECORD_DETAIL_SOURCE_NODE_SIZE \
            (sizeof(BinaryRecord_DetailSourceNode_V1))

#define MAX_BINARY_RECORD_DETAIL_DESTINATION_NODE_SIZE \
            (sizeof(BinaryRecord_DetailDestNode_V1))

#define MAX_BINARY_RECORD_DETAIL_HOST_MATRIX_SIZE \
            (sizeof(BinaryRecord_DetailHostMatrix_V1))

#define MAX_BINARY_RECORD_DETAIL_INTERFACE_SIZE \
            (sizeof(BinaryRecord_DetailInterface_V1))

#define MAX_BINARY_RECORD_CALL_RECORD_SIZE \
            (sizeof(BinaryRecord_CallRecord_V1))

#define MAX_BINARY_RECORD_AS_MATRIX_SIZE \
            (sizeof(BinaryRecord_ASMatrix_V1))

#define MAX_BINARY_RECORD_DETAIL_AS_MATRIX_SIZE \
            (sizeof(BinaryRecord_DetailASMatrix_V1))

#define MAX_BINARY_RECORD_NET_MATRIX_SIZE \
            (sizeof(BinaryRecord_NetMatrix_V1))

#define MAX_BINARY_RECORD_AS_HOST_MATRIX_SIZE \
            (sizeof(BinaryRecord_ASHostMatrix_V1))

#define MAX_BINARY_RECORD_HOST_MATRIX_INTERFACE_SIZE \
            (sizeof(BinaryRecord_HostMatrixInterface_V1))

#define MAX_BINARY_RECORD_DETAIL_CALL_RECORD_SIZE \
            (sizeof(BinaryRecord_DetailCallRecord_V1))

#define MAX_BINARY_RECORD_ROUTER_AS_SIZE \
            (sizeof(BinaryRecord_RouterAS_V1))

#define MAX_BINARY_RECORD_ROUTER_PROTO_PORT_SIZE \
            (sizeof(BinaryRecord_RouterProtoPort_V1))

#define MAX_BINARY_RECORD_ROUTER_SRC_PREFIX_SIZE \
            (sizeof(BinaryRecord_RouterSrcPrefix_V1))

#define MAX_BINARY_RECORD_ROUTER_DST_PREFIX_SIZE \
            (sizeof(BinaryRecord_RouterDstPrefix_V1))

#define MAX_BINARY_RECORD_ROUTER_PREFIX_SIZE \
            (sizeof(BinaryRecord_RouterPrefix_V1))

#endif /* __NFC_DATAFILE_H__ */


#if defined(HAVE_SOLARIS)
#include <sys/socket.h>
#endif

#define RA_MODIFIED		0x10000000

extern void ArgusLog (int, char *, ...);
extern int ArgusExitStatus;

#ifdef ArgusClient

#if defined(ARGUS_SASL)
int ArgusMaxSsf = 128;
int ArgusMinSsf = 40;
#endif

char *appOptstring = NULL;

struct RaSrvTreeNode *RaSrcTCPServicesTree[RASIGLENGTH];
struct RaSrvTreeNode *RaDstTCPServicesTree[RASIGLENGTH];
struct RaSrvTreeNode *RaSrcUDPServicesTree[RASIGLENGTH];
struct RaSrvTreeNode *RaDstUDPServicesTree[RASIGLENGTH];

struct RaSrvSignature **RaSignatureFile = NULL;
struct RaQueueStruct *RaSrvQueue = NULL;
char RaSrvTreeArray[MAXSTRLEN];
char *sigbuf[ARGUSMAXSIGFILE];


extern struct ArgusInput *ArgusInput;
extern struct ArgusDSRHeader *ArgusThisDsrs[];

extern signed long long tcp_dst_bytes, tcp_src_bytes;
extern signed long long udp_dst_bytes, udp_src_bytes;
extern signed long long icmp_dst_bytes, icmp_src_bytes;
extern signed long long ip_dst_bytes, ip_src_bytes;

extern void ArgusDebug (int, char *, ...);
extern int setArgusRemoteFilter(struct ArgusParserStruct *, unsigned char *);

void ArgusClientInit(struct ArgusParserStruct *);
void RaArgusInputComplete (struct ArgusInput *);
void RaParseComplete (int);

int RaParseType (char *);
struct ArgusISOAddr *RaParseISOAddr (struct ArgusParserStruct *, char *);
struct ArgusCIDRAddr *RaParseCIDRAddr (struct ArgusParserStruct *, char *);

void ArgusClientTimeout (void);
void parse_arg (int, char**);
void usage (void);

void RaClearConfiguration (struct ArgusParserStruct *);

struct ArgusRecordStruct *ArgusCopyRecordStruct (struct ArgusRecordStruct *);
void RaDeleteArgusRecordStruct (struct ArgusParserStruct *, struct ArgusRecordStruct *);
signed long long RaGetActiveDuration (struct ArgusRecordStruct *);
signed long long RaGetuSecDuration (struct ArgusRecordStruct *);
signed long long RaGetuSecAvgDuration (struct ArgusRecordStruct *);
float RaGetFloatSrcDuration(struct ArgusRecordStruct *);
float RaGetFloatDstDuration(struct ArgusRecordStruct *);
float RaGetFloatDuration(struct ArgusRecordStruct *);
float RaGetFloatAvgDuration(struct ArgusRecordStruct *);
float RaGetFloatMinDuration(struct ArgusRecordStruct *);
float RaGetFloatMaxDuration(struct ArgusRecordStruct *);

void RaProcessRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessManRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessEventRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessFragRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessTCPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessICMPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessIGMPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessUDPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessIPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessARPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessNonIPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

struct RaFlowModelStruct *RaReadFlowModelFile (struct ArgusParserStruct *, char **);

void *ArgusProcessInputList (void *);
void ArgusReadFileStream (struct ArgusParserStruct *parser, struct ArgusInput *);
void *ArgusConnectRemotes (void *);
void *ArgusConnectRemote (void *);
 
void ArgusCloseInput(struct ArgusParserStruct *parser, struct ArgusInput *);
int ArgusReadStreamSocket (struct ArgusParserStruct *parser, struct ArgusInput *);

extern void ArgusLog (int, char *, ...);
extern int RaSendArgusRecord(struct ArgusRecordStruct *);

extern void ArgusClientTimeout (void);
extern void clearArgusWfile(struct ArgusParserStruct *);
extern unsigned char *ArgusConvertRecord (struct ArgusInput *, char *);

int ArgusWriteConnection (struct ArgusParserStruct *parser, struct ArgusInput *, u_char *, int);

char *RaGenerateLabel(struct ArgusParserStruct *, struct ArgusRecordStruct *);

int RaParseProbeResourceFile (char **);
int RaProbeMonitorsThisAddr (unsigned int, unsigned int);
int ArgusProcessFileIndependantly = 0;

struct ArgusAggregatorStruct *ArgusParseAggregator (struct ArgusParserStruct *, char *, char **);

struct ArgusRecordStruct *ArgusGenerateRecordStruct (struct ArgusParserStruct *, struct ArgusInput *, struct ArgusRecord *);
struct ArgusRecord *ArgusGenerateRecord (struct ArgusRecordStruct *, unsigned char, char *);

void ArgusDeleteRecordStruct (struct ArgusParserStruct *, struct ArgusRecordStruct *); 

struct ArgusRecordStruct *ArgusFindRecord (struct ArgusHashTable *, struct ArgusHashStruct *);
struct ArgusMaskStruct *ArgusSelectMaskDefs(struct ArgusRecordStruct *ns);
struct ArgusMaskStruct *ArgusSelectRevMaskDefs(struct ArgusRecordStruct *ns);

struct ArgusHashTable *ArgusNewHashTable (size_t);
void ArgusDeleteHashTable (struct ArgusHashTable *);

struct ArgusHashStruct *ArgusGenerateHashStruct (struct ArgusAggregatorStruct *,  struct ArgusRecordStruct *, struct ArgusFlow *);
struct ArgusHashStruct *ArgusGenerateReverseHashStruct (struct ArgusAggregatorStruct *,  struct ArgusRecordStruct *, struct ArgusFlow *);
struct ArgusHashStruct *ArgusGenerateHintStruct (struct ArgusAggregatorStruct *,  struct ArgusRecordStruct *);
struct ArgusHashTableHdr *ArgusAddHashEntry (struct ArgusHashTable *, void *, struct ArgusHashStruct *);
struct ArgusHashTableHdr *ArgusFindHashEntry (struct ArgusHashTable *, struct ArgusHashStruct *);
void ArgusRemoveHashEntry (struct ArgusHashTableHdr **);
void ArgusEmptyHashTable (struct ArgusHashTable *);

struct ArgusListStruct *ArgusNewList (void);
void ArgusDeleteList (struct ArgusListStruct *, int);
int ArgusListEmpty (struct ArgusListStruct *);
int ArgusGetListCount(struct ArgusListStruct *);
int ArgusPushFrontList(struct ArgusListStruct *, struct ArgusListRecord *, int);
int ArgusPushBackList(struct ArgusListStruct *, struct ArgusListRecord *, int);
struct ArgusListRecord *ArgusFrontList(struct ArgusListStruct *);
struct ArgusListRecord *ArgusBackList(struct ArgusListStruct *);
struct ArgusListRecord *ArgusPopBackList(struct ArgusListStruct *, int);
struct ArgusListRecord *ArgusPopFrontList(struct ArgusListStruct *, int);

int ArgusProcessServiceAvailability (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusCheckTime (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusCheckTimeout (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int RaTestUserData(struct RaBinStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *, int);
void ArgusMergeUserData(struct RaBinStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);
void RaProcessSrvRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
struct RaBinProcessStruct *RaNewBinProcess (struct ArgusParserStruct *, int);
void RaPrintOutQueue (struct RaBinStruct *, struct ArgusQueueStruct *, int);

int RaReadSrvSignature(struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
struct RaSrvSignature *RaValidateService(struct ArgusParserStruct *, struct ArgusRecordStruct *);

extern struct ArgusLabelerStruct *ArgusNewLabeler (struct ArgusParserStruct *, int);

int ArgusHistoMetricParse (struct ArgusParserStruct *, struct ArgusAggregatorStruct *);
int ArgusHistoTallyMetric (struct ArgusParserStruct *, struct ArgusRecordStruct *);

struct RaBinStruct *RaNewBin (struct ArgusParserStruct *, struct RaBinProcessStruct *, struct ArgusRecordStruct *, long long, int);
void RaDeleteBin (struct ArgusParserStruct *, struct RaBinStruct *);

struct ArgusRecordStruct *ArgusAlignRecord(struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusAdjustStruct *);
int ArgusInsertRecord (struct ArgusParserStruct *, struct RaBinProcessStruct *, struct ArgusRecordStruct *, int);
void ArgusCalculatePeriod (struct ArgusRecordStruct *, struct ArgusAdjustStruct *);

void ArgusAdjustSrcLoss (struct ArgusRecordStruct *, double);
void ArgusAdjustDstLoss (struct ArgusRecordStruct *, double);

#else /* ArgusClient */


#if defined(ARGUS_SASL)
extern int ArgusMaxSsf;
extern int ArgusMinSsf;
#endif /* ARGUS_SASL */

extern char *appOptstring;

extern struct RaSrvTreeNode *RaSrcTCPServicesTree[RASIGLENGTH];
extern struct RaSrvTreeNode *RaDstTCPServicesTree[RASIGLENGTH];
extern struct RaSrvTreeNode *RaSrcUDPServicesTree[RASIGLENGTH];
extern struct RaSrvTreeNode *RaDstUDPServicesTree[RASIGLENGTH];

extern struct RaSrvSignature **RaSignatureFile;
extern struct RaQueueStruct *RaSrvQueue;
extern char RaSrvTreeArray[MAXSTRLEN];
extern char *sigbuf[ARGUSMAXSIGFILE];


extern void ArgusDebug (int, char *, ...);
extern int setArgusRemoteFilter(struct ArgusParserStruct *, char *);

extern void ArgusClientInit(struct ArgusParserStruct *);
extern void RaArgusInputComplete (struct ArgusInput *);
extern void RaParseComplete (int);

extern int RaParseType (char *);
extern struct ArgusISOAddr *RaParseISOAddr (struct ArgusParserStruct *, char *);
extern struct ArgusCIDRAddr *RaParseCIDRAddr (struct ArgusParserStruct *, char *);

extern void ArgusClientTimeout (void);
extern void parse_arg (int, char**);
extern void usage (void);

extern struct ArgusRecordStruct *ArgusCopyRecordStruct (struct ArgusRecordStruct *);
extern void RaDeleteArgusRecordStruct (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern signed long long RaGetActiveDuration (struct ArgusRecordStruct *);
extern signed long long RaGetuSecDuration (struct ArgusRecordStruct *);
extern signed long long RaGetuSecAvgDuration (struct ArgusRecordStruct *);
extern float RaGetFloatSrcDuration(struct ArgusRecordStruct *);
extern float RaGetFloatDstDuration(struct ArgusRecordStruct *);
extern float RaGetFloatDuration(struct ArgusRecordStruct *);
extern float RaGetFloatAvgDuration(struct ArgusRecordStruct *);
extern float RaGetFloatMinDuration(struct ArgusRecordStruct *);
extern float RaGetFloatMaxDuration(struct ArgusRecordStruct *);

extern void RaProcessRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern void RaProcessManRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern void RaProcessEventRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern void RaProcessFragRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern void RaProcessTCPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern void RaProcessICMPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern void RaProcessIGMPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern void RaProcessUDPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern void RaProcessIPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern void RaProcessARPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern void RaProcessNonIPRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

extern struct RaFlowModelStruct *RaReadFlowModelFile (struct ArgusParserStruct *, char **);

extern void *ArgusProcessInputList (void *);
extern void ArgusReadFileStream (struct ArgusParserStruct *parser, struct ArgusInput *);
extern void *ArgusConnectRemotes (void *);
extern void *ArgusConnectRemote (void *);
 
extern void ArgusCloseInput(struct ArgusParserStruct *parser, struct ArgusInput *);
extern int ArgusReadStreamSocket (struct ArgusParserStruct *parser, struct ArgusInput *);

extern void ArgusLog (int, char *, ...);

extern char *RaGenerateLabel(struct ArgusParserStruct *, struct ArgusRecordStruct *);

extern int RaSendArgusRecord(struct ArgusRecordStruct *);
extern int RaProbeMonitorsThisAddr (unsigned int, unsigned int);
extern int ArgusProcessFileIndependantly;

extern struct ArgusAggregatorStruct *ArgusParseAggregator (struct ArgusParserStruct *, char *, char **);
extern struct ArgusRecordStruct *ArgusGenerateRecordStruct (struct ArgusParserStruct *, struct ArgusInput *, struct ArgusRecord *);
extern struct ArgusRecord *ArgusGenerateRecord (struct ArgusRecordStruct *, unsigned char, char *);

extern void ArgusDeleteRecordStruct (struct ArgusParserStruct *, struct ArgusRecordStruct *); 
extern struct ArgusRecordStruct *ArgusFindRecord (struct ArgusHashTable *, struct ArgusHashStruct *);

extern struct ArgusMaskStruct *ArgusSelectMaskDefs(struct ArgusRecordStruct *ns);
extern struct ArgusMaskStruct *ArgusSelectRevMaskDefs(struct ArgusRecordStruct *ns);

extern struct ArgusHashTable *ArgusNewHashTable (size_t);
extern void ArgusDeleteHashTable (struct ArgusHashTable *);
extern struct ArgusHashStruct *ArgusGenerateHashStruct (struct ArgusAggregatorStruct *,  struct ArgusRecordStruct *, struct ArgusFlow *);
extern struct ArgusHashStruct *ArgusGenerateReverseHashStruct (struct ArgusAggregatorStruct *,  struct ArgusRecordStruct *, struct ArgusFlow *);
extern struct ArgusHashStruct *ArgusGenerateHintStruct (struct ArgusAggregatorStruct *,  struct ArgusRecordStruct *);
extern struct ArgusHashTableHdr *ArgusAddHashEntry (struct ArgusHashTable *, struct ArgusRecordStruct *, struct ArgusHashStruct *);
extern struct ArgusHashTableHdr *ArgusFindHashEntry (struct ArgusHashTable *, struct ArgusHashStruct *);
extern void ArgusRemoveHashEntry (struct ArgusHashTableHdr **);
extern void ArgusEmptyHashTable (struct ArgusHashTable *);

extern struct ArgusListStruct *ArgusNewList (void);
extern void ArgusDeleteList (struct ArgusListStruct *, int);
extern int ArgusListEmpty (struct ArgusListStruct *);
extern int ArgusGetListCount(struct ArgusListStruct *);
extern int ArgusPushFrontList(struct ArgusListStruct *, struct ArgusListRecord *, int);
extern int ArgusPushBackList(struct ArgusListStruct *, struct ArgusListRecord *, int);
extern struct ArgusListRecord *ArgusFrontList(struct ArgusListStruct *);
extern struct ArgusListRecord *ArgusBackList(struct ArgusListStruct *);
extern struct ArgusListRecord *ArgusPopBackList(struct ArgusListStruct *, int);
extern struct ArgusListRecord *ArgusPopFrontList(struct ArgusListStruct *, int);

extern int RaTestUserData(struct RaBinStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *, int);
extern void ArgusMergeUserData(struct RaBinStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern void RaProcessSrvRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern struct RaBinProcessStruct *RaNewBinProcess (struct ArgusParserStruct *, int);
extern void RaPrintOutQueue (struct RaBinStruct *, struct ArgusQueueStruct *, int);

extern int RaReadSrvSignature(struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern struct RaSrvSignature *RaValidateService(struct ArgusParserStruct *, struct ArgusRecordStruct *);

extern struct ArgusLabelerStruct *ArgusNewLabeler (struct ArgusParserStruct *, int);

extern int ArgusProcessServiceAvailability (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern int ArgusCheckTime (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern int ArgusCheckTimeout (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);

extern int ArgusHistoMetricParse (struct ArgusParserStruct *, struct ArgusAggregatorStruct *);
extern int ArgusHistoTallyMetric (struct ArgusParserStruct *, struct ArgusRecordStruct *);

extern struct RaBinStruct *RaNewBin (struct ArgusParserStruct *, struct RaBinProcessStruct *, struct ArgusRecordStruct *, long long, int);
extern void RaDeleteBin (struct ArgusParserStruct *, struct RaBinStruct *);

extern struct ArgusRecordStruct *ArgusAlignRecord(struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusAdjustStruct *);
extern int ArgusInsertRecord (struct ArgusParserStruct *, struct RaBinProcessStruct *, struct ArgusRecordStruct *, int);
extern void ArgusCalculatePeriod (struct ArgusRecordStruct *, struct ArgusAdjustStruct *);

extern void ArgusAdjustSrcLoss (struct ArgusRecordStruct *, double);
extern void ArgusAdjustDstLoss (struct ArgusRecordStruct *, double);

#endif
#endif