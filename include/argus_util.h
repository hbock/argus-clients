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
 * $Id: //depot/argus/argus-3.0/clients/include/argus_util.h#37 $
 * $DateTime: 2006/05/25 02:07:01 $
 * $Change: 858 $
 */

#ifndef ArgusUtil_h
#define ArgusUtil_h

#include <argus_os.h>
#include <compat.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif

#include <argus_def.h>
#include <argus_out.h>
#include <cons_out.h>

#define ARGUS_MAX_PRINT_ALG     	173
#define MAX_PRINT_ALG_TYPES     	173


#include <CflowdFlowPdu.h>

typedef void (*proc)(void);
typedef char *(*strproc)(void);

struct ArgusQueueHeader {
   struct ArgusQueueHeader *nxt;
   struct ArgusQueueHeader *prv;
   struct ArgusQueueStruct *queue;
   struct timeval lasttime, logtime;
};


struct ArgusMemoryHeader {
   struct ArgusMemoryHeader *nxt, *prv;
#if defined(__GNUC__)
   void *frame[3];
#endif
   unsigned int tag;
   unsigned short len;
   unsigned short offset;
};

struct ArgusMemoryList {
   struct ArgusMemoryHeader *start, *end;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif
   int total, count, size;
   int out, in, freed;
};

struct ArgusQueueStruct {
   unsigned int count;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif
   struct ArgusQueueHeader *start, *end;
   struct ArgusQueueHeader **array;
};

#include <argus_parser.h>
#include <argus_cluster.h>

#if defined(__OpenBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#include <netinet/ip_icmp.h>
#undef ICMP_MAXTYPE
#define ICMP_MAXTYPE	46

 
struct ArgusFileEntry {
   struct ArgusFileEntry *nxt;
   char *str;
};

 
#define ARGUS_NOLOCK     0
#define ARGUS_LOCK       1

#define ARGUS_RFILE_LIST        1
#define ARGUS_WFILE_LIST        2
#define ARGUS_DEVICE_LIST       3
#define ARGUS_OUTPUT_LIST       4
#define ARGUS_MODE_LIST         5


struct ArgusListObjectStruct {
   struct ArgusListObjectStruct *nxt, *prv;
   union {
      void *obj;
      unsigned int val;
   } list_union;
};

#define list_obj	list_union.obj
#define list_val	list_union.val
 
struct ArgusListRecord {
   struct ArgusListObjectStruct *nxt, *prv;
   struct ArgusRecordHeader argus;
};
 
struct ArgusListStruct {
   struct ArgusListObjectStruct *start;
   struct ArgusListObjectStruct *end;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
   pthread_cond_t cond;
#endif
   struct timeval outputTime, reportTime;
   unsigned int count;
};

struct ArgusPrintFieldStruct {
   char *field, *format;
   int length, index, class, value;
   void (*print)(struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
   void (*label)(struct ArgusParserStruct *, char *, int);
   char *dbformat;
};


#define Version1        1
#define Version5        5
#define Version6        6
#define Version7        7
#define Version8        8


struct ArgusRecord *ArgusNetFlowCallRecord (struct ArgusInput *, u_char **);
struct ArgusRecord *ArgusNetFlowDetailInt  (struct ArgusInput *, u_char **);
struct ArgusRecord *ArgusParseCiscoRecord (struct ArgusInput *, u_char **);

#ifdef ARGUS_SASL
#include <sasl/sasl.h>
#endif

#include <sys/stat.h>
#include <stdio.h>

#define ARGUS_DATA_SOURCE		0x01
#define ARGUS_V2_DATA_SOURCE		0x02
#define ARGUS_CISCO_DATA_SOURCE		0x10

#define ipaddr_string(p) ArgusGetName(ArgusParser, (u_char *)(p))

#ifdef ArgusUtil

void ArgusHandleSig (int);

char *chroot_dir = NULL;
uid_t new_uid;
gid_t new_gid;


extern int ArgusDeletePIDFile (struct ArgusParserStruct *);
extern char *ArgusCreatePIDFile (struct ArgusParserStruct *, char *);

void ArgusMainInit (struct ArgusParserStruct *, int, char **);

int RaDescend(char *);
int RaProcessRecursiveFiles (char *);

#define RAENVITEMS      2

char *RaResourceEnvStr [] = {
   "HOME",
   "ARGUSHOME",
};

char *RaOutputFilter = NULL;
char *RaHomePath = NULL;

char *RaDatabase = NULL;
char **RaTables = NULL;

int RaWriteOut = 1;
int ArgusSOptionRecord = 1;

long thiszone;

void ArgusParseArgs (struct ArgusParserStruct *, int, char **);


void ArgusPrintCause (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintRelativeDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSourceID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintFlags (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintProto (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintAddr (struct ArgusParserStruct *, char *, int, void *, int, int, int);
void ArgusPrintSrcNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int, unsigned char, unsigned int, int, int);
void ArgusPrintSrcPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDir (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveSrcIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveDstIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleSrcIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleDstIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveSrcJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveDstJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleSrcJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleDstJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintState (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaStartTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaLastTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaSrcPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaDstPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDeltaSrcPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDeltaDstPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDeltaSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDeltaDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcUserData (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstUserData (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintUserData (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPExtensions (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSrcLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDstLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSrcRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDstRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSrcNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDstNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintSrcSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSrcSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDstSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSrcFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDstFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintAutoId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintSrcRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcTos (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstTos (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcDSByte (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstDSByte (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcIpId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstIpId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcTtl (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstTtl (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcVlan (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstVlan (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcVID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstVID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcVPRI (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstVPRI (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMpls (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMpls (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcWindow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstWindow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintJoinDelay (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLeaveDelay (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintMean (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintStdDeviation (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintStartRange (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintEndRange (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTransactions (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSequenceNumber (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintBinNumber (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintBins (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPSrcBase (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPDstBase (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPRTT (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPSynAck (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPAckDat (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPSrcMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPDstMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintManStatus (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintICMPStatus (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIGMPStatus (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIPStatus (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintInode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintByteOffset (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcEncaps (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstEncaps (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMaxPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMinPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMaxPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMinPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcCountryCode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstCountryCode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcHopCount (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstHopCount (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIcmpId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcAsn (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstAsn (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintInodeAsn (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintCauseLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintStartDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLastDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcStartDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcLastDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstStartDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstLastDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintRelativeDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSourceIDLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintFlagsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMacAddressLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMacAddressLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMacAddressLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintProtoLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcNetLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstNetLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcPortLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstPortLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcIpIdLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstIpIdLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIpIdLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcTtlLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstTtlLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTtlLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDirLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPacketsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcPacketsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstPacketsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintAppBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcAppBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstAppBytesLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintSrcIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcIntPktDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstIntPktDistLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintActiveSrcIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveSrcIntPktDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveDstIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveDstIntPktDistLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintIdleSrcIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleSrcIntPktDistLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintIdleDstIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleDstIntPktDistLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveSrcIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveDstIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveDstIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleSrcIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleDstIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleDstIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveSrcJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveDstJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleSrcJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleDstJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintStateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaDurationLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaStartTimeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaLastTimeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaSrcPktsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaDstPktsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaSrcBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaDstBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDeltaSrcPktsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDeltaDstPktsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDeltaSrcBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDeltaDstBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcUserDataLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstUserDataLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintUserDataLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPExtensionsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcLoadLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstLoadLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLoadLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSrcRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDstRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSrcNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDstNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSrcSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDstSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSrcFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDstFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSrcLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDstLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcRateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstRateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintRateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcTosLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstTosLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcDSByteLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstDSByteLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcVlanLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstVlanLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcVIDLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstVIDLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcVPRILabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstVPRILabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMplsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMplsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintWindowLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcWindowLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstWindowLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintJoinDelayLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLeaveDelayLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMeanLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintStdDeviationLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintStartRangeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintEndRangeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcDurationLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstDurationLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDurationLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTransactionsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSequenceNumberLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintBinNumberLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintBinsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPSrcBaseLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPDstBaseLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPRTTLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPSynAckLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPAckDatLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPSrcMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPDstMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintInodeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintByteOffsetLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcEncapsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstEncapsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMaxPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMaxPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMinPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMaxPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMinPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcCountryCodeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstCountryCodeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcHopCountLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstHopCountLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIcmpIdLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintAutoIdLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLabelLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcAsnLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstAsnLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintInodeAsnLabel (struct ArgusParserStruct *, char *, int);

struct ArgusPrintFieldStruct 
RaPrintAlgorithmTable[MAX_PRINT_ALG_TYPES] = {
#define ARGUSPRINTSTARTDATE		0
   { "stime", "%T.%f", 12 , 1, 0, ARGUSPRINTSTARTDATE, ArgusPrintStartDate, ArgusPrintStartDateLabel, "double(18,6) unsigned not null"},
#define ARGUSPRINTLASTDATE		1
   { "ltime", "%T.%f", 12 , 1, 0, ARGUSPRINTLASTDATE, ArgusPrintLastDate, ArgusPrintLastDateLabel, "double(18,6) unsigned not null"},
#define ARGUSPRINTTRANSACTIONS		2
   { "trans", "", 6 , 1, 0, ARGUSPRINTTRANSACTIONS, ArgusPrintTransactions, ArgusPrintTransactionsLabel, "int unsigned"},
#define ARGUSPRINTDURATION		3
   { "dur", "", 10 , 1, 0, ARGUSPRINTDURATION, ArgusPrintDuration, ArgusPrintDurationLabel, "double(18,6) not null"},
#define ARGUSPRINTMEAN		        4
   { "mean", "", 10 , 1, 0, ARGUSPRINTMEAN, ArgusPrintMean, ArgusPrintMeanLabel, "double"},
#define ARGUSPRINTMIN			5
   { "min", "", 10 , 1, 0, ARGUSPRINTMIN, ArgusPrintMin, ArgusPrintMinLabel, "double"},
#define ARGUSPRINTMAX			6
   { "max", "", 10 , 1, 0, ARGUSPRINTMAX, ArgusPrintMax, ArgusPrintMaxLabel, "double"},
#define ARGUSPRINTSRCADDR		7
   { "saddr", "", 18 , 1, 0, ARGUSPRINTSRCADDR, ArgusPrintSrcAddr, ArgusPrintSrcAddrLabel, "varchar(64) not null"},
#define ARGUSPRINTDSTADDR		8
   { "daddr", "", 18 , 1, 0, ARGUSPRINTDSTADDR, ArgusPrintDstAddr, ArgusPrintDstAddrLabel, "varchar(64) not null"},
#define ARGUSPRINTPROTO			9
   { "proto", "", 6 , 1, 0, ARGUSPRINTPROTO, ArgusPrintProto, ArgusPrintProtoLabel, "varchar(16) not null"},
#define ARGUSPRINTSRCPORT		10
   { "sport", "", 6 , 1, 0, ARGUSPRINTSRCPORT, ArgusPrintSrcPort, ArgusPrintSrcPortLabel, "varchar(10) not null"},
#define ARGUSPRINTDSTPORT		11
   { "dport", "", 6 , 1, 0, ARGUSPRINTDSTPORT, ArgusPrintDstPort, ArgusPrintDstPortLabel, "varchar(10) not null"},
#define ARGUSPRINTSRCTOS		12
   { "stos", "", 5 , 1, 0, ARGUSPRINTSRCTOS, ArgusPrintSrcTos, ArgusPrintSrcTosLabel, "tinyint unsigned"},
#define ARGUSPRINTDSTTOS		13
   { "dtos", "", 5 , 1, 0, ARGUSPRINTDSTTOS, ArgusPrintDstTos, ArgusPrintDstTosLabel, "tinyint unsigned"},
#define ARGUSPRINTSRCDSBYTE		14
   { "sdsb", "", 5 , 1, 0, ARGUSPRINTSRCDSBYTE, ArgusPrintSrcDSByte, ArgusPrintSrcDSByteLabel, "varchar(4) not null"},
#define ARGUSPRINTDSTDSBYTE		15
   { "ddsb", "", 5 , 1, 0, ARGUSPRINTDSTDSBYTE, ArgusPrintDstDSByte, ArgusPrintDstDSByteLabel, "varchar(4) not null"},
#define ARGUSPRINTSRCTTL		16
   { "sttl", "", 4 , 1, 0, ARGUSPRINTSRCTTL, ArgusPrintSrcTtl, ArgusPrintSrcTtlLabel, "tinyint unsigned"},
#define ARGUSPRINTDSTTTL		17
   { "dttl", "", 4 , 1, 0, ARGUSPRINTDSTTTL, ArgusPrintDstTtl, ArgusPrintDstTtlLabel, "tinyint unsigned"},
#define ARGUSPRINTBYTES			18
   { "bytes", "", 10 , 1, 0, ARGUSPRINTBYTES, ArgusPrintBytes, ArgusPrintBytesLabel, "bigint"},
#define ARGUSPRINTSRCBYTES		19
   { "sbytes", "", 12 , 1, 0, ARGUSPRINTSRCBYTES, ArgusPrintSrcBytes, ArgusPrintSrcBytesLabel, "bigint"},
#define ARGUSPRINTDSTBYTES		20
   { "dbytes", "", 12 , 1, 0, ARGUSPRINTDSTBYTES, ArgusPrintDstBytes, ArgusPrintDstBytesLabel, "bigint"},
#define ARGUSPRINTAPPBYTES              21
   { "appbytes", "", 10 , 1, 0, ARGUSPRINTAPPBYTES, ArgusPrintAppBytes, ArgusPrintAppBytesLabel, "bigint"},
#define ARGUSPRINTSRCAPPBYTES           22
   { "sappbytes", "", 12 , 1, 0, ARGUSPRINTSRCAPPBYTES, ArgusPrintSrcAppBytes, ArgusPrintSrcAppBytesLabel, "bigint"},
#define ARGUSPRINTDSTAPPBYTES           23
   { "dappbytes", "", 12 , 1, 0, ARGUSPRINTDSTAPPBYTES, ArgusPrintDstAppBytes, ArgusPrintDstAppBytesLabel, "bigint"},
#define ARGUSPRINTPACKETS		24
   { "pkts", "", 8 , 1, 0, ARGUSPRINTPACKETS, ArgusPrintPackets, ArgusPrintPacketsLabel, "bigint"},
#define ARGUSPRINTSRCPACKETS		25
   { "spkts", "", 8 , 1, 0, ARGUSPRINTSRCPACKETS, ArgusPrintSrcPackets, ArgusPrintSrcPacketsLabel, "bigint"},
#define ARGUSPRINTDSTPACKETS		26
   { "dpkts", "", 8 , 1, 0, ARGUSPRINTDSTPACKETS, ArgusPrintDstPackets, ArgusPrintDstPacketsLabel, "bigint"},
#define ARGUSPRINTLOAD			27
   { "load", "", 8 , 1, 0, ARGUSPRINTLOAD, ArgusPrintLoad, ArgusPrintLoadLabel, "double"},
#define ARGUSPRINTSRCLOAD		28
   { "sload", "", 8 , 1, 0, ARGUSPRINTSRCLOAD, ArgusPrintSrcLoad, ArgusPrintSrcLoadLabel, "double"},
#define ARGUSPRINTDSTLOAD		29
   { "dload", "", 8 , 1, 0, ARGUSPRINTDSTLOAD, ArgusPrintDstLoad, ArgusPrintDstLoadLabel, "double"},
#define ARGUSPRINTLOSS			30
   { "loss", "", 10 , 1, 0, ARGUSPRINTLOSS, ArgusPrintLoss, ArgusPrintLossLabel, "int"},
#define ARGUSPRINTSRCLOSS		31
   { "sloss", "", 10 , 1, 0, ARGUSPRINTSRCLOSS, ArgusPrintSrcLoss, ArgusPrintSrcLossLabel, "int"},
#define ARGUSPRINTDSTLOSS		32
   { "dloss", "", 10 , 1, 0, ARGUSPRINTDSTLOSS, ArgusPrintDstLoss, ArgusPrintDstLossLabel, "int"},
#define ARGUSPRINTPERCENTLOSS		33
   { "ploss", "", 8 , 1, 0, ARGUSPRINTPERCENTLOSS, ArgusPrintPercentLoss, ArgusPrintPercentLossLabel, "double"},
#define ARGUSPRINTSRCPERCENTLOSS	34
   { "sploss", "", 10 , 1, 0, ARGUSPRINTSRCPERCENTLOSS, ArgusPrintPercentSrcLoss, ArgusPrintPercentSrcLossLabel, "double"},
#define ARGUSPRINTDSTPERCENTLOSS	35
   { "dploss", "", 10 , 1, 0, ARGUSPRINTDSTPERCENTLOSS, ArgusPrintPercentDstLoss, ArgusPrintPercentDstLossLabel, "double"},
#define ARGUSPRINTRATE			36
   { "rate", "", 12 , 1, 0, ARGUSPRINTRATE, ArgusPrintRate, ArgusPrintRateLabel, "double"},
#define ARGUSPRINTSRCRATE		37
   { "srate", "", 12 , 1, 0, ARGUSPRINTSRCRATE, ArgusPrintSrcRate, ArgusPrintSrcRateLabel, "double"},
#define ARGUSPRINTDSTRATE		38
   { "drate", "", 12 , 1, 0, ARGUSPRINTDSTRATE, ArgusPrintDstRate, ArgusPrintDstRateLabel, "double"},
#define ARGUSPRINTSOURCEID		39
   { "srcid", "", 18 , 1, 0, ARGUSPRINTSOURCEID, ArgusPrintSourceID, ArgusPrintSourceIDLabel, "varchar(64)"},
#define ARGUSPRINTFLAGS			40
   { "flgs", "", 7 , 1, 0, ARGUSPRINTFLAGS, ArgusPrintFlags, ArgusPrintFlagsLabel, "varchar(32)"},
#define ARGUSPRINTSRCMACADDRESS		41
   { "smac", "", 18 , 1, 0, ARGUSPRINTSRCMACADDRESS, ArgusPrintSrcMacAddress, ArgusPrintSrcMacAddressLabel, "varchar(24)"},
#define ARGUSPRINTDSTMACADDRESS		42
   { "dmac", "", 18 , 1, 0, ARGUSPRINTDSTMACADDRESS, ArgusPrintDstMacAddress, ArgusPrintDstMacAddressLabel, "varchar(24)"},
#define ARGUSPRINTDIR			43
   { "dir", "", 5 , 1, 0, ARGUSPRINTDIR, ArgusPrintDir, ArgusPrintDirLabel, "varchar(3)"},
#define ARGUSPRINTSRCINTPKT		44
   { "sintpkt", "", 12 , 1, 0, ARGUSPRINTSRCINTPKT, ArgusPrintSrcIntPkt, ArgusPrintSrcIntPktLabel, "double"},
#define ARGUSPRINTDSTINTPKT		45
   { "dintpkt", "", 12 , 1, 0, ARGUSPRINTDSTINTPKT, ArgusPrintDstIntPkt, ArgusPrintDstIntPktLabel, "double"},
#define ARGUSPRINTACTSRCINTPKT		46
   { "sintpktact", "", 12 , 1, 0, ARGUSPRINTACTSRCINTPKT, ArgusPrintActiveSrcIntPkt, ArgusPrintActiveSrcIntPktLabel, "double"},
#define ARGUSPRINTACTDSTINTPKT		47
   { "dintpktact", "", 12 , 1, 0, ARGUSPRINTACTDSTINTPKT, ArgusPrintActiveDstIntPkt, ArgusPrintActiveDstIntPktLabel, "double"},
#define ARGUSPRINTIDLESRCINTPKT		48
   { "sintpktidl", "", 12 , 1, 0, ARGUSPRINTIDLESRCINTPKT, ArgusPrintIdleSrcIntPkt, ArgusPrintIdleSrcIntPktLabel, "double"},
#define ARGUSPRINTIDLEDSTINTPKT		49
   { "dintpktidl", "", 12 , 1, 0, ARGUSPRINTIDLEDSTINTPKT, ArgusPrintIdleDstIntPkt, ArgusPrintIdleDstIntPktLabel, "double"},
#define ARGUSPRINTSRCINTPKTMAX		50
   { "sintpktmax", "", 12 , 1, 0, ARGUSPRINTSRCINTPKTMAX, ArgusPrintSrcIntPktMax, ArgusPrintSrcIntPktMaxLabel, "double"},
#define ARGUSPRINTSRCINTPKTMIN		51
   { "sintpktmin", "", 12 , 1, 0, ARGUSPRINTSRCINTPKTMIN, ArgusPrintSrcIntPktMin, ArgusPrintSrcIntPktMinLabel, "double"},
#define ARGUSPRINTDSTINTPKTMAX		52
   { "dintpktmax", "", 12 , 1, 0, ARGUSPRINTDSTINTPKTMAX, ArgusPrintDstIntPktMax, ArgusPrintDstIntPktMaxLabel, "double"},
#define ARGUSPRINTDSTINTPKTMIN		53
   { "dintpktmin", "", 12 , 1, 0, ARGUSPRINTDSTINTPKTMIN, ArgusPrintDstIntPktMin, ArgusPrintDstIntPktMinLabel, "double"},
#define ARGUSPRINTACTSRCINTPKTMAX	54
   { "sintpktactmax", "", 12 , 1, 0, ARGUSPRINTACTSRCINTPKTMAX, ArgusPrintActiveSrcIntPktMax, ArgusPrintActiveSrcIntPktMaxLabel, "double"},
#define ARGUSPRINTACTSRCINTPKTMIN	55
   { "sintpktactmin", "", 12 , 1, 0, ARGUSPRINTACTSRCINTPKTMIN, ArgusPrintActiveSrcIntPktMin, ArgusPrintActiveSrcIntPktMinLabel, "double"},
#define ARGUSPRINTACTDSTINTPKTMAX	56
   { "dintpktactmax", "", 12 , 1, 0, ARGUSPRINTACTDSTINTPKTMAX, ArgusPrintActiveDstIntPktMax, ArgusPrintActiveDstIntPktMaxLabel, "double"},
#define ARGUSPRINTACTDSTINTPKTMIN	57
   { "dintpktactmin", "", 12 , 1, 0, ARGUSPRINTACTDSTINTPKTMIN, ArgusPrintActiveDstIntPktMin, ArgusPrintActiveDstIntPktMinLabel, "double"},
#define ARGUSPRINTIDLESRCINTPKTMAX	58
   { "sintpktidlmax", "", 12 , 1, 0, ARGUSPRINTIDLESRCINTPKTMAX, ArgusPrintIdleSrcIntPktMax, ArgusPrintIdleSrcIntPktMaxLabel, "double"},
#define ARGUSPRINTIDLESRCINTPKTMIN	59
   { "sintpktidlmin", "", 12 , 1, 0, ARGUSPRINTIDLESRCINTPKTMIN, ArgusPrintIdleSrcIntPktMin, ArgusPrintIdleSrcIntPktMinLabel, "double"},
#define ARGUSPRINTIDLEDSTINTPKTMAX	60
   { "dintpktidlmax", "", 12 , 1, 0, ARGUSPRINTIDLEDSTINTPKTMAX, ArgusPrintIdleDstIntPktMax, ArgusPrintIdleDstIntPktMaxLabel, "double"},
#define ARGUSPRINTIDLEDSTINTPKTMIN	61
   { "dintpktidlmin", "", 12 , 1, 0, ARGUSPRINTIDLEDSTINTPKTMIN, ArgusPrintIdleDstIntPktMin, ArgusPrintIdleDstIntPktMinLabel, "double"},
#define ARGUSPRINTSPACER		62
   { "xxx", "", 12 , 1, 0, ARGUSPRINTSPACER, NULL, NULL, "varchar(3)"},
#define ARGUSPRINTSRCJITTER		63
   { "sjit", "", 12 , 1, 0, ARGUSPRINTSRCJITTER, ArgusPrintSrcJitter, ArgusPrintSrcJitterLabel, "double"},
#define ARGUSPRINTDSTJITTER		64
   { "djit", "", 12 , 1, 0, ARGUSPRINTDSTJITTER, ArgusPrintDstJitter, ArgusPrintDstJitterLabel, "double"},
#define ARGUSPRINTACTSRCJITTER		65
   { "sjitact", "", 12 , 1, 0, ARGUSPRINTACTSRCJITTER, ArgusPrintActiveSrcJitter, ArgusPrintActiveSrcJitterLabel, "double"},
#define ARGUSPRINTACTDSTJITTER		66
   { "djitact", "", 12 , 1, 0, ARGUSPRINTACTDSTJITTER, ArgusPrintActiveDstJitter, ArgusPrintActiveDstJitterLabel, "double"},
#define ARGUSPRINTIDLESRCJITTER		67
   { "sjitidl", "", 12 , 1, 0, ARGUSPRINTIDLESRCJITTER, ArgusPrintIdleSrcJitter, ArgusPrintIdleSrcJitterLabel, "double"},
#define ARGUSPRINTIDLEDSTJITTER		68
   { "djitidl", "", 12 , 1, 0, ARGUSPRINTIDLEDSTJITTER, ArgusPrintIdleDstJitter, ArgusPrintIdleDstJitterLabel, "double"},
#define ARGUSPRINTSTATE			69
   { "state", "", 5 , 1, 0, ARGUSPRINTSTATE, ArgusPrintState, ArgusPrintStateLabel, "varchar(32)"},
#define ARGUSPRINTDELTADURATION		70
   { "dldur", "", 12 , 1, 0, ARGUSPRINTDELTADURATION, ArgusPrintDeltaDuration, ArgusPrintDeltaDurationLabel, "double"},
#define ARGUSPRINTDELTASTARTTIME	71
   { "dlstime", "", 12 , 1, 0, ARGUSPRINTDELTASTARTTIME, ArgusPrintDeltaStartTime, ArgusPrintDeltaStartTimeLabel, "double(18,6)"},
#define ARGUSPRINTDELTALASTTIME		72
   { "dlltime", "", 12 , 1, 0, ARGUSPRINTDELTALASTTIME, ArgusPrintDeltaLastTime, ArgusPrintDeltaLastTimeLabel, "double(18,6)"},
#define ARGUSPRINTDELTASPKTS		73
   { "dlspkt", "", 6 , 1, 0, ARGUSPRINTDELTASPKTS, ArgusPrintDeltaSrcPkts, ArgusPrintDeltaSrcPktsLabel, "int"},
#define ARGUSPRINTDELTADPKTS		74
   { "dldpkt", "", 6 , 1, 0, ARGUSPRINTDELTADPKTS, ArgusPrintDeltaDstPkts, ArgusPrintDeltaDstPktsLabel, "int"},
#define ARGUSPRINTDELTASRCPKTS		75
   { "dspkts", "", 12 , 1, 0, ARGUSPRINTDELTASRCPKTS, ArgusPrintDeltaSrcPkts, ArgusPrintDeltaSrcPktsLabel, "int"},
#define ARGUSPRINTDELTADSTPKTS		76
   { "ddpkts", "", 12 , 1, 0, ARGUSPRINTDELTADSTPKTS, ArgusPrintDeltaDstPkts, ArgusPrintDeltaDstPktsLabel, "int"},
#define ARGUSPRINTDELTASRCBYTES		77
   { "dsbytes", "", 12 , 1, 0, ARGUSPRINTDELTASRCBYTES, ArgusPrintDeltaSrcBytes, ArgusPrintDeltaSrcBytesLabel, "int"},
#define ARGUSPRINTDELTADSTBYTES		78
   { "ddbytes", "", 12 , 1, 0, ARGUSPRINTDELTADSTBYTES, ArgusPrintDeltaDstBytes, ArgusPrintDeltaDstBytesLabel, "int"},
#define ARGUSPRINTPERCENTDELTASRCPKTS	79
   { "pdspkts", "", 12 , 1, 0, ARGUSPRINTPERCENTDELTASRCPKTS, ArgusPrintPercentDeltaSrcPkts, ArgusPrintPercentDeltaSrcPktsLabel, "double"},
#define ARGUSPRINTPERCENTDELTADSTPKTS	80
   { "pddpkts", "", 12 , 1, 0, ARGUSPRINTPERCENTDELTADSTPKTS, ArgusPrintPercentDeltaDstPkts, ArgusPrintPercentDeltaDstPktsLabel, "double"},
#define ARGUSPRINTPERCENTDELTASRCBYTES	81
   { "pdsbytes", "", 12 , 1, 0, ARGUSPRINTPERCENTDELTASRCBYTES, ArgusPrintPercentDeltaSrcBytes, ArgusPrintPercentDeltaSrcBytesLabel, "double"},
#define ARGUSPRINTPERCENTDELTADSTBYTES	82
   { "pddbytes", "", 12 , 1, 0, ARGUSPRINTPERCENTDELTADSTBYTES, ArgusPrintPercentDeltaDstBytes, ArgusPrintPercentDeltaDstBytesLabel, "double"},
#define ARGUSPRINTSRCUSERDATA		83
   { "suser", "", 16 , 1, 0, ARGUSPRINTSRCUSERDATA, ArgusPrintSrcUserData, ArgusPrintSrcUserDataLabel, "varbinary(2048)"},
#define ARGUSPRINTDSTUSERDATA		84
   { "duser", "", 16 , 1, 0, ARGUSPRINTDSTUSERDATA, ArgusPrintDstUserData, ArgusPrintDstUserDataLabel, "varbinary(2048)"},
#define ARGUSPRINTTCPEXTENSIONS		85
   { "tcpext", "", 12 , 1, 0, ARGUSPRINTTCPEXTENSIONS, ArgusPrintTCPExtensions, ArgusPrintTCPExtensionsLabel, "varchar(64)"},
#define ARGUSPRINTSRCWINDOW		86
   { "swin", "", 6 , 1, 0, ARGUSPRINTSRCWINDOW, ArgusPrintSrcWindow, ArgusPrintSrcWindowLabel, "tinyint unsigned"},
#define ARGUSPRINTDSTWINDOW		87
   { "dwin", "", 6 , 1, 0, ARGUSPRINTDSTWINDOW, ArgusPrintDstWindow, ArgusPrintDstWindowLabel, "tinyint unsigned"},
#define ARGUSPRINTJOINDELAY		88
   { "jdelay", "", 12 , 1, 0, ARGUSPRINTJOINDELAY, ArgusPrintJoinDelay, ArgusPrintJoinDelayLabel, "double"},
#define ARGUSPRINTLEAVEDELAY		89
   { "ldelay", "", 12 , 1, 0, ARGUSPRINTLEAVEDELAY, ArgusPrintLeaveDelay, ArgusPrintLeaveDelayLabel, "double"},
#define ARGUSPRINTSEQUENCENUMBER	90
   { "seq", "", 12 , 1, 0, ARGUSPRINTSEQUENCENUMBER, ArgusPrintSequenceNumber, ArgusPrintSequenceNumberLabel, "int unsigned"},
#define ARGUSPRINTBINS			91
   { "bins", "", 6 , 1, 0, ARGUSPRINTBINS, ArgusPrintBins, ArgusPrintBinsLabel, "int unsigned"},
#define ARGUSPRINTBINNUMBER		92
   { "binnum", "", 6 , 1, 0, ARGUSPRINTBINNUMBER, ArgusPrintBinNumber, ArgusPrintBinNumberLabel, "int unsigned"},
#define ARGUSPRINTSRCMPLS		93
   { "smpls", "", 8 , 1, 0, ARGUSPRINTSRCMPLS, ArgusPrintSrcMpls, ArgusPrintSrcMplsLabel, "int unsigned"},
#define ARGUSPRINTDSTMPLS		94
   { "dmpls", "", 8 , 1, 0, ARGUSPRINTDSTMPLS, ArgusPrintDstMpls, ArgusPrintDstMplsLabel, "int unsigned"},
#define ARGUSPRINTSRCVLAN		95
   { "svlan", "", 8 , 1, 0, ARGUSPRINTSRCVLAN, ArgusPrintSrcVlan, ArgusPrintSrcVlanLabel, "smallint unsigned"},
#define ARGUSPRINTDSTVLAN		96
   { "dvlan", "", 8 , 1, 0, ARGUSPRINTDSTVLAN, ArgusPrintDstVlan, ArgusPrintDstVlanLabel, "smallint unsigned"},
#define ARGUSPRINTSRCVID		97
   { "svid", "", 6 , 1, 0, ARGUSPRINTSRCVID, ArgusPrintSrcVID, ArgusPrintSrcVIDLabel, "smallint unsigned"},
#define ARGUSPRINTDSTVID		98
   { "dvid", "", 6 , 1, 0, ARGUSPRINTDSTVID, ArgusPrintDstVID, ArgusPrintDstVIDLabel, "smallint unsigned"},
#define ARGUSPRINTSRCVPRI		99
   { "svpri", "", 6 , 1, 0, ARGUSPRINTSRCVPRI, ArgusPrintSrcVPRI, ArgusPrintSrcVPRILabel, "smallint unsigned"},
#define ARGUSPRINTDSTVPRI		100
   { "dvpri", "", 6 , 1, 0, ARGUSPRINTDSTVPRI, ArgusPrintDstVPRI, ArgusPrintDstVPRILabel, "smallint unsigned"},
#define ARGUSPRINTSRCIPID		101
   { "sipid", "", 7 , 1, 0, ARGUSPRINTSRCIPID, ArgusPrintSrcIpId, ArgusPrintSrcIpIdLabel, "smallint unsigned"},
#define ARGUSPRINTDSTIPID		102
   { "dipid", "", 7 , 1, 0, ARGUSPRINTDSTIPID, ArgusPrintDstIpId, ArgusPrintDstIpIdLabel, "smallint unsigned"},
#define ARGUSPRINTSTARTRANGE		103
   { "srng", "", 6 , 1, 0, ARGUSPRINTSTARTRANGE, ArgusPrintStartRange, ArgusPrintStartRangeLabel, "int unsigned"},
#define ARGUSPRINTENDRANGE		104
   { "erng", "", 6 , 1, 0, ARGUSPRINTENDRANGE, ArgusPrintEndRange, ArgusPrintEndRangeLabel, "int unsigned"},
#define ARGUSPRINTTCPSRCBASE		105
   { "stcpb", "", 12 , 1, 0, ARGUSPRINTTCPSRCBASE, ArgusPrintTCPSrcBase, ArgusPrintTCPSrcBaseLabel, "int unsigned"},
#define ARGUSPRINTTCPDSTBASE		106
   { "dtcpb", "", 12 , 1, 0, ARGUSPRINTTCPDSTBASE, ArgusPrintTCPDstBase, ArgusPrintTCPDstBaseLabel, "int unsigned"},
#define ARGUSPRINTTCPRTT		107
   { "tcprtt", "", 12 , 1, 0, ARGUSPRINTTCPRTT, ArgusPrintTCPRTT, ArgusPrintTCPRTTLabel, "double"},
#define ARGUSPRINTINODE   		108
   { "inode", "", 18, 1, 0, ARGUSPRINTINODE, ArgusPrintInode, ArgusPrintInodeLabel, "varchar(64)"},
#define ARGUSPRINTSTDDEV  		109
   { "stddev", "", 10 , 1, 0, ARGUSPRINTSTDDEV, ArgusPrintStdDeviation, ArgusPrintStdDeviationLabel, "double unsigned"},
#define ARGUSPRINTRELDATE		110
   { "rtime", "", 12 , 1, 0, ARGUSPRINTRELDATE, ArgusPrintRelativeDate, ArgusPrintRelativeDateLabel, "double(18,6)"},
#define ARGUSPRINTBYTEOFFSET		111
   { "offset", "", 12 , 1, 0, ARGUSPRINTBYTEOFFSET, ArgusPrintByteOffset, ArgusPrintByteOffsetLabel, "bigint"},
#define ARGUSPRINTSRCNET		112
   { "snet", "", 18 , 1, 0, ARGUSPRINTSRCNET, ArgusPrintSrcNet, ArgusPrintSrcNetLabel, "varchar(64)"},
#define ARGUSPRINTDSTNET		113
   { "dnet", "", 18 , 1, 0, ARGUSPRINTDSTNET, ArgusPrintDstNet, ArgusPrintDstNetLabel, "varchar(64)"},
#define ARGUSPRINTSRCDURATION		114
   { "sdur", "", 10 , 1, 0, ARGUSPRINTSRCDURATION, ArgusPrintSrcDuration, ArgusPrintSrcDurationLabel, "double"},
#define ARGUSPRINTDSTDURATION		115
   { "ddur", "", 10 , 1, 0, ARGUSPRINTDSTDURATION, ArgusPrintDstDuration, ArgusPrintDstDurationLabel, "double"},
#define ARGUSPRINTTCPSRCMAX		116
   { "stcpmax", "", 10 , 1, 0, ARGUSPRINTTCPSRCMAX, ArgusPrintTCPSrcMax, ArgusPrintTCPSrcMaxLabel, "double"},
#define ARGUSPRINTTCPDSTMAX		117
   { "dtcpmax", "", 10 , 1, 0, ARGUSPRINTTCPDSTMAX, ArgusPrintTCPDstMax, ArgusPrintTCPDstMaxLabel, "double"},
#define ARGUSPRINTTCPSYNACK		118
   { "synack", "", 12 , 1, 0, ARGUSPRINTTCPSYNACK, ArgusPrintTCPSynAck, ArgusPrintTCPSynAckLabel, "double"},
#define ARGUSPRINTTCPACKDAT		119
   { "ackdat", "", 12 , 1, 0, ARGUSPRINTTCPACKDAT, ArgusPrintTCPAckDat, ArgusPrintTCPAckDatLabel, "double"},
#define ARGUSPRINTSRCSTARTDATE		120
   { "sstime", "%T.%f", 12 , 1, 0, ARGUSPRINTSRCSTARTDATE, ArgusPrintSrcStartDate, ArgusPrintSrcStartDateLabel, "double(18,6) unsigned not null"},
#define ARGUSPRINTSRCLASTDATE		121
   { "sltime", "%T.%f", 12 , 1, 0, ARGUSPRINTSRCLASTDATE, ArgusPrintSrcLastDate, ArgusPrintSrcLastDateLabel, "double(18,6) unsigned not null"},
#define ARGUSPRINTDSTSTARTDATE		122
   { "dstime", "%T.%f", 12 , 1, 0, ARGUSPRINTDSTSTARTDATE, ArgusPrintDstStartDate, ArgusPrintDstStartDateLabel, "double(18,6) unsigned not null"},
#define ARGUSPRINTDSTLASTDATE		123
   { "dltime", "%T.%f", 12 , 1, 0, ARGUSPRINTDSTLASTDATE, ArgusPrintDstLastDate, ArgusPrintDstLastDateLabel, "double(18,6) unsigned not null"},
#define ARGUSPRINTSRCENCAPS		124
   { "senc", "", 12 , 1, 0, ARGUSPRINTSRCENCAPS, ArgusPrintSrcEncaps, ArgusPrintSrcEncapsLabel, "varchar(32)"},
#define ARGUSPRINTDSTENCAPS		125
   { "denc", "", 12 , 1, 0, ARGUSPRINTDSTENCAPS, ArgusPrintDstEncaps, ArgusPrintDstEncapsLabel, "varchar(32)"},
#define ARGUSPRINTSRCPKTSIZE		126
   { "spktsz", "", 12 , 1, 0, ARGUSPRINTSRCPKTSIZE, ArgusPrintSrcPktSize, ArgusPrintSrcPktSizeLabel, "varchar(32)"},
#define ARGUSPRINTSRCMAXPKTSIZE		127
   { "smaxsz", "", 12 , 1, 0, ARGUSPRINTSRCMAXPKTSIZE, ArgusPrintSrcMaxPktSize, ArgusPrintSrcMaxPktSizeLabel, "smallint unsigned"},
#define ARGUSPRINTSRCMINPKTSIZE		128
   { "sminsz", "", 12 , 1, 0, ARGUSPRINTSRCMINPKTSIZE, ArgusPrintSrcMinPktSize, ArgusPrintSrcMinPktSizeLabel, "smallint unsigned"},
#define ARGUSPRINTDSTPKTSIZE		129
   { "dpktsz", "", 12 , 1, 0, ARGUSPRINTDSTPKTSIZE, ArgusPrintDstPktSize, ArgusPrintDstPktSizeLabel, "varchar(32)"},
#define ARGUSPRINTDSTMAXPKTSIZE		130
   { "dmaxsz", "", 12 , 1, 0, ARGUSPRINTDSTMAXPKTSIZE, ArgusPrintDstMaxPktSize, ArgusPrintDstMaxPktSizeLabel, "smallint unsigned"},
#define ARGUSPRINTDSTMINPKTSIZE		131
   { "dminsz", "", 12 , 1, 0, ARGUSPRINTDSTMINPKTSIZE, ArgusPrintDstMinPktSize, ArgusPrintDstMinPktSizeLabel, "smallint unsigned"},
#define ARGUSPRINTSRCCOUNTRYCODE	132
   { "sco", "", 3 , 1, 0, ARGUSPRINTSRCCOUNTRYCODE, ArgusPrintSrcCountryCode, ArgusPrintSrcCountryCodeLabel, "varchar(2)"},
#define ARGUSPRINTDSTCOUNTRYCODE	133
   { "dco", "", 3 , 1, 0, ARGUSPRINTDSTCOUNTRYCODE, ArgusPrintDstCountryCode, ArgusPrintDstCountryCodeLabel, "varchar(2)"},
#define ARGUSPRINTSRCHOPCOUNT		134
   { "shops", "", 5 , 1, 0, ARGUSPRINTSRCHOPCOUNT, ArgusPrintSrcHopCount, ArgusPrintSrcHopCountLabel, "smallint"},
#define ARGUSPRINTDSTHOPCOUNT		135
   { "dhops", "", 5 , 1, 0, ARGUSPRINTDSTHOPCOUNT, ArgusPrintDstHopCount, ArgusPrintDstHopCountLabel, "smallint"},
#define ARGUSPRINTICMPID		136
   { "icmpid", "", 6 , 1, 0, ARGUSPRINTICMPID, ArgusPrintIcmpId, ArgusPrintIcmpIdLabel, "smallint unsigned"},
#define ARGUSPRINTLABEL			137
   { "label", "", 5 , 1, 0, ARGUSPRINTLABEL, ArgusPrintLabel, ArgusPrintLabelLabel, "varchar(4098)"},
#define ARGUSPRINTSRCINTPKTDIST		138
   { "sintdist", "", 8, 1, 0, ARGUSPRINTSRCINTPKTDIST, ArgusPrintSrcIntPktDist, ArgusPrintSrcIntPktDistLabel, "varchar(8)"},
#define ARGUSPRINTDSTINTPKTDIST		139
   { "dintdist", "", 8, 1, 0, ARGUSPRINTDSTINTPKTDIST, ArgusPrintDstIntPktDist, ArgusPrintDstIntPktDistLabel, "varchar(8)"},
#define ARGUSPRINTACTSRCINTPKTDIST	140
   { "sintdistact", "", 11, 1, 0, ARGUSPRINTACTSRCINTPKTDIST, ArgusPrintActiveSrcIntPktDist, ArgusPrintActiveSrcIntPktDistLabel, "varchar(8)"},
#define ARGUSPRINTACTDSTINTPKTDIST	141
   { "dintdistact", "", 11, 1, 0, ARGUSPRINTACTDSTINTPKTDIST, ArgusPrintActiveDstIntPktDist, ArgusPrintActiveDstIntPktDistLabel, "varchar(8)"},
#define ARGUSPRINTIDLESRCINTPKTDIST	142
   { "sintdistidl", "", 11, 1, 0, ARGUSPRINTIDLESRCINTPKTDIST, ArgusPrintIdleSrcIntPktDist, ArgusPrintIdleSrcIntPktDistLabel, "varchar(8)"},
#define ARGUSPRINTIDLEDSTINTPKTDIST	143
   { "dintdistidl", "", 11, 1, 0, ARGUSPRINTIDLEDSTINTPKTDIST, ArgusPrintIdleDstIntPktDist, ArgusPrintIdleDstIntPktDistLabel, "varchar(8)"},
#define ARGUSPRINTRETRANS          	144
   { "retrans", "", 7, 1, 0, ARGUSPRINTRETRANS, ArgusPrintRetrans, ArgusPrintRetransLabel, "int"},
#define ARGUSPRINTSRCRETRANS          	145
   { "sretrans", "", 8, 1, 0, ARGUSPRINTSRCRETRANS, ArgusPrintSrcRetrans, ArgusPrintSrcRetransLabel, "int"},
#define ARGUSPRINTDSTRETRANS          	146
   { "dretrans", "", 8, 1, 0, ARGUSPRINTDSTRETRANS, ArgusPrintDstRetrans, ArgusPrintDstRetransLabel, "int"},
#define ARGUSPRINTPERCENTRETRANS        147
   { "pretrans", "", 7, 1, 0, ARGUSPRINTPERCENTRETRANS, ArgusPrintPercentRetrans, ArgusPrintPercentRetransLabel, "double"},
#define ARGUSPRINTPERCENTSRCRETRANS     148
   { "spretrans", "", 8, 1, 0, ARGUSPRINTPERCENTSRCRETRANS, ArgusPrintPercentSrcRetrans, ArgusPrintPercentSrcRetransLabel, "double"},
#define ARGUSPRINTPERCENTDSTRETRANS     149
   { "dpretrans", "", 8, 1, 0, ARGUSPRINTPERCENTDSTRETRANS, ArgusPrintPercentDstRetrans, ArgusPrintPercentDstRetransLabel, "double"},
#define ARGUSPRINTNACKS          	150
   { "nacks", "", 7, 1, 0, ARGUSPRINTNACKS, ArgusPrintNacks, ArgusPrintNacksLabel, "int"},
#define ARGUSPRINTSRCNACKS          	151
   { "snacks", "", 8, 1, 0, ARGUSPRINTSRCNACKS, ArgusPrintSrcNacks, ArgusPrintSrcNacksLabel, "int"},
#define ARGUSPRINTDSTNACKS          	152
   { "dnacks", "", 8, 1, 0, ARGUSPRINTDSTNACKS, ArgusPrintDstNacks, ArgusPrintDstNacksLabel, "int"},
#define ARGUSPRINTPERCENTNACKS		153
   { "pnacks", "", 7, 1, 0, ARGUSPRINTPERCENTNACKS, ArgusPrintPercentNacks, ArgusPrintPercentNacksLabel, "double"},
#define ARGUSPRINTPERCENTSRCNACKS	154
   { "spnacks", "", 8, 1, 0, ARGUSPRINTPERCENTSRCNACKS, ArgusPrintPercentSrcNacks, ArgusPrintPercentSrcNacksLabel, "double"},
#define ARGUSPRINTPERCENTDSTNACKS	155
   { "dpnacks", "", 8, 1, 0, ARGUSPRINTPERCENTDSTNACKS, ArgusPrintPercentDstNacks, ArgusPrintPercentDstNacksLabel, "double"},
#define ARGUSPRINTSOLO          	156
   { "solo", "", 7, 1, 0, ARGUSPRINTSOLO, ArgusPrintSolo, ArgusPrintSoloLabel, "int"},
#define ARGUSPRINTSRCSOLO          	157
   { "ssolo", "", 8, 1, 0, ARGUSPRINTSRCSOLO, ArgusPrintSrcSolo, ArgusPrintSrcSoloLabel, "int"},
#define ARGUSPRINTDSTSOLO          	158
   { "dsolo", "", 8, 1, 0, ARGUSPRINTDSTSOLO, ArgusPrintDstSolo, ArgusPrintDstSoloLabel, "int"},
#define ARGUSPRINTPERCENTSOLO		159
   { "psolo", "", 7, 1, 0, ARGUSPRINTPERCENTSOLO, ArgusPrintPercentSolo, ArgusPrintPercentSoloLabel, "double"},
#define ARGUSPRINTPERCENTSRCSOLO	160
   { "spsolo", "", 8, 1, 0, ARGUSPRINTPERCENTSRCSOLO, ArgusPrintPercentSrcSolo, ArgusPrintPercentSrcSoloLabel, "double"},
#define ARGUSPRINTPERCENTDSTSOLO	161
   { "dpsolo", "", 8, 1, 0, ARGUSPRINTPERCENTDSTSOLO, ArgusPrintPercentDstSolo, ArgusPrintPercentDstSoloLabel, "double"},
#define ARGUSPRINTFIRST          	162
   { "first", "", 7, 1, 0, ARGUSPRINTFIRST, ArgusPrintFirst, ArgusPrintFirstLabel, "int"},
#define ARGUSPRINTSRCFIRST          	163
   { "sfirst", "", 8, 1, 0, ARGUSPRINTSRCFIRST, ArgusPrintSrcFirst, ArgusPrintSrcFirstLabel, "int"},
#define ARGUSPRINTDSTFIRST          	164
   { "dfirst", "", 8, 1, 0, ARGUSPRINTDSTFIRST, ArgusPrintDstFirst, ArgusPrintDstFirstLabel, "int"},
#define ARGUSPRINTPERCENTFIRST		165
   { "pfirst", "", 7, 1, 0, ARGUSPRINTPERCENTFIRST, ArgusPrintPercentFirst, ArgusPrintPercentFirstLabel, "double"},
#define ARGUSPRINTPERCENTSRCFIRST	166
   { "spfirst", "", 8, 1, 0, ARGUSPRINTPERCENTSRCFIRST, ArgusPrintPercentSrcFirst, ArgusPrintPercentSrcFirstLabel, "double"},
#define ARGUSPRINTPERCENTDSTFIRST	167
   { "dpfirst", "", 8, 1, 0, ARGUSPRINTPERCENTDSTFIRST, ArgusPrintPercentDstFirst, ArgusPrintPercentDstFirstLabel, "double"},
#define ARGUSPRINTAUTOID		168
   { "autoid", "", 6, 1, 0, ARGUSPRINTAUTOID, ArgusPrintAutoId, ArgusPrintAutoIdLabel, "int not null auto_increment"},
#define ARGUSPRINTSRCASN		169
   { "sas", "", 5 , 1, 0, ARGUSPRINTSRCASN, ArgusPrintSrcAsn, ArgusPrintSrcAsnLabel, "int unsigned"},
#define ARGUSPRINTDSTASN		170
   { "das", "", 5 , 1, 0, ARGUSPRINTDSTASN, ArgusPrintDstAsn, ArgusPrintDstAsnLabel, "int unsigned"},
#define ARGUSPRINTINODEASN		171
   { "ias", "", 5 , 1, 0, ARGUSPRINTINODEASN, ArgusPrintInodeAsn, ArgusPrintInodeAsnLabel, "int unsigned"},
#define ARGUSPRINTCAUSE			172
   { "cause", "", 7 , 1, 0, ARGUSPRINTCAUSE, ArgusPrintCause, ArgusPrintCauseLabel, "varchar(8)"},
};


#define IPPROTOSTR              256

char *ip_proto_string [IPPROTOSTR] = {"ip", "icmp", "igmp", "ggp",
   "ipnip", "st2", "tcp", "cbt", "egp", "igp", "bbn-rcc", "nvp",
   "pup", "argus", "emcon", "xnet", "chaos", "udp", "mux", "dcn",
   "hmp", "prm", "xns-idp", "trunk-1", "trunk-2", "leaf-1", "leaf-2",
   "rdp", "irtp", "iso-tp4", "netblt", "mfe-nsp", "merit-inp", "sep",
   "3pc", "idpr", "xtp", "ddp", "idpr-cmtp", "tp++", "il", "ipv6",
   "sdrp", "ipv6-route", "ipv6-frag", "idrp", "rsvp", "gre", "mhrp", "bna",
   "esp", "ah", "i-nlsp", "swipe", "narp", "mobile", "tlsp", "skip",
   "ipv6-icmp", "ipv6-no", "ipv6-opts", "any", "cftp", "any", "sat-expak", "kryptolan",
   "rvd", "ippc", "any", "sat-mon", "visa", "ipcv", "cpnx", "cphb", "wsn",
   "pvp", "br-sat-mon", "sun-nd", "wb-mon", "wb-expak", "iso-ip", "vmtp",
   "secure-vmtp", "vines", "ttp", "nsfnet-igp", "dgp", "tcf", "eigrp",
   "ospf", "sprite-rpc", "larp", "mtp", "ax.25", "ipip", "micp",
   "aes-sp3-d", "etherip", "encap", "pri-enc", "gmtp", "ifmp", "pnni",
   "pim", "aris", "scps", "qnx", "a/n", "ipcomp", "snp", "compaq-peer",
   "ipx-n-ip", "vrrp", "pgm", "zero", "l2tp", "ddx", "iatp", "stp", "srp",
   "uti", "smp", "sm", "ptp", "isis", "fire", "crtp", "crudp", "sccopmce", "iplt",
   "sps", "pipe", "sctp", "fc", "rsvp", NULL, NULL, NULL, NULL, NULL, NULL,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*141-150*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*151-160*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*161-170*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*171-180*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*181-190*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*191-200*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*201-210*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*211-220*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*221-230*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*231-240*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*241-250*/
   NULL, NULL, "ib", NULL, NULL,                                /*251-255*/
};

char *icmptypestr[ICMP_MAXTYPE + 1] = {
   "ECR", "   ", "   ", "UR" , "SRC", "RED",
   "AHA", "   ", "ECO", "RTA", "RTS", "TXD",
   "PAR", "TST", "TSR", "IRQ", "IRR", "MAS",
   "MSR", "SEC", "ROB", "ROB", "ROB", "ROB",
   "ROB", "ROB", "ROB", "ROB", "ROB", "ROB",
   "TRC", "DCE", "MHR", "WAY", "IAH", "MRQ",
   "MRP", "DNQ", "DNP", "SKP", "PHO", "NRS",
   "NRA", "NNS", "NNA", "PTB",
};   

struct ArgusTokenStruct llcsap_db[] = {
   { LLCSAP_NULL,   "null" },
   { LLCSAP_8021B_I,   "gsap" },
   { LLCSAP_8021B_G,   "isap" },
   { LLCSAP_SNAPATH,   "snapath" },
   { LLCSAP_IP,      "ipsap" },
   { LLCSAP_SNA1,   "sna1" },
   { LLCSAP_SNA2,   "sna2" },
   { LLCSAP_PROWAYNM,   "p-nm" },
   { LLCSAP_TI,      "ti" },
   { LLCSAP_BPDU,   "stp" },
   { LLCSAP_RS511,   "eia" },
   { LLCSAP_ISO8208,   "x25" },
   { LLCSAP_XNS,   "xns" },
   { LLCSAP_NESTAR,   "nestar" },
   { LLCSAP_PROWAYASLM,   "p-aslm" },
   { LLCSAP_ARP,   "arp" },
   { LLCSAP_SNAP,   "snap" },
   { LLCSAP_VINES1,   "vine1" },
   { LLCSAP_VINES2,   "vine2" },
   { LLCSAP_NETWARE,   "netware" },
   { LLCSAP_NETBIOS,   "netbios" },
   { LLCSAP_IBMNM,   "ibmnm" },
   { LLCSAP_RPL1,   "rpl1" },
   { LLCSAP_UB,      "ub" },
   { LLCSAP_RPL2,   "rpl2" },
   { LLCSAP_ISONS,   "clns" },
   { LLCSAP_GLOBAL,   "gbl" },
   { 0,             NULL }
};

void ArgusLoadList(struct ArgusListStruct *, struct ArgusListStruct *);
void ArgusInitServarray(struct ArgusParserStruct *);
void ArgusInitEprotoarray(void);
void ArgusInitProtoidarray(void);
void ArgusInitEtherarray(void);
void ArgusInitLlcsaparray(void);
void ArgusInitAddrtoname(struct ArgusParserStruct *, u_int, u_int);

unsigned int ArgusIndexRecord (struct ArgusRecordStruct *);

void ArgusFree (void *buf);
void *ArgusMalloc (int);
void *ArgusCalloc (int, int);
void *ArgusMallocListRecord (struct ArgusParserStruct *, int);
void ArgusFreeListRecord (struct ArgusParserStruct *, void *buf);
int ArgusParseResourceFile (struct ArgusParserStruct *, char *);
int ArgusParseTimeArg (char **, char **, int, struct tm *);

void ArgusAdjustGlobalTime (struct ArgusParserStruct *parser, struct timeval *now);
void ArgusReverseRecordWithFlag (struct ArgusRecordStruct *, int); 
void ArgusReverseRecord (struct ArgusRecordStruct *); 
void ArgusReverseDataRecord (struct ArgusRecordStruct *); 
void ArgusZeroRecord (struct ArgusRecordStruct *); 
void ArgusZeroRecordWithFlag (struct ArgusRecordStruct *, int); 
struct ArgusRecordStruct *ArgusSubtractRecord (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

struct ArgusQueueStruct *ArgusNewQueue (void);
void ArgusDeleteQueue (struct ArgusQueueStruct *);
int ArgusGetQueueCount(struct ArgusQueueStruct *);
void ArgusPushQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
struct ArgusQueueHeader *ArgusPopQueue (struct ArgusQueueStruct *queue, int);
int ArgusAddToQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
struct ArgusQueueHeader *ArgusRemoveFromQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);

int ArgusConvertInitialWriteStruct (struct WriteStruct *, struct ArgusRecordStruct *);
int ArgusConvertWriteStruct (struct WriteStruct *, struct ArgusRecordStruct *);

struct timeval *RaMinTime (struct timeval *, struct timeval *);
struct timeval *RaMaxTime (struct timeval *, struct timeval *);
struct timeval *RaDiffTime (struct timeval *, struct timeval *);

void ArgusPrintTime(struct ArgusParserStruct *, char *, struct timeval *);
char *ArgusGenerateLabel(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void ArgusPrintRecord (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *ptr, int);
void ArgusDump (const u_char *, int, char *);


char *RaGetUserDataString (struct ArgusRecordStruct *);

int ArgusEncode (struct ArgusParserStruct *, const char *, const char *, int, char *, int);
int ArgusEncode32 (struct ArgusParserStruct *, const char *, int , char *, int );

int ArgusEncode64 (struct ArgusParserStruct *, const char *, int, char *, int);
int ArgusEncodeAscii (struct ArgusParserStruct *, const char *, int, char *, int);

void clearArgusWfile(struct ArgusParserStruct *);
extern unsigned int thisnet, localaddr, localnet, netmask;

void ArgusProcessLabelOptions(struct ArgusParserStruct *, char *);

void (*RaPrintAlgorithms[ARGUS_MAX_PRINT_ALG])(struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int) = {
   ArgusPrintStartDate,
   ArgusPrintFlags,
   ArgusPrintProto,
   ArgusPrintSrcAddr,
   ArgusPrintSrcPort,
   ArgusPrintDir,
   ArgusPrintDstAddr,
   ArgusPrintDstPort,
   ArgusPrintSrcPackets,
   ArgusPrintDstPackets,
   ArgusPrintSrcBytes,
   ArgusPrintDstBytes,
   ArgusPrintState,
   NULL,
};


int argus_nametoeproto(char *);
unsigned int __argus_atoin(char *, unsigned int *);

void ArgusNtoH (struct ArgusRecord *);
void ArgusHtoN (struct ArgusRecord *);

void ArgusV2NtoH (struct ArgusV2Record *);
void ArgusV2HtoN (struct ArgusV2Record *);

#else
#define ARGUSPRINTSTARTDATE		0
#define ARGUSPRINTLASTDATE		1
#define ARGUSPRINTTRANSACTIONS		2
#define ARGUSPRINTDURATION		3
#define ARGUSPRINTAVGDURATION		4
#define ARGUSPRINTMIN			5
#define ARGUSPRINTMAX			6
#define ARGUSPRINTSRCADDR		7
#define ARGUSPRINTDSTADDR		8
#define ARGUSPRINTPROTO			9
#define ARGUSPRINTSRCPORT		10
#define ARGUSPRINTDSTPORT		11
#define ARGUSPRINTSRCTOS		12
#define ARGUSPRINTDSTTOS		13
#define ARGUSPRINTSRCDSBYTE		14
#define ARGUSPRINTDSTDSBYTE		15
#define ARGUSPRINTSRCTTL		16
#define ARGUSPRINTDSTTTL		17
#define ARGUSPRINTBYTES			18
#define ARGUSPRINTSRCBYTES		19
#define ARGUSPRINTDSTBYTES		20
#define ARGUSPRINTAPPBYTES              21
#define ARGUSPRINTSRCAPPBYTES           22
#define ARGUSPRINTDSTAPPBYTES           23
#define ARGUSPRINTPACKETS		24
#define ARGUSPRINTSRCPACKETS		25
#define ARGUSPRINTDSTPACKETS		26
#define ARGUSPRINTLOAD			27
#define ARGUSPRINTSRCLOAD		28
#define ARGUSPRINTDSTLOAD		29
#define ARGUSPRINTLOSS			30
#define ARGUSPRINTSRCLOSS		31
#define ARGUSPRINTDSTLOSS		32
#define ARGUSPRINTPERCENTLOSS		33
#define ARGUSPRINTSRCPERCENTLOSS	34
#define ARGUSPRINTDSTPERCENTLOSS	35
#define ARGUSPRINTRATE			36
#define ARGUSPRINTSRCRATE		37
#define ARGUSPRINTDSTRATE		38
#define ARGUSPRINTSOURCEID		39
#define ARGUSPRINTFLAGS			40
#define ARGUSPRINTSRCMACADDRESS		41
#define ARGUSPRINTDSTMACADDRESS		42
#define ARGUSPRINTDIR			43
#define ARGUSPRINTSRCINTPKT		44
#define ARGUSPRINTDSTINTPKT		45
#define ARGUSPRINTACTSRCINTPKT		46
#define ARGUSPRINTACTDSTINTPKT		47
#define ARGUSPRINTIDLESRCINTPKT		48
#define ARGUSPRINTIDLEDSTINTPKT		49
#define ARGUSPRINTSRCINTPKTMAX		50
#define ARGUSPRINTSRCINTPKTMIN		51
#define ARGUSPRINTDSTINTPKTMAX		52
#define ARGUSPRINTDSTINTPKTMIN		53
#define ARGUSPRINTACTSRCINTPKTMAX	54
#define ARGUSPRINTACTSRCINTPKTMIN	55
#define ARGUSPRINTACTDSTINTPKTMAX	56
#define ARGUSPRINTACTDSTINTPKTMIN	57
#define ARGUSPRINTIDLESRCINTPKTMAX	58
#define ARGUSPRINTIDLESRCINTPKTMIN	59
#define ARGUSPRINTIDLEDSTINTPKTMAX	60
#define ARGUSPRINTIDLEDSTINTPKTMIN	61
#define ARGUSPRINTSPACER		62
#define ARGUSPRINTSRCJITTER		63
#define ARGUSPRINTDSTJITTER		64
#define ARGUSPRINTACTSRCJITTER		65
#define ARGUSPRINTACTDSTJITTER		66
#define ARGUSPRINTIDLESRCJITTER		67
#define ARGUSPRINTIDLEDSTJITTER		68
#define ARGUSPRINTSTATE			69
#define ARGUSPRINTDELTADURATION		70
#define ARGUSPRINTDELTASTARTTIME	71
#define ARGUSPRINTDELTALASTTIME		72
#define ARGUSPRINTDELTASRCPKTS		73
#define ARGUSPRINTDELTADSTPKTS		74
#define ARGUSPRINTDELTASRCBYTES		75
#define ARGUSPRINTDELTADSTBYTES		76
#define ARGUSPRINTPERCENTDELTASRCPKTS	77
#define ARGUSPRINTPERCENTDELTADSTPKTS	78
#define ARGUSPRINTPERCENTDELTASRCBYTES	79
#define ARGUSPRINTPERCENTDELTADSTBYTES	80
#define ARGUSPRINTSRCUSERDATA		81
#define ARGUSPRINTDSTUSERDATA		82
#define ARGUSPRINTTCPEXTENSIONS		83
#define ARGUSPRINTSRCWINDOW		84
#define ARGUSPRINTDSTWINDOW		85
#define ARGUSPRINTJOINDELAY		86
#define ARGUSPRINTLEAVEDELAY		87
#define ARGUSPRINTSEQUENCENUMBER	88
#define ARGUSPRINTBINS			89
#define ARGUSPRINTBINNUMBER		90
#define ARGUSPRINTSRCMPLS		91
#define ARGUSPRINTDSTMPLS		92
#define ARGUSPRINTSRCVLAN		93
#define ARGUSPRINTDSTVLAN		94
#define ARGUSPRINTSRCVID		95
#define ARGUSPRINTDSTVID		96
#define ARGUSPRINTSRCVPRI		97
#define ARGUSPRINTDSTVPRI		98
#define ARGUSPRINTSRCIPID		99
#define ARGUSPRINTDSTIPID		100
#define ARGUSPRINTSTARTRANGE		101
#define ARGUSPRINTENDRANGE		102
#define ARGUSPRINTTCPSRCBASE		103
#define ARGUSPRINTTCPDSTBASE		104
#define ARGUSPRINTTCPRTT		105
#define ARGUSPRINTINODE   		106
#define ARGUSPRINTSTDDEV  		107
#define ARGUSPRINTRELDATE		108
#define ARGUSPRINTBYTEOFFSET		109
#define ARGUSPRINTSRCNET		110
#define ARGUSPRINTDSTNET		111
#define ARGUSPRINTSRCDURATION		112
#define ARGUSPRINTDSTDURATION		113
#define ARGUSPRINTTCPSRCMAX		114
#define ARGUSPRINTTCPDSTMAX		115
#define ARGUSPRINTTCPSYNACK		116
#define ARGUSPRINTTCPACKDAT		117
#define ARGUSPRINTSRCSTARTDATE		118
#define ARGUSPRINTSRCLASTDATE		119
#define ARGUSPRINTDSTSTARTDATE		120
#define ARGUSPRINTDSTLASTDATE		121
#define ARGUSPRINTSRCENCAPS		122
#define ARGUSPRINTDSTENCAPS		123
#define ARGUSPRINTSRCMAXPKTSIZE		124
#define ARGUSPRINTSRCMINPKTSIZE		125
#define ARGUSPRINTDSTMAXPKTSIZE		126
#define ARGUSPRINTDSTMINPKTSIZE		127
#define ARGUSPRINTSRCCOUNTRYCODE	128
#define ARGUSPRINTDSTCOUNTRYCODE	129
#define ARGUSPRINTSRCHOPCOUNT		130
#define ARGUSPRINTDSTHOPCOUNT		131

extern struct ArgusPrintFieldStruct RaPrintAlgorithmTable[MAX_PRINT_ALG_TYPES];
extern void (*RaPrintAlgorithms[ARGUS_MAX_PRINT_ALG])(struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusProcessLabelOptions(struct ArgusParserStruct *, char *);

extern void ArgusLoadList(struct ArgusListStruct *, struct ArgusListStruct *);
extern void ArgusInitServarray(void);
extern void ArgusInitEprotoarray(void);
extern void ArgusInitProtoidarray(void);
extern void ArgusInitEtherarray(void);
extern void ArgusInitLlcsaparray(void);
extern void ArgusInitAddrtoname(struct ArgusParserStruct *, u_int, u_int);

extern char *ip_proto_string [];
extern char *icmptypestr[];

extern unsigned int ArgusIndexRecord (struct ArgusRecordStruct *);

extern void ArgusFree (void *buf);
extern void *ArgusMalloc (int);
extern void *ArgusCalloc (int, int);
extern void *ArgusMallocListRecord (struct ArgusParserStruct *, int);
extern void ArgusFreeListRecord (struct ArgusParserStruct *, void *buf);
extern int ArgusParseResourceFile (struct ArgusParserStruct *, char *);

extern int ArgusParseTimeArg (char **, char **, int, struct tm *);

extern void ArgusAdjustGlobalTime (struct ArgusParserStruct *parser, struct timeval *now);
extern void ArgusReverseRecordWithFlag (struct ArgusRecordStruct *, int);
extern void ArgusReverseRecord (struct ArgusRecordStruct *); 
extern void ArgusReverseDataRecord (struct ArgusRecordStruct *); 
extern void ArgusZeroRecord (struct ArgusRecordStruct *);  
extern void ArgusZeroRecordWithFlag (struct ArgusRecordStruct *, int); 
extern struct ArgusRecordStruct *ArgusSubtractRecord (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

extern struct ArgusQueueStruct *ArgusNewQueue (void);
extern void ArgusDeleteQueue (struct ArgusQueueStruct *);
extern int ArgusGetQueueCount(struct ArgusQueueStruct *);
extern void ArgusPushQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
extern struct ArgusQueueHeader *ArgusPopQueue (struct ArgusQueueStruct *queue, int);
extern int ArgusAddToQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
extern struct ArgusQueueHeader *ArgusRemoveFromQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);

extern int ArgusConvertInitialWriteStruct (struct WriteStruct *, struct ArgusRecordStruct *);
extern int ArgusConvertWriteStruct (struct WriteStruct *, struct ArgusRecordStruct *);

extern struct timeval *RaMinTime (struct timeval *, struct timeval *);
extern struct timeval *RaMaxTime (struct timeval *, struct timeval *);
extern struct timeval *RaDiffTime (struct timeval *, struct timeval *);

extern void ArgusPrintTime(struct ArgusParserStruct *, char *, struct timeval *);
extern char *ArgusGenerateLabel(struct ArgusParserStruct *, struct ArgusRecordStruct *);

extern void ArgusPrintRecord (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *ptr, int);
extern void ArgusDump (const u_char *, int, char *);

extern void ArgusMainInit (struct ArgusParserStruct *, int, char **);

extern void ArgusPrintCause (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int, int);
extern void ArgusPrintDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int, int);
extern void ArgusPrintStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSourceID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintFlags (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintProto (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintAddr (struct ArgusParserStruct *, char *, int, void *, int, int, int);
extern void ArgusPrintSrcNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int, unsigned char, unsigned int, int, int);
extern void ArgusPrintSrcPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDir (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintState (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaStartTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaLastTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaSrcPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaDstPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPercentDeltaSrcPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPercentDeltaDstPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPercentDeltaSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPercentDeltaDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcUserData (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstUserData (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintTCPExtensions (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPercentLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintSrcTos (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstTos (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintSrcDSByte (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstDSByte (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcIpId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIpId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintSrcTtl (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstTtl (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintSrcVlan (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstVlan (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintSrcVID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstVID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintSrcVPRI (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstVPRI (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintSrcMpls (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstMpls (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);


extern void ArgusPrintSrcWindow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstWindow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintJoinDelay (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLeaveDelay (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintMean (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintStartRange (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintEndRange (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTransactions (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSequenceNumber (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintBinNumber (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintBins (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPSrcBase (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPDstBase (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPRTT (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPSrcMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPDstMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintInode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintStdDeviation (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintCauseLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintStartDateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintLastDateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSourceIDLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintFlagsLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcMacAddressLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstMacAddressLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintProtoLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcAddrLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintDstAddrLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcPortLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstPortLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcIpIdLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstIpIdLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcTtlLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstTtlLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintDirLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPacketsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcPacketsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstPacketsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintAppBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcAppBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstAppBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcIntPktDistLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstIntPktDistLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcIntPktMinLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIntPktMaxLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIntPktMinLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveSrcIntPktLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveSrcIntPktDistLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveSrcIntPktMinLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveDstIntPktMaxLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveDstIntPktMinLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPktLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPktDistLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPktMinLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleDstIntPktMaxLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleDstIntPktMinLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintJitterLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcJitterLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstJitterLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintStateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaDurationLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaStartTimeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaLastTimeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaSrcPktsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaDstPktsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaSrcBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaDstBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPercentDeltaSrcPktsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPercentDeltaDstPktsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPercentDeltaSrcBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPercentDeltaDstBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcUserDataLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstUserDataLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintTCPExtensionsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcLoadLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstLoadLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcLoadLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstLoadLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintLoadLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcLossLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstLossLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintLossLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPercentLossLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcRateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstRateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintRateLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcTosLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstTosLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcDSByteLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstDSByteLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcVlanLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstVlanLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcVIDLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstVIDLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcVPRILabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstVPRILabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcMplsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstMplsLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintWindowLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcWindowLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstWindowLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintJoinDelayLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintLeaveDelayLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintMeanLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintStartRangeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintEndRangeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcDurationLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcDurationLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDurationLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTransactionsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSequenceNumberLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintBinNumberLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintBinsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPSrcBaseLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPDstBaseLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPRTTLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPSrcMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPDstMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintInodeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintMinLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintStdDeviationLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintAutoId (struct ArgusParserStruct *, char *, int);

extern char *RaGetUserDataString (struct ArgusRecordStruct *);

extern int ArgusEncode (struct ArgusParserStruct *, const char *, const char *, int, char *, int);
extern int ArgusEncode32 (struct ArgusParserStruct *, const char *, int , char *, int );
extern int ArgusEncode64 (const char *, int, char *, int);
extern int ArgusEncodeAscii (const char *, int, char *, int);

extern int argus_nametoeproto(char *);
extern unsigned int __argus_atoin(char *, unsigned int *);


extern void ArgusNtoH (struct ArgusRecord *);
extern void ArgusHtoN (struct ArgusRecord *);

extern void ArgusV2NtoH (struct ArgusV2Record *);
extern void ArgusV2HtoN (struct ArgusV2Record *);

#endif 
#endif /* ArgusUtil_h */
