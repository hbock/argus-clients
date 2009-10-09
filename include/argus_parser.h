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
 * $Id: //depot/argus/argus-3.0/clients/include/argus_parser.h#49 $
 * $DateTime: 2006/05/25 02:07:01 $
 * $Change: 858 $
 */


#ifndef ArgusParser_h
#define ArgusParser_h

#include <regex.h>

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>

#include <net/nff.h>

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif

#define ARGUS_RECORD_WRITTEN	0x0001

#define ARGUS_PRINTGMT		0x0020
#define ARGUS_PRINTNET		0x0022
 
#define ARGUS_ENCODE_ASCII       0
#define ARGUS_ENCODE_64          1
#define ARGUS_ENCODE_32          2
#define ARGUS_HEXDUMP            3

#define ARGUS_MAX_S_OPTIONS      134

#define RA_PRINTPROTO		1
#define RA_PRINTSRCID		2
 
#define RAMON_TOPN		1
#define RAMON_MATRIX		2
#define RAMON_SVCS		3
#define RAMON_SINGLE		4

#define RA_FIXED_WIDTH		1
#define RA_VARIABLE_WIDTH	2

#define RA_SINGLE_QUOTED	'\''
#define RA_DOUBLE_QUOTED	'\"'

#define ARGUS_MAX_REMOTE		256

#define RABINS_HASHTABLESIZE	0x100


/* the ArgusRecordStruct (ns) is a single point data structure
   for clients to use to process and report on ARGUS flow data.  
   To support this rather nebulous function, the ns  provides
   a canonical record buffer which supports a completely
   parsed and formatted record (exploded view), and indexes
   to the various sections of the ns structure.

   A queue header struct is supported so that the strucutre
   can be placed in a queue, and there is an hstruct pointer
   provided so that if the record is hashed, the hash entry
   can be found quickly, ie for removal.

   Because ns data is time series data, there is a desire to
   support an array style data structure to provide the
   ability to  maintain some aspects fo the time-series
   qualities.  This struct was enabled in earlier versions
   using the 'H' (histogram) option.  In order to support the
   concept of the Stream Block Processor, however, this data
   structure needs to be embeeded in the ns itself.

   The concept is that the ns itself holds the aggregate
   stats for the time series array.  Each  member is an
   ns, which can further subdivided into additional time series
   structures.  For most applications, this structure will
   be NULL, indicating that subdivision is not being done.

*/

 
struct ArgusHashStruct {
   unsigned int len, hash;
   unsigned int *buf; 
}; 
 
struct ArgusHashTableHdr {
   struct ArgusHashTableHdr *nxt, *prv;
   struct ArgusHashTable *htbl;
   struct ArgusHashStruct hstruct;
   void *object;
};

struct ArgusHashTable {
   unsigned int size, count;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif /* ARGUS_THREADS */
   struct ArgusHashTableHdr **array;
};

struct ArgusAdjustStruct {
   int mode, turns, modify, hard, zero;
   int count, qual, slen, len;

   double stperiod, dtperiod;
   double stduration, dtduration;

   float spkts, sbytes, sappbytes;
   float scpkts, scbytes, scappbytes;
   float dpkts, dbytes, dappbytes;
   float dcpkts, dcbytes, dcappbytes;

   struct timeval start, end;
   struct tm RaStartTmStruct, RaEndTmStruct;

   double value;
   long long startuSecs, size;

   char *filename, *filterstr;
   struct nff_program filter;
};

struct RaBinStruct {
   int status;
   long long value, size;
   struct timeval stime, etime, timeout;
   struct ArgusAggregatorStruct *agg;

   unsigned char ArgusSrcDataMask[16],ArgusDstDataMask[16];
};

struct RaBinProcessStruct {
   int status;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif
   long long start, end, size;
   struct timeval startpt, endpt, rtime;
   int arraylen, len, max, count, index;
   int scalesecs;
   struct RaBinStruct **array;
   struct ArgusAdjustStruct nadp;
};

struct ArgusCorStruct {
   int count, size;
   struct ArgusRecordStruct **array;
};

#define ARGUS_NSR_STICKY		0x00100000
 
struct ArgusRecordStruct {
   struct ArgusQueueHeader qhdr;
   unsigned int status, dsrindex, trans, autoid;
   unsigned short timeout, idle;
   struct RaBinProcessStruct *bins;
   struct ArgusHashTableHdr *htblhdr;
   struct ArgusHashTableHdr *hinthdr;
   struct ArgusQueueStruct *nsq;
   struct ArgusInput *input;
   struct ArgusRecordHeader hdr;
   struct ArgusDSRHeader *dsrs[ARGUSMAXDSRTYPE];
   struct ArgusCorStruct *correlates;
   float srate, drate, sload, dload, dur, mean;
   float sploss, dploss;
   long long offset;
};

struct ArgusRemoteStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusInput *input;

#if defined(ARGUS_THREADS)
   pthread_t tid;
   pthread_mutex_t lock;
#endif
};

struct ArgusCIDRAddr {
   u_char type, len, masklen, pad; 
   u_int addr[4], mask[4];
   char *str;
};


#define ARGUS_MAXTHREADS	128
#define ARGUS_MAX_LISTEN	5

#define ARGUS_REAL_TIME_PROCESS   	0x0100
#define ARGUS_FILE_LIST_PROCESSED	0x1000

struct ArgusParserStruct {
   int status, RaParseCompleting, RaParseDone;
   int RaDonePending, RaShutDown;
   int RaTasksToDo, ArgusReliableConnection;
   int ArgusExitStatus, ArgusPassNum;

   char *ArgusProgramName, *RaTimeFormat, *RaTimeZone;
   char *ArgusProgramArgs, *ArgusProgramOptions;
   char *ArgusSQLStatement;

   struct timeval ArgusRealTime, ArgusGlobalTime;
   struct timeval ArgusStartRealTime, ArgusEndRealTime;
   struct timeval RaClientTimeout, RaClientUpdate;
   struct timeval RaStartTime, RaEndTime;
   struct timeval ArgusStartTimeVal;
   struct timeval ArgusTimeDelta;
   double ArgusTimeMultiplier;

   struct tm RaStartFilter, RaLastFilter;
   struct tm *RaTmStruct;


   struct ArgusAggregatorStruct *ArgusAggregator;
   struct ArgusLabelerStruct *ArgusLabeler;

#if defined(ARGUS_THREADS)
   pthread_t thread;
   pthread_mutex_t lock;
   pthread_cond_t cond;
   pthread_t remote, output, dns;
#endif /* ARGUS_THREADS */

   void *ArgusClientContext;

   int ArgusSessionId, NonBlockingDNS, ArgusDSCodePoints;

   char *ArgusPidFile, *ArgusPidPath;

   struct ArgusRecordStruct *ns;

   struct ArgusOutputStruct *ArgusOutput;
   struct ArgusListStruct *ArgusOutputList, *ArgusInputList;
   struct ArgusListStruct *ArgusNameList;

   struct ArgusQueueStruct *ArgusRemoteHosts, *ArgusActiveHosts;
   struct ArgusQueueStruct *ArgusRemoteList;

   regex_t upreg;
   regex_t lpreg;

   int ArgusRemotes;
   int ArgusReplaceMode;
   int ArgusHostsActive;
   int ArgusLfd[ARGUS_MAX_LISTEN];
   int ArgusListens;
   int ArgusAdjustTime;
   int ArgusConnectTime;
   int ArgusReverse;
   int ArgusPrintMan, ArgusPrintEvent;
   int ArgusPrintXml;
   int RaXMLStarted; 
   int ArgusGrepSource;
   int ArgusGrepDestination;
   int ArgusAutoId;

   int ArgusStripFields;
   int ArgusDSRFields[ARGUSMAXDSRTYPE];

   char *RadiumArchive;
   char *ArgusMatchLabel;

   unsigned int ArgusID, ArgusIDType;

   struct timeval ArgusReportTime;
   struct timeval ArgusUpdateInterval;
   struct timeval ArgusMarReportInterval;
   struct timeval timeout;

   long long ArgusTotalRecords;
   long long ArgusTotalMarRecords;
   long long ArgusTotalFarRecords;
   long long ArgusTotalPkts, ArgusTotalSrcPkts, ArgusTotalDstPkts;
   long long ArgusTotalBytes, ArgusTotalSrcBytes, ArgusTotalDstBytes;

   signed char aflag, Aflag, bflag;
   signed char cflag, Cflag, dflag, Dflag, eflag, Eflag;
   signed char fflag, Fflag, gflag, Gflag, Hflag;
   signed char idflag, jflag, lflag, Lflag, mflag;
   signed char notNetflag, Oflag, pflag, Pflag, qflag, Qflag;
   signed char Netflag, nflag, Normflag, Pctflag, pidflag;

   signed char tflag, uflag, Wflag, vflag, Vflag, iflag;
   signed char Iflag, Tflag, rflag, Rflag, Sflag, sflag, xflag;
   signed char Xflag, XMLflag, yflag, zflag, Zflag, domainonly;

   char *estr, *Hstr, *Mflag;

   double Bflag;
   int  debugflag, RaInitialized;

   char RaFieldDelimiter, RaFieldQuoted; 
   signed int RaFieldWidth, RaWriteOut;

   int Uflag, sNflag, eNflag;
   int startime_t, lasttime_t;

   float Pauseflag;

   char RaLabelStr[0x10000], *RaLabel;
   char RaDBString[0x10000], *RaDBStr;
   int ArgusRandomSeed;
   int RaLabelCounter;

   int RaSOptionIndex;
   char *RaSOptionStrings[ARGUS_MAX_S_OPTIONS];

   int ArgusFilterFiledes[2];
   int ArgusControlFiledes[2];

   int RaCumulativeMerge;
   int RaFlowMajorModified;
   int RaAllocHashTableHeaders;
   int RaAllocArgusRecord;
   int RaThisActiveIndex;
   int RaThisFlowNum;
   int RaThisModelNum;
   int RaParseError;
   int ArgusMinuteUpdate;
   int ArgusHourlyUpdate;

   int RaHistoMetricSeries;
   int RaHistoMetricLog;
   int RaHistoRangeState;

   double RaHistoLogInterval;
   double RaHistoBinSize;
   double RaHistoStart, RaHistoStartLog;
   double RaHistoEnd, RaHistoEndLog;
   struct ArgusRecordStruct **RaHistoRecords;

   unsigned short ArgusSourcePort, ArgusPortNum;

   int RaHistoBins, RaCloseInputFd;

   int RaPollMode;
   int RaAgMode;
   int RaMonMode;
   int RaZeroMode;
   int RaPrintMode;
   int RaCursesMode;
   int RaPrintIndex;
   int RaExplicitDate;
   int RaWildCardDate;

   char *RaFlowModelFile, *exceptfile;
   char *writeDbstr, *readDbstr;
   char *dbustr, *dbpstr;
   char *ntais, *ustr, *pstr; 
   char *timearg, *wfile;

   char *ArgusFlowModelFile;
   char *ArgusAggregatorFile;
   char *ArgusDelegatedIPFile;
   char *ArgusLocalFilter;
   char *ArgusRemoteFilter;
   char *ArgusDisplayFilter;

   char *ArgusBindAddr;

   struct nff_program ArgusFilterCode;
   struct nff_program ArgusDisplayCode;

   struct RaFlowModelStruct *RaFlowModel;

   struct ArgusCIDRAddr ArgusCIDRBuffer, *ArgusCIDRPtr;

   struct ArgusModeStruct *ArgusModeList;
   struct ArgusModeStruct *ArgusMaskList;
   struct ArgusInput *ArgusInputFileList;
   struct ArgusInput *ArgusRemoteHostList;
   struct ArgusInput *ArgusCurrentFile;
   struct ArgusListStruct *ArgusWfileList;

   struct ArgusPrintFieldStruct *RaPrintAlgorithm;
   struct ArgusPrintFieldStruct *RaPrintAlgorithmList[ARGUS_MAX_PRINT_ALG];

   char RaDebugString[MAXSTRLEN];

   struct ArgusRecordStruct argus;
   struct ArgusCanonRecord canon;
   struct ArgusRecord ArgusInitCon;

   char ArgusSrcUserData[0x10000];
   char ArgusDstUserData[0x10000];

   char ArgusSrcActDist[256];
   char ArgusSrcIdleDist[256];
   char ArgusDstActDist[256];
   char ArgusDstIdleDist[256];
};


#ifdef ArgusParse
struct ArgusParserStruct *ArgusNewParser(char *);
void ArgusInitializeParser(struct ArgusParserStruct *);
void ArgusCloseParser(struct ArgusParserStruct *);

#else
extern struct ArgusParserStruct *ArgusNewParser(char *);
extern void ArgusInitializeParser(struct ArgusParserStruct *);
extern void ArgusCloseParser(struct ArgusParserStruct *);
#endif

#endif
