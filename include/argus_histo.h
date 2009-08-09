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
 * $Id: //depot/argus/argus-3.0/clients/include/argus_histo.h#4 $
 * $DateTime: 2006/03/31 13:25:33 $
 * $Change: 793 $
 */

#define ARGUS_HISTO_RANGE_UNSPECIFIED	0x02
#define ARGUS_HISTO_CAPTURE_VALUES	0x10

extern double ArgusFetchSrcId (struct ArgusRecordStruct *);
extern double ArgusFetchTime (struct ArgusRecordStruct *);
extern double ArgusFetchStartTime (struct ArgusRecordStruct *);
extern double ArgusFetchLastTime (struct ArgusRecordStruct *);
extern double ArgusFetchTransactions (struct ArgusRecordStruct *);
extern double ArgusFetchuSecDuration (struct ArgusRecordStruct *);
extern double ArgusFetchDuration (struct ArgusRecordStruct *);
extern double ArgusFetchAvgDuration (struct ArgusRecordStruct *);
extern double ArgusFetchMinDuration (struct ArgusRecordStruct *);
extern double ArgusFetchMaxDuration (struct ArgusRecordStruct *);
extern double ArgusFetchSrcMac (struct ArgusRecordStruct *);
extern double ArgusFetchDstMac (struct ArgusRecordStruct *);
extern double ArgusFetchSrcAddr (struct ArgusRecordStruct *);
extern double ArgusFetchDstAddr (struct ArgusRecordStruct *);
extern double ArgusFetchProtocol (struct ArgusRecordStruct *);
extern double ArgusFetchSrcMpls (struct ArgusRecordStruct *);
extern double ArgusFetchDstMpls (struct ArgusRecordStruct *);
extern double ArgusFetchSrcVlan (struct ArgusRecordStruct *);
extern double ArgusFetchDstVlan (struct ArgusRecordStruct *);
extern double ArgusFetchSrcIpId (struct ArgusRecordStruct *);
extern double ArgusFetchDstIpId (struct ArgusRecordStruct *);
extern double ArgusFetchSrcPort (struct ArgusRecordStruct *);
extern double ArgusFetchDstPort (struct ArgusRecordStruct *);
extern double ArgusFetchSrcTos (struct ArgusRecordStruct *);
extern double ArgusFetchDstTos (struct ArgusRecordStruct *);
extern double ArgusFetchSrcTtl (struct ArgusRecordStruct *);
extern double ArgusFetchDstTtl (struct ArgusRecordStruct *);
extern double ArgusFetchByteCount (struct ArgusRecordStruct *);
extern double ArgusFetchLoad (struct ArgusRecordStruct *);
extern double ArgusFetchSrcLoad (struct ArgusRecordStruct *);
extern double ArgusFetchDstLoad (struct ArgusRecordStruct *);
extern double ArgusFetchLoss (struct ArgusRecordStruct *);
extern double ArgusFetchRate (struct ArgusRecordStruct *);
extern double ArgusFetchSrcRate (struct ArgusRecordStruct *);
extern double ArgusFetchDstRate (struct ArgusRecordStruct *);
extern double ArgusFetchTranRef (struct ArgusRecordStruct *);
extern double ArgusFetchSeq (struct ArgusRecordStruct *);
extern double ArgusFetchSrcByteCount (struct ArgusRecordStruct *);
extern double ArgusFetchDstByteCount (struct ArgusRecordStruct *);
extern double ArgusFetchPktsCount (struct ArgusRecordStruct *);
extern double ArgusFetchSrcPktsCount (struct ArgusRecordStruct *);
extern double ArgusFetchDstPktsCount (struct ArgusRecordStruct *);
extern double ArgusFetchSrcTcpBase (struct ArgusRecordStruct *);
extern double ArgusFetchDstTcpBase (struct ArgusRecordStruct *);
extern double ArgusFetchTcpRtt (struct ArgusRecordStruct *);
extern double ArgusFetchTcpSynAck (struct ArgusRecordStruct *);
extern double ArgusFetchTcpAckDat (struct ArgusRecordStruct *);
extern double ArgusFetchSrcTcpMax (struct ArgusRecordStruct *);
extern double ArgusFetchDstTcpMax (struct ArgusRecordStruct *);
extern double ArgusFetchSrcLoss (struct ArgusRecordStruct *);
extern double ArgusFetchDstLoss (struct ArgusRecordStruct *);
