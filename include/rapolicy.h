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
 * $Id: //depot/argus/argus-3.0/clients/include/rapolicy.h#7 $
 * $DateTime: 2006/03/31 13:25:33 $
 * $Change: 793 $
 */


#define DEFAULT_POLICY   "policy.conf"
#define POLICY_STRING    "access-list"

#define POLICYFIELDNUM     9

#define POLICYSTRING       0
#define POLICYID           1
#define POLICYACTION       2
#define POLICYPROTO        3
#define POLICYSRC          4
#define POLICYSRCPORT      5
#define POLICYDST          6
#define POLICYDSTPORT      7
#define POLICYNOTIFICATION 8
#define POLICYCOMPLETE     9
#define POLICYREMARK       10

#define POLICYERRORNUM     13
#define POLICYERR_NOACL    0
#define POLICYERR_NOID     1
#define POLICYERR_NOACTION 2
#define POLICYERR_NOPROTO  3
#define POLICYERR_NOSRCADR 4
#define POLICYERR_NOSRCMSK 5
#define POLICYERR_SP_ACT   6
#define POLICYERR_SPORT    7
#define POLICYERR_NODSTADR 8
#define POLICYERR_NODSTMSK 9
#define POLICYERR_DP_ACT   10
#define POLICYERR_DPORT    11
#define POLICYERR_NONOTE   12

#define POLICYTESTCRITERIA 5

#define POLICYTESTPROTO    0
#define POLICYTESTSRC      1
#define POLICYTESTSRCPORT  2
#define POLICYTESTDST      3
#define POLICYTESTDSTPORT  4

#define RA_PERMIT    0x10000
#define RA_DENY      0x20000

#define RA_PROTO_SET	1

#define RA_EQ        0x01
#define RA_LT        0x02
#define RA_GT        0x04
#define RA_NEQ       0x08
#define RA_EST       0x10
#define RA_RANGE     0x20

#define RA_SRCROUTED      0x01
#define RA_ACCESSLIST     0x02

struct ArgusNetStruct {
   arg_int32 operator;
   arg_uint32 addr;
   arg_uint32 mask;
};

struct RaPolicyPolicyStruct {
   struct RaPolicyPolicyStruct *prv, *nxt;
   char *policyID;
   arg_int32 type;
   arg_int32 flags;
   struct ArgusNetStruct src, dst;
   arg_uint16 proto, src_port_low, src_port_hi;
   arg_uint16 dst_port_low, dst_port_hi, src_action, dst_action;
   arg_int32 notification;
   char *str;
};
