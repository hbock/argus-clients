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
 * $Id: //depot/argus/argus-3.0/clients/include/argus_int.h#11 $
 * $DateTime: 2006/05/31 02:10:14 $
 * $Change: 862 $
 */

#ifndef Argus_int_h
#define Argus_int_h

#if !defined(__STDC__)
#define const
#endif

#if !defined(__GNUC__)
#define inline
#endif

#include <argus_os.h>		/* os dependent stuff */

#ifndef SIGRET
#define SIGRET void             /* default */
#endif

struct ArgusTokenStruct {
   int v;                  /* value */
   char *s;                /* string */
};
 
struct ArgusInterfaceStruct {
   int value; 
   char *label; 
   char *desc; 
}; 

#define MIN_SNAPLEN 96

#ifndef min
#define min(a,b) ((a)>(b)?(b):(a))
#define max(a,b) ((b)>(a)?(b):(a))
#endif

extern char timestamp_fmt[];
extern long timestamp_scale;
extern void timestampinit(void);

extern int fn_print(const u_char *, const u_char *, char *);
extern int fn_printn(const u_char *, u_int, const u_char *, char *);
extern char *dnaddr_string(u_short);
extern char *savestr(const char *);

extern char *isonsap_string(const u_char *, int);
extern char *llcsap_string(u_char);
extern char *protoid_string(const u_char *);
extern char *dnname_string(u_short);
extern char *dnnum_string(u_short);

#endif /* Argus_out_h */

