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
 * $Id:$
 * $DateTime:$
 * $Change:$
 */

#ifndef ArgusLabeler_h
#define ArgusLabeler_h

#if defined(ARGUS_GEOIP)
#include <GeoIP.h>
#endif

#define ARGUS_LABELER_COCODE	0x01
#define ARGUS_LABELER_ADDRESS	0x02


#define ARGUS_TREE              0x01
#define ARGUS_TREE_VISITED      0x02
#define ARGUS_VISITED           0x10
#define ARGUS_MOL               0x20
#define ARGUS_GRAPH             0x30

struct ArgusGeoIPCityObject {
   char *field, *format;
   int length, index, offset, value;
};
 
struct ArgusLabelerStruct {
   int status, mask, inserts, prune;
   int RaPrintLabelTreeMode;
   int RaLabelIanaAddress;
   int RaLabelCountryCode;
   int RaLabelBindName;
   int RaLabelIanaPort;
   int RaLabelArgusFlow;

#if defined(ARGUS_GEOIP)
   GeoIP *RaGeoIPAsnObject;
   int RaLabelGeoIPAsn;

   GeoIP *RaGeoIPCityObject;
   int RaLabelGeoIPCity;
   int RaLabelGeoIPCityLabels[16];
#endif

   struct RaPolicyStruct *drap, *rap;
   struct RaFlowModelStruct *fmodel;
   struct ArgusQueueStruct *queue;
   struct ArgusHashTable htable;
   struct ArgusHashStruct hstruct;
   struct RaAddressStruct **ArgusAddrTree;
   struct RaPortStruct **ArgusTCPPortLabels;
   struct RaPortStruct **ArgusUDPPortLabels;
   struct ArgusQueueStruct *ArgusFlowQueue;
};

#define ARGUS_EXACT_MATCH       0
#define ARGUS_LONGEST_MATCH     1
#define ARGUS_ANY_MATCH         2

struct RaAddressStruct {
   struct ArgusQueueHeader qhdr;
   struct RaAddressStruct *l, *r, *p;
   struct ArgusCIDRAddr addr;

   struct ArgusRecordStruct *ns;

   int offset, count, status;
   char *str, *label, *dns;
   float x, y, z;
};


struct RaPortStruct {
   struct ArgusQueueHeader qhdr;
   unsigned short proto, start, end;
   int offset, count, status;
   char *label, *desc;
};


struct RaFlowLabelStruct {
   struct ArgusQueueHeader qhdr;
   int status, cont;
   char *filterstr, *labelstr;
   struct nff_program filter;
};


#if defined(ArgusLabel)

/*
struct ArgusGeoIPCityObject {
   char *field, *format;
   int length, index, offset, value;
}
*/

#define ARGUS_GEOIP_TOTAL_OBJECTS       13

struct ArgusGeoIPCityObject ArgusGeoIPCityObjects[16] = {
   { "", "%s", 0, 0, 0, 0},
#define ARGUS_GEOIP_COUNTRY_CODE        1
   { "cco", "%s", 3, 2, 0, ARGUS_GEOIP_COUNTRY_CODE},
#define ARGUS_GEOIP_COUNTRY_CODE_3      2
   { "cco3", "%s", 4, 3, 0, ARGUS_GEOIP_COUNTRY_CODE_3},
#define ARGUS_GEOIP_COUNTRY_NAME        3
   { "cname", "%s", 5, 128, 0, ARGUS_GEOIP_COUNTRY_NAME},
#define ARGUS_GEOIP_REGION              4
   { "region", "%s", 6, 128, 0, ARGUS_GEOIP_REGION},
#define ARGUS_GEOIP_CITY_NAME           5
   { "city", "%s", 4, 128, 0, ARGUS_GEOIP_CITY_NAME},
#define ARGUS_GEOIP_POSTAL_CODE         6
   { "pcode", "%s", 5, 16, 0, ARGUS_GEOIP_POSTAL_CODE},
#define ARGUS_GEOIP_LATITUDE            7
   { "lat", "%f", 3, 16, 0, ARGUS_GEOIP_LATITUDE},
#define ARGUS_GEOIP_LONGITUDE           8
   { "lon", "%f", 3, 16, 0, ARGUS_GEOIP_LONGITUDE},
#define ARGUS_GEOIP_METRO_CODE          9
   { "metro", "%s", 5, 16, 0, ARGUS_GEOIP_METRO_CODE},
#define ARGUS_GEOIP_AREA_CODE           10
   { "area", "%s", 4, 16, 0, ARGUS_GEOIP_AREA_CODE},
#define ARGUS_GEOIP_CONTINENT_CODE      11
   { "cont", "%s", 4, 16, 0, ARGUS_GEOIP_CONTINENT_CODE},
#define ARGUS_GEOIP_OFFSET              12
   { "off", "%s", 3, 32, 0, ARGUS_GEOIP_OFFSET},
};

int RaLabelParseResourceFile (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

struct ArgusLabelerStruct *ArgusNewLabeler (struct ArgusParserStruct *, int);

struct ArgusLabelerStruct *ArgusLabeler = NULL;
int ArgusLabelRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);
struct RaAddressStruct *RaInsertAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct RaAddressStruct **, struct RaAddressStruct *, int);

char *RaPruneAddressTree (struct ArgusLabelerStruct *, struct RaAddressStruct *);

int RaReadAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadPortConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadFlowLabels (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

void RaMapLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
void RaPrintLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

int RaCountryCodeLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaAddressLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaLabelIANAAddressType (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaFetchIPv4AddressLabel(struct ArgusParserStruct *, unsigned int *);
char *RaPortLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaFlowLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaFetchIPPortLabel(struct ArgusParserStruct *, unsigned short, unsigned short);

#else

extern int RaLabelParseResourceFile (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

extern struct ArgusLabelerStruct *ArgusNewLabeler (struct ArgusParserStruct *, int);
extern struct ArgusLabelerStruct *ArgusLabeler;
extern void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

extern int ArgusLabelRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

extern struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);
extern struct RaAddressStruct *RaInsertAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct RaAddressStruct **, struct RaAddressStruct *, int);
extern char *RaPruneAddressTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int);

extern int RaReadAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern int RaReadPortConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern int RaReadFlowLabels (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

extern void RaMapLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
extern void RaPrintLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
extern void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

extern int RaCountryCodeLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaAddressLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaLabelIANAAddressType (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaFetchIPv4AddressLabel(struct ArgusParserStruct *, unsigned int *);
extern char *RaPortLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaFlowLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaFetchIPPortLabel(struct ArgusParserStruct *, unsigned short, unsigned short);

#endif
#endif

