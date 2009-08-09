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
 *
 * rasql  - Read Argus data using time offset indexs from mysql database.
 *         This program reads argus output streams from a database query,
 *         filters and optionally writes the output to a file, its
 *         stdout or prints the binary records to stdout in ASCII.
 */

/* 
 * $Id: $
 * $DateTime: $
 * $Change: $
 */


#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
  
#include <netdb.h>
#include <sys/socket.h>

#include <rabins.h>
#include <rasplit.h>
 
#include <mysql.h>

char **ArgusCreateSQLTableNames (struct ArgusParserStruct *, char *);
void RaSQLQueryTable (char **);

int RaInitialized = 0;
int ArgusAutoId = 0;

char *RaRoleString = NULL;
char *RaProbeString = NULL;

#define RA_MAXTABLES            255
unsigned int RaTableFlags = 0;
 
char *RaTableValues[256];
char *RaExistsTableNames[RA_MAXTABLES];
char ArgusSQLTableNameBuf[1024];

char *RaSource         = NULL;
char *RaArchive        = NULL;
char *RaLocalArchive   = NULL;
char *RaFormat         = NULL;
char *RaTable          = NULL;

int   RaStatus         = 1;
int   RaPeriod         = 1;
int   RaSQLMaxSeconds  = 0;

char RaLocalArchBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char RaFilterSQLStatement[];
  
char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;
struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (void);

MYSQL_ROW row;
MYSQL mysql;

extern int ArgusTotalMarRecords;
extern int ArgusTotalFarRecords;

extern struct ArgusParserStruct *ArgusParser;
struct RaBinProcessStruct *RaBinProcess = NULL;

void RaArgusInputComplete (struct ArgusInput *input) {};

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         if (ArgusParser->ArgusPrintXml && ArgusParser->RaXMLStarted)
            printf("</ArgusDataStream>\n");

         if ((sig >= 0) && ArgusParser->aflag) {
            printf (" Totalrecords %-8Ld  TotalManRecords %-8Ld  TotalFarRecords %-8Ld TotalPkts %-8Ld TotalBytes %-8Ld\n",
                          ArgusParser->ArgusTotalRecords,
                          ArgusParser->ArgusTotalMarRecords, ArgusParser->ArgusTotalFarRecords,
                          ArgusParser->ArgusTotalPkts, ArgusParser->ArgusTotalBytes);
         }
      }
      fflush(stdout);
      mysql_close(&mysql);
      exit(0);
   }
}


void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
         RaProcessManRecord (parser, argus);
         break;

      case ARGUS_EVENT:
         RaProcessEventRecord (parser, argus);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];
         if (metric != NULL) {
            parser->ArgusTotalPkts  += metric->src.pkts;
            parser->ArgusTotalPkts  += metric->dst.pkts;
            parser->ArgusTotalBytes += metric->src.bytes;
            parser->ArgusTotalBytes += metric->dst.bytes;
         }

         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(argus);
            struct ArgusFlow *flow;

            if ((flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, argus);
            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else {
            RaProcessThisRecord(parser, argus);
         }
      }
   }
}


void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];

   if (parser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = parser->ArgusWfileList->count;

      if ((lobj = parser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int retn = 1;
               if (wfile->filterstr) {
                  struct nff_insn *wfcode = wfile->filter.bf_insns;
                  retn = ArgusFilterRecord (wfcode, argus);
               }

               if (retn != 0) {
                  if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;
                     static char sbuf[0x10000];
                     if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                     }
                  }
               }
            }

            lobj = lobj->nxt;
         }
      }

   } else {
      if (!parser->qflag) {
         if (parser->Lflag && !(parser->ArgusPrintXml)) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);

            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);

            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         bzero (buf, sizeof(buf));
         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);

         fprintf (stdout, "%s", buf);

         if (parser->eflag == ARGUS_HEXDUMP) {
            int i;
            for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
               struct ArgusDataStruct *user = NULL;
               if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData) {
                  int slen = 0, len = parser->RaPrintAlgorithmList[i]->length;
                  if (len > 0) {
                     if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
                        if (user->hdr.type == ARGUS_DATA_DSR) {
                           slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                        } else
                           slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                        slen = (user->count < slen) ? user->count : slen;
                        slen = (slen > len) ? len : slen;
                        ArgusDump ((const u_char *) &user->array, slen, "      ");
                     }
                  }
               }
               if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
                  int slen = 0, len = parser->RaPrintAlgorithmList[i]->length;
                  if (len > 0) {
                     if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
                        if (user->hdr.type == ARGUS_DATA_DSR) {
                           slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                        } else
                           slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                        slen = (user->count < slen) ? user->count : slen;
                        slen = (slen > len) ? len : slen;
                        ArgusDump ((const u_char *) &user->array, slen, "      ");
                     }
                  }
               }
            }
         }

         fprintf (stdout, "\n");
         fflush (stdout);
      }
   }
}


void RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns) {};
void RaProcessEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns) {};
int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}


void
RaMySQLInit ()
{
   char *sptr = NULL, *ptr;
   char userbuf[1024];

   bzero((char *)RaTableValues, sizeof(RaTableValues));
   bzero((char *)RaExistsTableNames, sizeof(RaExistsTableNames));

   bzero(userbuf, sizeof(userbuf));

   if (ArgusParser->dbustr != NULL) {
      strncpy (userbuf, ArgusParser->dbustr, sizeof(userbuf));
      if ((sptr = strchr (userbuf, '/')) != NULL)
         *sptr = '\0';
      RaUser = userbuf;
   }

   if (ArgusParser->dbpstr != NULL) 
      RaPass = ArgusParser->dbpstr;

   if ((RaDatabase == NULL) && (ArgusParser->readDbstr != NULL)) {
      RaDatabase = strdup(ArgusParser->readDbstr);
      if (!(strncmp("mysql:", RaDatabase, 6)))
         RaDatabase = &RaDatabase[6];
   }

   if (RaDatabase == NULL)
      ArgusLog(LOG_ERR, "must specify database ");

/*
      //[[username[:password]@]hostname[:port]]/database/tablename
*/

   if (!(strncmp ("//", RaDatabase, 2))) {
      if ((strncmp ("///", RaDatabase, 3))) {
         RaDatabase = &RaDatabase[2];
         RaHost = RaDatabase;
         if ((ptr = strchr (RaDatabase, '/')) != NULL) {
            *ptr++ = '\0';
            RaDatabase = ptr;

            if ((ptr = strchr (RaHost, '@')) != NULL) {
               RaUser = RaHost;
               *ptr++ = '\0';
               RaHost = ptr;
               if ((ptr = strchr (RaUser, ':')) != NULL) {
                  *ptr++ = '\0';
                  RaPass = ptr;
               } else {
                  RaPass = NULL;
               }
            }

            if ((ptr = strchr (RaHost, ':')) != NULL) {
               *ptr++ = '\0';
               RaPort = atoi(ptr);
            }
         } else
            RaDatabase = NULL;

      } else {
         RaDatabase = &RaDatabase[3];
      }
   }

#define RATABLES_MAX_ENTRIES	65536

   if ((ptr = strchr (RaDatabase, '/')) != NULL) {
      *ptr++ = '\0';
      RaTable = ptr;
   }
 
   if ((mysql_init(&mysql)) == NULL)
      ArgusLog(LOG_ERR, "mysql_init error %s", strerror(errno));

   mysql_options(&mysql, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);

   if ((mysql_real_connect(&mysql, RaHost, RaUser, RaPass, RaDatabase, RaPort, NULL, 0)) == NULL)
      ArgusLog(LOG_ERR, "mysql_connect error %s", mysql_error(&mysql));



#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}

 
#define RA_MAXSQLQUERY          4
char *RaTableQueryString[RA_MAXSQLQUERY] = {
   "SELECT id, name from NTAIS.Probes",
   "SELECT * from %s_%s_Seconds WHERE second >= %u and second <= %u",
   "SELECT filename from %s_%s_Filename WHERE id = %d",
};

#define RA_MAXMCASTSQLQUERY     3
char *RaMcastTableQueryString[RA_MAXMCASTSQLQUERY] = {
   "SELECT record from %s_CurrMcastGroups where groupaddr=\"\"",
   "SELECT record from %s_CurrMcastSender",
   "SELECT record from %s_CurrMcastMember",
};

#define RAMYSQL_NETWORKSTABLE_NUMBER	0
#define RAMYSQL_NETWORKSTABLE_START	1
#define RAMYSQL_NETWORKSTABLE_END	2

struct RaMySQLNetworksTable {
   struct ArgusQueueHeader qhdr;
   unsigned int number;
   unsigned int start;
   unsigned int last;
};
 
struct RaMySQLFileStruct {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   unsigned int fileindex;
   unsigned int second;
   char *filename;
   unsigned int ostart, ostop;
};

#define RAMYSQL_SECONDTABLE_PROBE	0
#define RAMYSQL_SECONDTABLE_SECOND	1
#define RAMYSQL_SECONDTABLE_FILEINDEX	2
#define RAMYSQL_SECONDTABLE_OSTART	3
#define RAMYSQL_SECONDTABLE_OSTOP 	4

struct RaMySQLSecondsTable {
   struct ArgusQueueHeader qhdr;
   unsigned int fileindex;
   char *filename;
   unsigned int probe;
   unsigned int second;
   unsigned int ostart, ostop;
};

#define RAMYSQL_PROBETABLE_PROBE	0
#define RAMYSQL_PROBETABLE_NAME		1

struct RaMySQLProbeTable {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   char *name;
};
 

void RaMySQLInit (void);

struct timeval RaStartTime = {0x7FFFFFFF, 0x7FFFFFFF};
struct timeval RaEndTime = {0, 0};

struct ArgusQueueStruct *ArgusModelerQueue;
struct ArgusQueueStruct *ArgusFileQueue;
struct ArgusQueueStruct *ArgusProbeQueue;

char ArgusArchiveBuf[4098];

#define RAMON_NETS_CLASSA	0
#define RAMON_NETS_CLASSB	1
#define RAMON_NETS_CLASSC	2
#define RAMON_NETS_CLASS	3

void
RaSQLQueryTable (char **tables)
{
   char buf[0x10000], sbuf[0x10000], *table;
   MYSQL_RES *mysqlRes;
   struct timeval now;
   int retn, x, i;

   if ((ArgusInput = (struct ArgusInput *) ArgusCalloc (1, sizeof(struct ArgusInput))) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   ArgusInput->fd            = -1;
   ArgusInput->ArgusOriginal = (struct ArgusRecord *)&ArgusInput->ArgusOriginalBuffer;
   ArgusInput->mode          = ARGUS_DATA_SOURCE;
   ArgusInput->status       |= ARGUS_DATA_SOURCE;
   ArgusInput->index         = -1;
   ArgusInput->ostart        = -1;
   ArgusInput->ostop         = -1;

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&ArgusInput->lock, NULL);
#endif

   ArgusInput->ArgusInitCon.hdr.type  = ARGUS_MAR | ARGUS_VERSION;
   ArgusInput->ArgusInitCon.hdr.cause = ARGUS_START;
   ArgusInput->ArgusInitCon.hdr.len   = htons((unsigned short) sizeof(struct ArgusRecord)/4);

   ArgusInput->ArgusInitCon.argus_mar.argusid = htonl(ARGUS_COOKIE);

   gettimeofday (&now, 0L);

   ArgusInput->ArgusInitCon.argus_mar.now.tv_sec  = now.tv_sec;
   ArgusInput->ArgusInitCon.argus_mar.now.tv_usec = now.tv_usec;

   ArgusInput->ArgusInitCon.argus_mar.major_version = VERSION_MAJOR;
   ArgusInput->ArgusInitCon.argus_mar.minor_version = VERSION_MINOR;

   bcopy((char *)&ArgusInput->ArgusInitCon, (char *)&ArgusParser->ArgusInitCon, sizeof (ArgusParser->ArgusInitCon));

   for (i = 0; ((table = tables[i]) != NULL); i++) {
      if (ArgusAutoId)
         sprintf (buf, "SELECT autoid,record from %s", table);
      else
         sprintf (buf, "SELECT record from %s", table);

      if (ArgusParser->ArgusSQLStatement != NULL)
         sprintf (&buf[strlen(buf)], " WHERE %s", ArgusParser->ArgusSQLStatement);

#ifdef ARGUSDEBUG
      ArgusDebug (1, "SQL Query %s\n", buf);
#endif
      if ((retn = mysql_real_query(&mysql, buf, strlen(buf))) == 0) {
         if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               while ((row = mysql_fetch_row(mysqlRes))) {
                  unsigned long *lengths = mysql_fetch_lengths(mysqlRes);
                  int autoid = 0;

                  bzero(sbuf, sizeof(sbuf));
                  if (ArgusAutoId && (retn > 1)) {
                     char *endptr;
                     autoid = strtol(row[0], &endptr, 10);
                     if (row[0] == endptr)
                        ArgusLog(LOG_ERR, "mysql database error: autoid returned %s", row[0]);
                     x = 1;
                  } else
                     x = 0;

                  ArgusParser->ArgusAutoId = autoid;
                  bcopy (row[x], sbuf, (int) lengths[x]);

                  if (((struct ArgusRecord *)sbuf)->hdr.type & ARGUS_MAR) {
                     bcopy ((char *) &sbuf, (char *)&ArgusInput->ArgusInitCon, sizeof (struct ArgusRecord));
                  } else {
                     ArgusHandleDatum (ArgusParser, ArgusInput, (struct ArgusRecord *)&sbuf, &ArgusParser->ArgusFilterCode);
                  }
               }
            }

            mysql_free_result(mysqlRes);
         }
      }
   }
}


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusAdjustStruct *nadp = NULL;
   struct ArgusModeStruct *mode;
   int x, retn;

   if (!(parser->RaInitialized)) {
      parser->RaInitialized++;
      parser->RaWriteOut = 0;

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      ArgusParseInit(ArgusParser, NULL);

      if (ArgusParser->Sflag)
         usage();

      for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (parser->RaPrintAlgorithmList[x] != NULL) {
            if (!(strncmp(parser->RaPrintAlgorithmList[x]->field, "autoid", 6))) {
               ArgusAutoId = 1;
               break;
            }
         } else
            break;
      }

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((ArgusProbeQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((ArgusFileQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((RaBinProcess = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*RaBinProcess))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
      pthread_mutex_init(&RaBinProcess->lock, NULL);
#endif

      nadp = &RaBinProcess->nadp;

      nadp->mode   = -1;
      nadp->modify =  0;
      nadp->slen   =  2;
 
      if (parser->aflag)
         nadp->slen = parser->aflag;

      if ((mode = parser->ArgusModeList) != NULL) {
         int i, ind;
         while (mode) {
            for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
               if (!(strncasecmp (mode->mode, RaSplitModes[i], strlen(RaSplitModes[i])))) {
                  ind = i;
                  break;
               }
            }

            if (ind >= 0) {
               char *mptr = NULL;
               switch (ind) {
                  case ARGUSSPLITRATE:  {   /* "%d:%d[yMwdhms]" */
                     struct ArgusModeStruct *tmode = NULL; 
                     nadp->mode = ind;
                     if ((tmode = mode->nxt) != NULL) {
                        mptr = tmode->mode;
                        if (isdigit((int)*tmode->mode)) {
                           char *ptr = NULL;
                           nadp->count = strtol(tmode->mode, (char **)&ptr, 10);
                           if (*ptr++ != ':') 
                              usage();
                           tmode->mode = ptr;
                        }
                     }
                  }

                  case ARGUSSPLITTIME: /* "%d[yMwdhms] */
                     nadp->mode = ind;
                     if ((mode = mode->nxt) != NULL) {
                        if (isdigit((int)*mode->mode)) {
                           char *ptr = NULL;
                           nadp->value = strtol(mode->mode, (char **)&ptr, 10);
                           if (ptr == mode->mode)
                              usage();
                           else {
                              switch (*ptr) {
                                 case 'y':
                                    nadp->qual = ARGUSSPLITYEAR;  
                                    nadp->size = nadp->value * 31556926 * 1000000LL;
                                    break;
                                 case 'M':
                                    nadp->qual = ARGUSSPLITMONTH; 
                                    nadp->size = nadp->value * 2629744 * 1000000LL;
                                    break;
                                 case 'w':
                                    nadp->qual = ARGUSSPLITWEEK;  
                                    nadp->size = nadp->value * 604800 * 1000000LL;
                                    break;
                                 case 'd':
                                    nadp->qual = ARGUSSPLITDAY;   
                                    nadp->size = nadp->value * 86400 * 1000000LL;
                                    break;
                                 case 'h':
                                    nadp->qual = ARGUSSPLITHOUR;  
                                    nadp->size = nadp->value * 3600 * 1000000LL;
                                    break;
                                 case 'm':
                                    nadp->qual = ARGUSSPLITMINUTE;
                                    nadp->size = nadp->value * 60 * 1000000LL;
                                    break;
                                  default:
                                    nadp->qual = ARGUSSPLITSECOND;
                                    nadp->size = nadp->value * 1000000LL;
                                    break;
                              }
                           }
                        }
                        if (mptr != NULL)
                            mode->mode = mptr;
                     }

                     nadp->modify = 1;

                     if (ind == ARGUSSPLITRATE) {
                        /* need to set the flow idle timeout value to be equal to or
                           just a bit bigger than (nadp->count * nadp->size) */

                        ArgusParser->timeout.tv_sec  = (nadp->count * (nadp->size / 1000000));
                        ArgusParser->timeout.tv_usec = 0;
                     }
                     break;

                  case ARGUSSPLITSIZE:
                  case ARGUSSPLITCOUNT:
                     nadp->mode = ind;
                     nadp->count = 1;

                     if ((mode = mode->nxt) != NULL) {
                        if (isdigit((int)*mode->mode)) {
                           char *ptr = NULL;
                           nadp->value = strtol(mode->mode, (char **)&ptr, 10);
                           if (ptr == mode->mode)
                              usage();
                           else {
                              switch (*ptr) {
                                 case 'B':   
                                 case 'b':  nadp->value *= 1000000000; break;
                                  
                                 case 'M':   
                                 case 'm':  nadp->value *= 1000000; break;
                                  
                                 case 'K':   
                                 case 'k':  nadp->value *= 1000; break;
                              }
                           }
                        }
                     }
                     break;

                  case ARGUSSPLITNOMODIFY:
                     nadp->modify = 0;
                     break;

                  case ARGUSSPLITHARD:
                     nadp->hard++;
                     break;

                  case ARGUSSPLITZERO:
                     nadp->zero++;
                     break;
               }

            } else {
               if (!(strncasecmp (mode->mode, "nocorrect", 9))) {
                  if (parser->ArgusAggregator->correct != NULL) {
                     free(parser->ArgusAggregator->correct);
                     parser->ArgusAggregator->correct = NULL;
                  }
               } else
               if (!(strncasecmp (mode->mode, "rtime", 5)) ||
                  (!(strncasecmp (mode->mode, "realtime", 8)))) {
                  char *ptr = NULL;
                  ArgusParser->status |= ARGUS_REAL_TIME_PROCESS;
                  if ((ptr = strchr(mode->mode, ':')) != NULL) {
                     double value = 0.0;
                     char *endptr = NULL;
                     ptr++;
                     value = strtod(ptr, &endptr);
                     if (ptr != endptr)
                        parser->ArgusTimeMultiplier = value;
                  }
               }
            }

            mode = mode->nxt;
         }
      }

      RaBinProcess->size = nadp->size;

      if (nadp->mode < 0) {
         nadp->mode = ARGUSSPLITCOUNT;
         nadp->value = 10000;
         nadp->count = 1;
      }

      RaMySQLInit();

      if (parser->tflag) {

// so we've been given a time filter, so we have a start and end time
// stored in parser->startime_t && parser->lasttime_t, and we support
// wildcard options, so ..., the idea is that we need at some point to
// calculate the set of tables we'll search for records.  We should do
// that here.
//
// So the actual table, datatbase, etc..., were set in the RaMySQLInit()
// call so we can test some values here.

         if (strchr(RaTable, '%') || strchr(RaTable, '$'))
            RaTables = ArgusCreateSQLTableNames(parser, RaTable);
      }

      if (RaTables == NULL) {
         sprintf (ArgusSQLTableNameBuf, "%s", RaTable);

         if ((RaTables = ArgusCalloc(sizeof(void *), 2)) == NULL)
            ArgusLog(LOG_ERR, "mysql_init error %s", strerror(errno));

         RaTables[0] = strdup(ArgusSQLTableNameBuf);
      }

      if (parser->tflag) {
         char ArgusSQLStatement[MAXSTRLEN];
         char *timeField = NULL;
         MYSQL_RES *mysqlRes;

         sprintf (ArgusSQLStatement, "desc %s", RaTables[0]);

         if ((retn = mysql_real_query(&mysql, ArgusSQLStatement , strlen(ArgusSQLStatement))) != 0)
            ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(&mysql));
         else {
            if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
               if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                  while ((row = mysql_fetch_row(mysqlRes))) {
                     if (strstr(row[0], "time")) {
                        if (!(strcmp("stime", row[0]))) {
                           timeField = "stime";
                           break;
                        }
                        if (!(strcmp("ltime", row[0])))
                           timeField = "ltime";
                     }
                  }
               }

               mysql_free_result(mysqlRes);
            }

            if (timeField == NULL)
               ArgusLog (LOG_ERR, "ArgusClientInit () time range specified but schema does not suppor time\n");
         }

         if (ArgusParser->ArgusSQLStatement != NULL) {
         } else {
            snprintf (ArgusSQLStatement, MAXSTRLEN, "%s >= %d and %s < %d", timeField, parser->startime_t, timeField, parser->lasttime_t);
            ArgusParser->ArgusSQLStatement = strdup(ArgusSQLStatement);
         }
      }

      if (RaTables) {
         RaSQLQueryTable (RaTables);
         RaParseComplete (SIGINT);
      }
   }
}

void
usage ()
{
   extern char version[];

   fprintf (stderr, "RaSql Version %s\n", version);
   fprintf (stderr, "usage: %s -r mysql://[user[:pass]@]host[:port]/db/table\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [ra-options] [rasql-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -M sql='where clause'  pass where clause to database engine.\n");
   fprintf (stderr, "         -r <dbUrl>             read argus data from mysql database.\n");
   fprintf (stderr, "             Format:            mysql://[user[:pass]@]host[:port]/db/table\n");
   exit(1);
}


/*
 *  Convert host name to internet address.
 *  Return 0 upon failure.
 */

unsigned int **
argus_nametoaddr(char *name)
{
#ifndef h_addr
   static unsigned int *hlist[2];
#endif
   struct hostent *hp;

   if ((hp = gethostbyname(name)) != NULL) {
#ifndef h_addr
      hlist[0] = (unsigned int *)hp->h_addr;
#if defined(_LITTLE_ENDIAN)
      *hp->h_addr = ntohl(*hp->h_addr);
#endif
      return hlist;
#else
#if defined(_LITTLE_ENDIAN)
      {
         unsigned int **p;
          for (p = (unsigned int **)hp->h_addr_list; *p; ++p)
             **p = ntohl(**p);
      }
#endif
      return (unsigned int **)hp->h_addr_list;
#endif
   }
   else
      return 0;
}



int
RaProcessSplitOptions(struct ArgusParserStruct *parser, char *str, int len, struct ArgusRecordStruct *ns)
{
   char resultbuf[MAXSTRLEN], tmpbuf[MAXSTRLEN];
   char *ptr = NULL, *tptr = str;
   int retn = 0, i, x;

   bzero (resultbuf, len);

   if (ns == NULL)
      return (1);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      sprintf (&resultbuf[strlen(resultbuf)], "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            bzero (tmpbuf, MAXSTRLEN);
            RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);

            while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
               tmpbuf[strlen(tmpbuf) - 1] = '\0';

            while (isspace((int)tmpbuf[i])) i++;
            sprintf (&resultbuf[strlen(resultbuf)], "%s", &tmpbuf[i]);

            ptr += strlen(RaPrintAlgorithmTable[x].field);
            while (*ptr && (*ptr != '$'))
               bcopy (ptr++, &resultbuf[strlen(resultbuf)], 1);
            break;
         }
      }

      tptr = ptr;
      retn++;
   }

   if (retn) {
      bzero (str, len);
      bcopy (resultbuf, str, strlen(resultbuf));
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaProcessSplitOptions(%s, %d, 0x%x): returns %d", str, len, ns, retn);
#endif

   return (retn);
}


extern int RaDaysInAMonth[12];

time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;

#define ARGUS_MAX_TABLE_LIST_SIZE	1024

char **
ArgusCreateSQLTableNames (struct ArgusParserStruct *parser, char *table)
{
   char **retn = NULL, *fileStr = NULL;
   struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;
   int retnIndex = 0;

   if (strchr(table, '%') || strchr(table, '$')) {
      int size = nadp->size / 1000000;
      long long start;
      time_t tableSecs;
      struct tm tmval;

      {
         if (parser->startime_t > 0) {
            start = parser->startime_t * 1000000LL;
         } else
            start = parser->ArgusRealTime.tv_sec * 1000000LL + parser->ArgusRealTime.tv_usec;

            fileStr = NULL;
            tableSecs = start / 1000000;

            switch (nadp->qual) {
               case ARGUSSPLITYEAR:
               case ARGUSSPLITMONTH:
               case ARGUSSPLITWEEK: 
                  gmtime_r(&tableSecs, &tmval);
                  break;
            }

            switch (nadp->qual) {
               case ARGUSSPLITYEAR:
                  tmval.tm_mon = 0;
               case ARGUSSPLITMONTH:
                  tmval.tm_mday = 1;

               case ARGUSSPLITWEEK: 
                  if (nadp->qual == ARGUSSPLITWEEK) {
                     if ((tmval.tm_mday - tmval.tm_wday) < 0) {
                        if (tmval.tm_mon == 0) {
                           if (tmval.tm_year != 0)
                              tmval.tm_year--;
                           tmval.tm_mon = 11;
                        } else {
                           tmval.tm_mon--;
                        }
                        tmval.tm_mday = RaDaysInAMonth[tmval.tm_mon];
                     }
                     tmval.tm_mday -= tmval.tm_wday;
                  }

                  tmval.tm_hour = 0;
                  tmval.tm_min  = 0;
                  tmval.tm_sec  = 0;
                  tableSecs = timegm(&tmval);
                  localtime_r(&tableSecs, &tmval);
                  tableSecs -= tmval.tm_gmtoff;
                  break;

               case ARGUSSPLITDAY:
               case ARGUSSPLITHOUR:
               case ARGUSSPLITMINUTE:
               case ARGUSSPLITSECOND: {
                  localtime_r(&tableSecs, &tmval);
                  tableSecs += tmval.tm_gmtoff;
                  tableSecs = tableSecs / size;
                  tableSecs = tableSecs * size;
                  tableSecs -= tmval.tm_gmtoff;
                  break;
               }
            }

            localtime_r(&tableSecs, &tmval);

            if (strftime(ArgusSQLTableNameBuf, MAXSTRLEN, table, &tmval) <= 0)
               ArgusLog (LOG_ERR, "RaSendArgusRecord () ArgusCalloc %s\n", strerror(errno));

            ArgusTableStartSecs = tableSecs;

            switch (nadp->qual) {
               case ARGUSSPLITYEAR:  
                  tmval.tm_year++;
                  ArgusTableEndSecs = mktime(&tmval);
                  break;
               case ARGUSSPLITMONTH:
                  tmval.tm_mon++;
                  ArgusTableEndSecs = mktime(&tmval);
                  break;
               case ARGUSSPLITWEEK: 
               case ARGUSSPLITDAY: 
               case ARGUSSPLITHOUR: 
               case ARGUSSPLITMINUTE: 
               case ARGUSSPLITSECOND: 
                  ArgusTableEndSecs = tableSecs + size;
                  break;
            }

            fileStr = ArgusSQLTableNameBuf;

            if (fileStr != NULL) {
               if (retn == NULL) {
                  if ((retn = ArgusCalloc(sizeof(void *), ARGUS_MAX_TABLE_LIST_SIZE)) == NULL)
                     ArgusLog(LOG_ERR, "ArgusCreateSQLTableNames ArgusCalloc %s", strerror(errno));
                  retnIndex = 0;
               }

               retn[retnIndex++] = strdup(fileStr);
            }
         }

      } else {
         bcopy(ArgusSQLTableNameBuf, table, strlen(table));
         fileStr = ArgusSQLTableNameBuf;

         if (retn == NULL) {
            if ((retn = ArgusCalloc(sizeof(void *), 2)) == NULL)
               ArgusLog(LOG_ERR, "ArgusCreateSQLTableNames ArgusCalloc %s", strerror(errno));
            retnIndex = 0;
         }

         retn[0] = strdup(fileStr);
      }

   return (retn);
}
