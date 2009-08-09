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
 * rasqlinsert.c  - top program basis for mysql loaded and retrieved data.  
 * 
*/

/* 
 * $Id$
 * $DateTime$
 * $Change$
 */


#define ARGUS_RECORD_MODIFIED	0x0100
#define ARGUS_RECORD_CLEARED	0x0200

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>

#include <compat.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <rabins.h>
#include <rasplit.h>
#include <rasqlinsert.h>

#include <signal.h>
#include <ctype.h>

#include <argus_sort.h>
#include <argus_cluster.h>

#include <glob.h>
#include <regex.h>

#include <sys/types.h>
#include <sys/wait.h>


char * ArgusTrimString (char *);


#if defined(ARGUS_CURSES)
void * ArgusCursesProcess (void *);

#if defined(ARGUS_READLINE)
#include <readline/readline.h>
#include <readline/history.h>

void argus_redisplay_function(void);
int argus_readline_timeout(void);
int argus_getch_function(FILE *);
void argus_getsearch_string(int);
void argus_command_string(void);

int argus_process_command (struct ArgusParserStruct *, int);

void argus_enable_history(void);
void argus_disable_history(void);
void argus_recall_history(void);
void argus_save_history(void);

int argus_history_is_enabled(void);

#endif

int ArgusTerminalColors = 0;
int ArgusDisplayStatus = 0;
#endif

int ArgusSQLBulkInsertSize = 0;
int ArgusSQLMaxPacketSize = 0;
int ArgusSQLBulkBufferSize = 0;
int ArgusSQLBulkBufferIndex = 0;
char *ArgusSQLBulkLastTable = NULL;
char *ArgusSQLBulkBuffer = NULL;

extern int ArgusSOptionRecord;
int ArgusDeleteTable = 0;

void ArgusUpdateScreen(void);

#define ARGUS_FORWARD	1
#define ARGUS_BACKWARD	2

int ArgusRankSize = 4;
int ArgusSearchDirection = ARGUS_FORWARD;


#if defined(ARGUSMYSQL)
#include <netdb.h>
#include <sys/socket.h>

#include <mysql.h>

int ArgusCreateSQLSaveTable(char *);
char *ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);
void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaSQLQueryMcastTables (void);
void RaSQLQueryTable (char *);
void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);

char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);
struct RaBinProcessStruct *ArgusNewRateBins (struct ArgusParserStruct *, struct ArgusRecordStruct *);

int RaInitialized = 0;
int RaSQLMcastMode = 0;

char *RaRoleString = NULL;
char *RaProbeString = NULL;
char *RaSQLSaveTable = NULL;
char *RaSQLCurrentTable = NULL;

#define RA_MAXTABLES            1024

unsigned int RaTableFlags = 0;

char *RaTableValues[256];
char *RaTableExistsNames[RA_MAXTABLES];
char *RaTableCreateNames[RA_MAXTABLES];
char *RaTableCreateString[RA_MAXTABLES];
char *RaTableDeleteString[RA_MAXTABLES];

char *RaSource       = NULL;
char *RaArchive      = NULL;
char *RaLocalArchive = NULL;
char *RaFormat       = NULL;
char *RaTable        = NULL;
int   RaPeriod       = 1;
int   RaStatus       = 1;

int   RaSQLMaxSecs   = 0;
int   RaSQLUpdateDB  = 1;
int   RaSQLDBInserts = 0;
int   RaSQLDBUpdates = 0;
int   RaSQLDBDeletes = 1;
int   RaFirstManRec  = 1;

char ArgusArchiveBuf[4098];
char RaLocalArchBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char *RaLocalFilter;

extern char RaFilterSQLStatement[];

char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;

struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (void);

MYSQL_ROW row;
MYSQL mysql, *RaMySQL = NULL;

struct ArgusSQLQueryStruct {
   struct ArgusListObjectStruct *nxt;
   char *tbl, *sptr, *dptr;
};


#define RA_MAXSQLQUERY          3
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

#endif

struct timeval RaStartTime = {0x7FFFFFFF, 0x7FFFFFFF};
struct timeval RaEndTime = {0, 0};

#define ARGUS_REMOTE_FILTER	1
#define ARGUS_LOCAL_FILTER	2
#define ARGUS_DISPLAY_FILTER	3


#define RAMON_NETS_CLASSA	0
#define RAMON_NETS_CLASSB	1
#define RAMON_NETS_CLASSC	2
#define RAMON_NETS_CLASS	3

#define RA_DIRTYBINS            0x20

extern void ArgusInitAggregatorStructs(struct ArgusAggregatorStruct *);

void RaTopLoop (struct ArgusParserStruct *);
void RaRefreshDisplay(struct ArgusParserStruct *);
void RaOutputModifyScreen (void);
void RaOutputHelpScreen (void);
int RaSearchDisplay (struct ArgusParserStruct *, struct ArgusQueueStruct *, int, int *, int *, char *);

struct RaBinProcessStruct *RaBinProcess = NULL;

struct RaTopProcessStruct *RaTopNewProcess(struct ArgusParserStruct *parser);


#if defined(ARGUS_THREADS)
pthread_attr_t RaTopAttr;
pthread_t RaCursesThread = 0;
#endif

#define RATOPSTARTINGINDEX	2

struct RaTopProcessStruct {
   int status, timeout; 
   int value, size;
   struct ArgusRecordStruct *ns;
   struct ArgusQueueStruct *queue;
   struct ArgusHashTable *htable;
   struct nff_program filter;
};

struct RaTopProcessStruct *RaTopProcess = NULL;

float RaUpdateRate = 1.0;
int RaCursorOffset = 0;
int RaCursorX = 0;
int RaCursorY = 0;

int ArgusCursesEnabled = 0;
int ArgusDropTable = 1;
int ArgusCreateTable = 0;
int ArgusAutoId = 0;

struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};

char ArgusSQLSaveTableNameBuf[1024];
struct tm ArgusSaveTableTmStruct;
time_t ArgusSaveTableSeconds = 0;

struct timeval dLastTime = {0, 0};
struct timeval dRealTime = {0, 0};
struct timeval dThisTime = {0, 0};
struct timeval dTime     = {0, 0};

long long thisUsec = 0;
long long lastUsec = 0;

struct ArgusQueueStruct *ArgusModelerQueue;
struct ArgusQueueStruct *ArgusFileQueue;
struct ArgusQueueStruct *ArgusProbeQueue;

struct ArgusListStruct *ArgusSQLQueryList;

void RaResizeHandler (int);


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusAdjustStruct *nadp = NULL;
   struct ArgusInput *input = NULL;
   struct ArgusModeStruct *mode; 
   char outputfile[MAXSTRLEN];
   int i = 0;

#if defined(ARGUS_CURSES)
#if defined(ARGUS_READLINE)
   int keytimeout;

   using_history();
   rl_redisplay_function = argus_redisplay_function;
   rl_getc_function = argus_getch_function;
#if defined(ARGUS_READLINE_EVENT_HOOK)
   rl_event_hook = argus_readline_timeout;
#endif
   keytimeout = RaTopUpdateInterval.tv_sec * 1000000 + RaTopUpdateInterval.tv_usec;
   keytimeout = (keytimeout == 1000000) ? keytimeout - 1 : keytimeout;
   rl_set_keyboard_input_timeout (keytimeout);

   rl_outstream = NULL;
   rl_catch_signals = 0;
   rl_catch_sigwinch = 0;
#endif
#endif

   outputfile[0] = '\0';
   parser->RaWriteOut = 1;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      (void) signal (SIGWINCH,(void (*)(int)) RaResizeHandler);

      (void) signal (SIGPIPE, SIG_IGN);
      (void) signal (SIGALRM, SIG_IGN);

      parser->RaClientTimeout.tv_sec  = 0;
      parser->RaClientTimeout.tv_usec = 10000;

      parser->RaInitialized++;
      parser->ArgusPrintXml = 0;

      parser->NonBlockingDNS = 1;
      parser->RaCumulativeMerge = 1;

      if ((parser->timeout.tv_sec == -1) && (parser->timeout.tv_usec == 0)) {
         parser->timeout.tv_sec  = 60;
         parser->timeout.tv_usec = 0;
      }

      ArgusCursesEnabled = 1;

      if ((ArgusInput = (struct ArgusInput *) ArgusCalloc (1, sizeof(struct ArgusInput))) != NULL) {
         ArgusInput->ArgusOriginal = (struct ArgusRecord *)&ArgusInput->ArgusOriginalBuffer;
         ArgusInput->fd = -1;
      }

      if (parser->ArgusRemoteHosts)
         if ((input = (void *)parser->ArgusRemoteHosts->start) != NULL) 
            parser->RaTasksToDo = 1;

      if (parser->ArgusInputFileList != NULL) {
         parser->RaTasksToDo = 1;
         if (!(parser->ArgusRemoteHosts && parser->ArgusRemoteHosts->count)) {
            if (!(ArgusParser->status & ARGUS_REAL_TIME_PROCESS)) {
               ArgusCursesEnabled = 0;
               parser->timeout.tv_sec  = 0;
               parser->timeout.tv_usec = 0;
            }
         }
      }

      if (parser->ArgusFlowModelFile) {
         parser->ArgusAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL);
      } else
         parser->ArgusAggregator = ArgusNewAggregator(parser, NULL);

      if (parser->Hstr != NULL)
         ArgusHistoMetricParse(parser, parser->ArgusAggregator);

      if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewQueue error %s", strerror(errno));

      if ((ArgusProbeQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewQueue error %s", strerror(errno));

      if ((ArgusFileQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewQueue error %s", strerror(errno));

      if ((ArgusSQLQueryList = ArgusNewList()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewList error %s", strerror(errno));

      if ((RaTopProcess = RaTopNewProcess(parser)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: RaTopNewProcess error");

      if (parser->vflag) 
         ArgusReverseSortDir++;
 
      if ((ArgusSorter = ArgusNewSorter()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));

      ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[ARGUSSORTPKTSCOUNT];

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
         int i, x, ind;
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

                     ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                     ArgusSorter->ArgusSortAlgorithms[1] = NULL;
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
                     ArgusSorter->ArgusSortAlgorithms[0] = NULL;
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
               if (!(strncasecmp (mode->mode, "nocurses", 8))) {
                  ArgusCursesEnabled = 0;
               } else
               if (!(strncasecmp (mode->mode, "cache", 5))) {
                  RaSQLDBDeletes = 0;
               } else
               if (!(strncasecmp (mode->mode, "nodrop", 6))) {
                  ArgusDropTable = 0;
               } else
               if (!(strncasecmp (mode->mode, "rmon", 4))) {
                  parser->RaMonMode++;
               } else
               if (!(strncasecmp (mode->mode, "delete", 6))) {
                  ArgusDeleteTable = 1;
               } else
               if (!(strncasecmp (mode->mode, "norec", 5))) {
                  ArgusSOptionRecord = 0;
               } else
               if (!(strncasecmp (mode->mode, "nomerge", 7))) {
                  parser->RaCumulativeMerge = 0;
               } else
               if (!(strncasecmp (mode->mode, "merge", 5))) {
                  parser->RaCumulativeMerge = 1;
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

               } else {
                  for (x = 0, i = 0; x < MAX_SORT_ALG_TYPES; x++) {
                     if (!strncmp (ArgusSortKeyWords[x], mode->mode, strlen(ArgusSortKeyWords[x]))) {
                        ArgusSorter->ArgusSortAlgorithms[i++] = ArgusSortAlgorithmTable[x];
                        break;
                     }
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

      if (ArgusCursesEnabled) {
#if defined(ARGUS_CURSES)
         if (!parser->dflag)
            RaInitCurses(parser);
#endif
      }

      /* if content substitution, either time or any field, is used,
         size and count modes will not work properly.  If using
         the default count, set the value so that we generate only
         one filename.

         if no substitution, then we need to add "aa" suffix to the
         output file for count and size modes.
      */

      if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
         struct ArgusWfileStruct *wfile = NULL;
         int count = parser->ArgusWfileList->count;

         if (count > 1)
            usage();

         if ((wfile = (struct ArgusWfileStruct *) ArgusPopFrontList(parser->ArgusWfileList, ARGUS_LOCK)) != NULL) {
            strncpy (outputfile, wfile->filename, MAXSTRLEN);
 
            if ((strchr(outputfile, '%')) || (strchr(outputfile, '$'))) {
               switch (nadp->mode) {
                  case ARGUSSPLITCOUNT:
                     nadp->count = -1;
                     break;

                  case ARGUSSPLITSIZE:
                     for (i = 0; i < nadp->slen; i++) 
                        strcat(outputfile, "a");
                     break;
               }

            } else {
               switch (nadp->mode) {
                  case ARGUSSPLITSIZE:
                  case ARGUSSPLITCOUNT:
                     for (i = 0; i < nadp->slen; i++) 
                        strcat(outputfile, "a");
                     break;
               }
            }

            if (!(strchr(outputfile, '%'))) {
               switch (nadp->mode) {
                  case ARGUSSPLITTIME:
                    break;
               }
            }

            nadp->filename = strdup(outputfile);
            setArgusWfile (parser, outputfile, NULL);
         }
      }

      if (parser->RaTasksToDo == 0) {
         RaTopUpdateInterval.tv_sec  = 1;
         RaTopUpdateInterval.tv_usec = 0;
      } else {
         RaTopUpdateInterval.tv_sec  = 0;
         RaTopUpdateInterval.tv_usec = 453613;
      }

#ifdef ARGUS_CURSES
      if (ArgusCursesEnabled) {
#if defined(ARGUS_THREADS)
            sigset_t blocked_signals;
            sigset_t sigs_to_catch;

            sigfillset(&blocked_signals);
            pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

            if ((pthread_create(&RaCursesThread, NULL, ArgusCursesProcess, NULL)) != 0)
               ArgusLog (LOG_ERR, "ArgusCursesProcess() pthread_create error %s\n", strerror(errno));

            sigemptyset(&sigs_to_catch);
            sigaddset(&sigs_to_catch, SIGHUP);
            sigaddset(&sigs_to_catch, SIGTERM);
            sigaddset(&sigs_to_catch, SIGQUIT);
            sigaddset(&sigs_to_catch, SIGINT);
            pthread_sigmask(SIG_UNBLOCK, &sigs_to_catch, NULL);
#endif
      }
#endif

#if defined(ARGUSMYSQL)
      for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
         if (parser->RaPrintAlgorithmList[i] != NULL) {
            parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[i];
            if (!strncmp(parser->RaPrintAlgorithm->field, "autoid", 6)) {
               ArgusAutoId = 1;
               break;
            }
         }
      }

      if ((ArgusParser->writeDbstr != NULL) || (ArgusParser->readDbstr != NULL)) {
         if (ArgusParser->writeDbstr != NULL) {
            if (strncmp ("mysql:", ArgusParser->writeDbstr, 6))
               ArgusLog (LOG_ERR, "mysql url syntax error");
         }

         if (ArgusParser->readDbstr != NULL)  {
            if (strncmp ("mysql:", ArgusParser->readDbstr, 6))
               ArgusLog (LOG_ERR, "mysql url syntax error");
         }

         RaMySQLInit();
         ArgusParseInit(ArgusParser, NULL);
      }

      if (RaDatabase && RaTable)
         ArgusParser->RaTasksToDo = 1;
#endif

      if (parser->dflag) {
         int pid;
 
         if (parser->Sflag)
            parser->ArgusReliableConnection++;
 
         ArgusLog(LOG_WARNING, "started");
 
         if (chdir ("/") < 0)
            ArgusLog (LOG_ERR, "Can't chdir to / %s", strerror(errno));

         if ((pid = fork ()) < 0) {
            ArgusLog (LOG_ERR, "Can't fork daemon %s", strerror(errno));
         } else {
            if (pid) {
               struct timespec ts = {0, 20000000};
               int status;
               nanosleep(&ts, NULL);
               waitpid(pid, &status, WNOHANG);
               if (kill(pid, 0) < 0) {
                  exit (1);
               } else
                  exit (0);
            } else {
               FILE *tmpfile;
 
               parser->ArgusSessionId = setsid();
 
               if ((tmpfile = freopen ("/dev/null", "r", stdin)) == NULL)
                  ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");
 
               if ((tmpfile = freopen ("/dev/null", "a+", stdout)) == NULL)
                  ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");
 
               if ((tmpfile = freopen ("/dev/null", "a+", stderr)) == NULL)
                  ArgusLog (LOG_ERR, "Cannot map stderr to /dev/null");
            }
         }
      }

      if (ArgusCursesEnabled)
         RaTopLoop (parser);
   }
}


#define ARGUS_FILE_LIST_PROCESSED	0x1000

void
RaTopLoop (struct ArgusParserStruct *parser)
{
   parser->RaParseDone = 0;
   sprintf (parser->RaDebugString, "RaTopLoop() Idle.");

   while (1) {
      if (parser->RaTasksToDo) {
         struct ArgusInput *input = NULL, *file =  NULL;
#if defined(ARGUS_THREADS)
         int hosts = 0;
#endif

         sprintf (parser->RaDebugString, "RaTopLoop() Processing.");
         ArgusInitializeParser(parser);
         RaTopStartTime.tv_sec  = 0;
         RaTopStartTime.tv_usec = 0;
         RaTopStopTime.tv_sec   = 0;
         RaTopStopTime.tv_usec  = 0;

         if ((!(parser->status & ARGUS_FILE_LIST_PROCESSED)) && ((file = parser->ArgusInputFileList) != NULL)) {
            while (file && ArgusParser->eNflag) {
               if (strcmp (file->filename, "-")) {
                  if (file->fd < 0) {
                     if ((file->file = fopen(file->filename, "r")) == NULL) {
                        sprintf (parser->RaDebugString, "open '%s': %s", file->filename, strerror(errno));
                     }

                  } else {
                     fseek(file->file, 0, SEEK_SET);
                  }

                  if ((file->file != NULL) && ((ArgusReadConnection (ArgusParser, file, ARGUS_FILE)) >= 0)) {
                     ArgusParser->ArgusTotalMarRecords++;
                     ArgusParser->ArgusTotalRecords++;

                     if (ArgusParser->RaPollMode) {
                         ArgusHandleDatum (ArgusParser, file, &file->ArgusInitCon, &ArgusParser->ArgusFilterCode);
                     } else {
                        if (file->ostart != -1) {
                           file->offset = file->ostart;
                           if (fseek(file->file, file->offset, SEEK_SET) >= 0)
                              ArgusReadFileStream(ArgusParser, file);
                        } else
                           ArgusReadFileStream(ArgusParser, file);
                     }

                     sprintf (parser->RaDebugString, "RaTopLoop() Processing Input File %s done.", file->filename);

                  } else {
                     file->fd = -1;
                     sprintf (parser->RaDebugString, "ArgusReadConnection '%s': %s", file->filename, strerror(errno));
                  }

                  if (file->file != NULL)
                     ArgusCloseInput(ArgusParser, file);

               } else {
                  file->file = stdin;
                  file->ostart = -1;
                  file->ostop = -1;

                  if (((ArgusReadConnection (ArgusParser, file, ARGUS_FILE)) >= 0)) {
                     ArgusParser->ArgusTotalMarRecords++;
                     ArgusParser->ArgusTotalRecords++;
                     fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);
                     ArgusReadFileStream(ArgusParser, file);
                  }
               }

               RaArgusInputComplete(file);
               file = (struct ArgusInput *)file->qhdr.nxt;
            }

            parser->status |= ARGUS_FILE_LIST_PROCESSED;
         }

         if (ArgusParser->Sflag) {
            if (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0)) {
               struct ArgusQueueStruct *tqueue = ArgusNewQueue();
               int flags;

#if defined(ARGUS_THREADS)
               if (ArgusParser->ArgusReliableConnection) {
                  if (ArgusParser->ArgusRemoteHosts && (hosts = ArgusParser->ArgusRemoteHosts->count)) {
                     if ((pthread_create(&ArgusParser->remote, NULL, ArgusConnectRemotes, ArgusParser->ArgusRemoteHosts)) != 0)
                        ArgusLog (LOG_ERR, "ArgusNewOutput() pthread_create error %s\n", strerror(errno));
                  }

               } else {
#else
               {
#endif
                  while ((input = (void *)ArgusPopQueue(ArgusParser->ArgusRemoteHosts, ARGUS_LOCK)) != NULL) {
                     if ((input->fd = ArgusGetServerSocket (input, 5)) >= 0) {
                        if ((ArgusReadConnection (ArgusParser, input, ARGUS_SOCKET)) >= 0) {
                           ArgusParser->ArgusTotalMarRecords++;
                           ArgusParser->ArgusTotalRecords++;

                           if ((flags = fcntl(input->fd, F_GETFL, 0L)) < 0)
                              ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));

                           if (fcntl(input->fd, F_SETFL, flags | O_NONBLOCK) < 0)
                              ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));

                           if (ArgusParser->RaPollMode)
                              ArgusHandleDatum (ArgusParser, input, &input->ArgusInitCon, &ArgusParser->ArgusFilterCode);

                           ArgusAddToQueue(ArgusParser->ArgusActiveHosts, &input->qhdr, ARGUS_LOCK);
                           ArgusParser->RaTasksToDo++;
                        } else
                           ArgusAddToQueue(tqueue, &input->qhdr, ARGUS_LOCK);
                     } else
                        ArgusAddToQueue(tqueue, &input->qhdr, ARGUS_LOCK);
#if !defined(ARGUS_THREADS)
                  }
#else
                  }
#endif
               }

               while ((input = (void *)ArgusPopQueue(tqueue, ARGUS_LOCK)) != NULL)
                  ArgusAddToQueue(ArgusParser->ArgusRemoteHosts, &input->qhdr, ARGUS_LOCK);

               ArgusDeleteQueue(tqueue);
            }

         } else {
            if (ArgusCursesEnabled) {
#if defined(ARGUSMYSQL)
               if (RaDatabase && RaTable) {
                  struct ArgusRecordStruct *ns = NULL, *tn = NULL;
                  char sbuf[MAXSTRLEN], buf[MAXSTRLEN];
                  struct timeval RaSQLUpdateTime = {0, 0};
                  MYSQL_RES *mysqlRes;

                  RaSQLUpdateDB = 0;
                  bzero(sbuf, sizeof(sbuf));
                  gettimeofday(&ArgusParser->ArgusRealTime, 0);

                  if (strchr(RaTable, '%') || strchr(RaTable, '$')) {
                     char *stbuf = ArgusSQLSaveTableNameBuf, *table;

                     if ((table = ArgusCreateSQLSaveTableName(parser, NULL, RaTable)) != NULL) {
                        if (strncpy(stbuf, table, 1024))
                           ArgusLog (LOG_ERR, "RaTopLoop () strftime %s\n", strerror(errno));

                        RaProcessSplitOptions(parser, stbuf, 1024, ns);
                     }

                  } else
                     sprintf (ArgusSQLSaveTableNameBuf, "%s", RaTable);

                  sprintf (sbuf, "SELECT record FROM %s", ArgusSQLSaveTableNameBuf);
                  if (ArgusParser->ArgusSQLStatement != NULL)
                     sprintf (&sbuf[strlen(sbuf)], " WHERE %s", ArgusParser->ArgusSQLStatement);

                  while (RaTopProcess->queue) {
                     struct timespec ts = {0, 100000000};
                     int retn = 0;

                     if (RaSQLUpdateTime.tv_sec == 0)  
                        RaSQLUpdateTime = ArgusParser->ArgusRealTime;   

                     if ((RaSQLUpdateTime.tv_sec < ArgusParser->ArgusRealTime.tv_sec) ||
                        ((RaSQLUpdateTime.tv_sec == ArgusParser->ArgusRealTime.tv_sec) && 
                         (RaSQLUpdateTime.tv_usec <= ArgusParser->ArgusRealTime.tv_usec))) {
#if defined(ARGUSDEBUG)
                        ArgusDebug (2, "RaTopProcess () fetching %s data\n", RaTable);
#endif

                        RaSQLUpdateTime = ArgusParser->ArgusRealTime;
                        RaSQLUpdateTime.tv_sec  += RaTopUpdateInterval.tv_sec;
                        RaSQLUpdateTime.tv_usec += RaTopUpdateInterval.tv_usec;
                      
                        if (RaSQLUpdateTime.tv_usec >= 1000000) {
                           RaSQLUpdateTime.tv_sec  += 1; 
                           RaSQLUpdateTime.tv_usec -= 1000000;
                        }

#if defined(ARGUS_THREADS)
                        pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
                        while ((ns = (void *)ArgusPopQueue(RaTopProcess->queue, ARGUS_NOLOCK)) != NULL)
                           RaMySQLDeleteRecords(ArgusParser, ns);

                        if (ArgusInput == NULL) {
                           struct timeval now;

                           if ((ArgusInput = (struct ArgusInput *) ArgusCalloc (1, sizeof(struct ArgusInput))) == NULL)
                              ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

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
                        }

                        bzero(sbuf, sizeof(sbuf));
                        gettimeofday(&ArgusParser->ArgusRealTime, 0);

                        if (strchr(RaTable, '%') || strchr(RaTable, '$')) {
                           char *stbuf = ArgusSQLSaveTableNameBuf, *table;

                           if ((table = ArgusCreateSQLSaveTableName(parser, NULL, RaTable)) != NULL) {
                              if (strncpy(stbuf, table, 1024))
                                 ArgusLog (LOG_ERR, "RaTopLoop () strftime %s\n", strerror(errno));

                              RaProcessSplitOptions(parser, stbuf, 1024, ns);
                           }

                        } else
                           sprintf (ArgusSQLSaveTableNameBuf, "%s", RaTable);

                        sprintf (sbuf, "SELECT record FROM %s", ArgusSQLSaveTableNameBuf);
                        if (ArgusParser->ArgusSQLStatement != NULL)
                           sprintf (&sbuf[strlen(sbuf)], " WHERE %s", ArgusParser->ArgusSQLStatement);

                        if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
                           ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));
                        else {
                           if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
                              if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                                 while ((row = mysql_fetch_row(mysqlRes))) {
                                    unsigned long *lengths;
                                    int x;
                
                                    lengths = mysql_fetch_lengths(mysqlRes);
                                    bzero(buf, sizeof(buf));
                               
                                    for (x = 0; x < retn; x++) {
                                       bcopy (row[x], buf, (int) lengths[x]);
                                       if (((struct ArgusRecord *)buf)->hdr.type & ARGUS_FAR) {
#ifdef _LITTLE_ENDIAN 
                                          ArgusNtoH((struct ArgusRecord *) buf);
#endif
                                          if ((ns = ArgusGenerateRecordStruct (ArgusParser, ArgusInput, (struct ArgusRecord *) buf)) != NULL)
                                             if ((tn = ArgusCopyRecordStruct(ns)) != NULL)
                                                ArgusAddToQueue (RaTopProcess->queue, &tn->qhdr, ARGUS_NOLOCK);
                                       }
                                    }
                                 }
                              }
             
                              mysql_free_result(mysqlRes);
                           }
                        }

#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
                        ArgusUpdateScreen();
                     }

                     nanosleep (&ts, 0L);
                     ArgusClientTimeout();
                  }

               } else
#endif
               {
#if defined(ARGUS_THREADS)
                  ArgusParser->RaDonePending++;
                  pthread_cond_signal(&ArgusParser->ArgusOutputList->cond);
#else
                  ArgusParser->RaParseDone++;
#endif
               }
            } else {
               ArgusClientTimeout ();
               return;
            }
         }

         if (ArgusParser->ArgusReliableConnection || ArgusParser->ArgusActiveHosts)
            if (ArgusParser->ArgusActiveHosts->count)
               ArgusReadStream(ArgusParser, ArgusParser->ArgusActiveHosts);

         parser->RaTasksToDo = 0;


      } else {
         struct timespec ts = {0, 25000000};
         gettimeofday (&ArgusCurrentTime, 0L);
         nanosleep (&ts, NULL);

         if (ArgusParser->ArgusActiveHosts->count)
            parser->RaTasksToDo = 1;
      }

      ArgusClientTimeout ();
   }
}

void RaArgusInputComplete (struct ArgusInput *input) {
   ArgusUpdateScreen();
#if !defined(ARGUS_THREADS)
   RaRefreshDisplay(ArgusParser);
#endif
}


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
#if defined(ARGUSMYSQL)
      if (!ArgusParser->RaParseCompleting++) {
         int i, retn;
         char *str = NULL;

         if (RaSQLUpdateDB) {
            if (ArgusDeleteTable) {
               for (i = 0; i < RA_MAXTABLES; i++) {
                  if ((str = RaTableDeleteString[i]) != NULL) {
#ifdef ARGUSDEBUG
                     ArgusDebug (2, "deleting table %s\n", str);
#endif
                     if ((retn = mysql_real_query(&mysql, str, strlen(str))) != 0)
                        ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));
                  }
               }

            } else {
               ArgusParser->RaClientUpdate.tv_sec = 1;
               ArgusClientTimeout();

               if (ArgusSQLBulkBufferIndex > 0) {
                  if (mysql_real_query(&mysql, ArgusSQLBulkBuffer, ArgusSQLBulkBufferIndex) != 0)
                     ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));
                  ArgusSQLBulkBufferIndex = 0;
               }
            }

         } else {
         }

         mysql_close(&mysql);
#endif
         if (sig == SIGINT) {
            ArgusShutDown(0);
            exit(0);
         }
      }
   }
}

void
RaResizeHandler (int sig)
{
#ifdef ARGUS_CURSES
   RaScreenResize = TRUE;
#endif

#ifdef ARGUSDEBUG 
   ArgusDebug (1, "RaResizeHandler(%d)\n", sig);
#endif
}


char *ArgusGenerateProgramArgs(struct ArgusParserStruct *);
char RaProgramArgs[MAXSTRLEN];

char *
ArgusGenerateProgramArgs(struct ArgusParserStruct *parser)
{
   char *retn = RaProgramArgs;
   struct ArgusModeStruct *mode = NULL;
   struct ArgusInput *input = NULL;
   
   sprintf (retn, "%s ", parser->ArgusProgramName);

   if (parser->ArgusActiveHosts) {
      if (parser->Sflag) {
         sprintf (&retn[strlen(retn)], "-S ");

         if ((input = (void *)parser->ArgusActiveHosts->start) != NULL) {
            do {
               if (parser->Sflag)
                  sprintf (&retn[strlen(retn)], "%s:%d ", input->hostname, input->portnum);
               else
                  sprintf (&retn[strlen(retn)], "%s ", input->filename);
               input = (void *)input->qhdr.nxt;
            } while (input != (void *)parser->ArgusActiveHosts->start);
         }

      } else {
         struct ArgusInput *file =  NULL;

         if ((!(parser->status & ARGUS_FILE_LIST_PROCESSED)) && ((file = parser->ArgusInputFileList) != NULL)) {
            sprintf (&retn[strlen(retn)], "-r ");
            while (file) {
               sprintf (&retn[strlen(retn)], "%s ", file->filename);
               file = (void *)file->qhdr.nxt;
            }
         }
      }


   }

   if (RaDatabase && RaTable) {
      if (ArgusParser->readDbstr != NULL) {
         sprintf (&retn[strlen(retn)], "-r %s/%s ", ArgusParser->readDbstr, ArgusSQLSaveTableNameBuf);
      }
      if (ArgusParser->writeDbstr != NULL)
         sprintf (&retn[strlen(retn)], "-w %s/%s ", ArgusParser->writeDbstr, RaSQLCurrentTable);
   }

   if ((mode = parser->ArgusModeList) != NULL) { 
      sprintf (&retn[strlen(retn)], "-M ");
      while (mode) { 
         sprintf (&retn[strlen(retn)], "%s ", mode->mode);
         mode = mode->nxt;
      }
   }

   if (((mode = parser->ArgusMaskList) != NULL) || (parser->ArgusAggregator->mask == 0)) {
      sprintf (&retn[strlen(retn)], "-m ");
      while (mode) {
         sprintf (&retn[strlen(retn)], "%s ", mode->mode);
         mode = mode->nxt;
      }
   }

   if (parser->Hstr)
      sprintf (&retn[strlen(retn)], "-H %s ", parser->Hstr);

   if ((parser->ArgusDisplayFilter) || parser->ArgusLocalFilter || parser->ArgusRemoteFilter) {
      sprintf (&retn[strlen(retn)], "- ");
      if (parser->ArgusDisplayFilter)
         sprintf (&retn[strlen(retn)], "display '%s' ", parser->ArgusDisplayFilter);
      if (parser->ArgusLocalFilter)
         sprintf (&retn[strlen(retn)], "local '%s' ", parser->ArgusLocalFilter);
      if (parser->ArgusRemoteFilter) 
         sprintf (&retn[strlen(retn)], "remote '%s' ", parser->ArgusRemoteFilter);
   }
   return (retn);
}


void RaTopSortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *, int);
int RaSortItems = 0;
 
void
RaTopSortQueue (struct ArgusSorterStruct *sorter, struct ArgusQueueStruct *queue, int type)
{
   struct nff_insn *fcode = NULL;
   int i = 0, x = 0, cnt;

#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_lock(&queue->lock);
#endif

   cnt = queue->count;

   if (queue->array != NULL) {
      ArgusFree(queue->array);
      queue->array = NULL;
   } 

   if (cnt > 0) {
      fcode = sorter->filter.bf_insns;
      if ((queue->array = (struct ArgusQueueHeader **) ArgusCalloc(1, sizeof(struct ArgusQueueHeader *) * (cnt + 1))) != NULL) {
         struct ArgusQueueHeader *qhdr = queue->start;

         if (qhdr != NULL) {
            for (i = 0; i < cnt; i++) {
               int keep = 0;

               if (fcode) {
                  if (ArgusFilterRecord (fcode, (struct ArgusRecordStruct *)qhdr) != 0)
                     keep = 1;
               } else
                  keep = 1;
      
               if (keep) {
                  if (qhdr->queue != queue) {
                     ArgusLog (LOG_WARNING, "ArgusSortQueue: qhdr 0x%x not in queue 0x%x\n", qhdr, queue);
                  }
                  queue->array[x++] = qhdr;
               }

               qhdr = qhdr->nxt;
            }
         }

         
         queue->array[x] = NULL;

         if (x > 1)
            qsort ((char *) queue->array, x, sizeof (struct ArgusQueueHeader *), ArgusSortRoutine);

      } else 
         ArgusLog (LOG_ERR, "ArgusSortQueue: ArgusMalloc(%d) %s\n", sizeof(struct ArgusRecord *), cnt, strerror(errno));
   }

   RaSortItems = x;
   bzero (&ArgusParser->ArgusStartTimeVal, sizeof(ArgusParser->ArgusStartTimeVal));

#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_unlock(&queue->lock);
#endif

#ifdef ARGUSDEBUG 
   ArgusDebug (5, "ArgusSortQueue(0x%x, 0x%x, %d) returned\n", sorter, queue, type);
#endif
}


#if defined(ARGUS_CURSES)
void RaUpdateWindow (struct ArgusParserStruct *, WINDOW *, struct ArgusQueueStruct *);

void
RaUpdateWindow (struct ArgusParserStruct *parser, WINDOW *window, struct ArgusQueueStruct *queue)
#else
void RaUpdateWindow (struct ArgusParserStruct *, struct ArgusQueueStruct *);

void
RaUpdateWindow (struct ArgusParserStruct *parser, struct ArgusQueueStruct *queue)
#endif
{
#if defined(ARGUS_CURSES)
   struct ArgusRecordStruct *ns = NULL;
   char buf[MAXSTRLEN], tbuf[MAXSTRLEN];
   int x, cnt, attr = A_NORMAL, z;
#endif
   int i;

   if (RaWindowModified) {
      parser->RaLabel = NULL;
      if (RaWindowStatus) {
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&queue->lock);
#endif
         if (queue->count) {
            RaTopSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);

            if (RaSortItems) {
               if (ArgusParser->ns) {
                  ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                  ArgusParser->ns = NULL;
               }
               for (i = 0; i < queue->count; i++) {
                  struct ArgusRecordStruct *ns;
                  if ((ns = (struct ArgusRecordStruct *)queue->array[i]) != NULL) {
                     if (ArgusParser->ns)
                        ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
                     else
                        ArgusParser->ns = ArgusCopyRecordStruct (ns);
                  }
               }
            }
         }

#ifdef ARGUS_CURSES
         if (!ArgusParser->dflag) {
            if (queue->array != NULL) {
               double value;

               if (parser->ns != NULL) {
                  if (parser->RaLabel == NULL)
                     parser->RaLabel = ArgusGenerateLabel(parser, parser->ns);
                  if (ArgusPrintRank)
                     snprintf (tbuf, RaScreenColumns, "%*s %s", ArgusRankSize, "Rank", parser->RaLabel);
                  else
                     snprintf (tbuf, RaScreenColumns, "%s", parser->RaLabel);
                  mvwaddnstr (window, 0, 0, tbuf, RaScreenColumns);
                  wclrtoeol(window);
               }

               if (queue->count < RaWindowStartLine) {
                  RaWindowStartLine = queue->count - RaDisplayLines;
                  RaWindowStartLine = (RaWindowStartLine > 0) ? RaWindowStartLine : 0;
               }

               cnt = ((RaDisplayLines > 0) ? RaDisplayLines : RaWindowLines);
               cnt = (cnt > (queue->count - RaWindowStartLine)) ? (queue->count - RaWindowStartLine) : cnt;
               attr = A_NORMAL;

               value = log10(queue->count);
               ArgusRankSize = (value > 4) ? value + 1 : 4;

               for (x = 0, z = 0, i = RaWindowStartLine; x < cnt; x++, i++) {
                  if ((ns = (struct ArgusRecordStruct *) queue->array[i]) != NULL) {
                     int slen;
                     z++;
                     *(unsigned int *)buf = 0;
                     ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                     if (ArgusPrintRank)
                        snprintf (tbuf, RaScreenColumns, "%*d %s", ArgusRankSize, i + 1, buf);
                     else
                        snprintf (tbuf, RaScreenColumns, "%s", buf);

                     slen = strlen(tbuf);
                     mvwaddnstr (window, x + 1, 0, tbuf, (slen > RaScreenColumns) ? RaScreenColumns : slen);
                     wclrtoeol(window);
                  }
               }

               wclrtoeol(RaWindow);

            } else {
               mvwaddstr (window, 1, 0, " ");
               wclrtoeol(window);
            }

            wclrtobot(window);
         }
#endif
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&queue->lock);
#endif
      }
#ifdef ARGUS_CURSES
      if (!ArgusParser->dflag)
         wnoutrefresh(window);
#endif
   }
   RaWindowModified  = 0;
   RaWindowImmediate = FALSE;
}

int ArgusSourceConnected = 0;

void
RaRefreshDisplay(struct ArgusParserStruct *parser)
{
   struct timeval tvp;
#if defined(ARGUS_CURSES)
   char stimebuf[128], tbuf[MAXSTRLEN];
   char strbuf[128];  
   struct tm *tm, tmbuf;
   float secs, rate;
#endif

   tvp = parser->ArgusRealTime;

   if (RaTopUpdateTime.tv_sec == 0)
      RaTopUpdateTime = tvp;
   
   if (RaWindowImmediate ||
      ((RaTopUpdateTime.tv_sec < tvp.tv_sec) ||
      ((RaTopUpdateTime.tv_sec == tvp.tv_sec) &&
       (RaTopUpdateTime.tv_usec <= tvp.tv_usec)))) {

      if (RaWindowModified) {
         int i;

#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
         RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
         if (RaSortItems) {
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < RaTopProcess->queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)RaTopProcess->queue->array[i]) == NULL)
                  break;

               if (ArgusParser->ns) 
                  ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
         }

#if defined(ARGUSMYSQL)
         if (RaSQLUpdateDB && RaSQLCurrentTable) {
            char sbuf[MAXSTRLEN];
  
            if (RaTopProcess->queue->array != NULL) {
               for (i = 0; i < RaTopProcess->queue->count; i++) {
                  struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *)RaTopProcess->queue->array[i];
  
                  if (ns && (ns->status & ARGUS_RECORD_MODIFIED)) {
                     ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, ns, sbuf, ARGUS_STATUS);
                     ns->status &= ~ARGUS_RECORD_MODIFIED;
                  }
               }
            }
         }

#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif

         if (!ArgusParser->dflag)
#if defined(ARGUS_CURSES)
            RaUpdateWindow(parser, RaAvailableWindow, RaTopProcess->queue);
#else
            RaUpdateWindow(parser, RaTopProcess->queue);
#endif
#endif

#if defined(ARGUSDEBUG)
         ArgusDebug (9, "RaRefreshDisplay (0x%x) queue processed", parser); 
#endif
      }

      RaTopUpdateTime = tvp;

      RaTopUpdateTime.tv_sec  += RaTopUpdateInterval.tv_sec;
      RaTopUpdateTime.tv_usec += RaTopUpdateInterval.tv_usec;

      if (RaTopUpdateTime.tv_usec >= 1000000) {
         RaTopUpdateTime.tv_sec  += 1;
         RaTopUpdateTime.tv_usec -= 1000000;
      }

#if defined(ARGUS_CURSES)
      if (!ArgusParser->dflag) {
         RaWindowImmediate = FALSE;

         if (parser->ArgusRealTime.tv_sec > 0) {
            time_t tsec =  parser->ArgusRealTime.tv_sec;
            tm = localtime_r(&tsec, &tmbuf);
            strftime ((char *) stimebuf, 32, "%Y/%m/%d.%T", tm);
            sprintf ((char *)&stimebuf[strlen(stimebuf)], " ");
            strftime(&stimebuf[strlen(stimebuf)], 32, "%Z ", tm);

         } else 
            sprintf (stimebuf, " ");

         mvwprintw (RaWindow, RaScreenLines - 1, 0, "\n");
         mvwaddnstr (RaHeaderWindow, 0, 0, ArgusGenerateProgramArgs(ArgusParser), RaScreenColumns - 5);
         wclrtoeol(RaHeaderWindow);
         mvwaddnstr (RaHeaderWindow, 0, RaScreenColumns - strlen(stimebuf) , stimebuf, strlen(stimebuf));

         if (ArgusPrintTotals) {
            if (parser->ns != NULL) {
               char buf[MAXSTRLEN];
               bzero (buf, 16);
               ArgusPrintRecord(parser, buf, parser->ns, MAXSTRLEN);
               if (ArgusPrintRank)
                  snprintf (tbuf, RaScreenColumns, "%*d %s", ArgusRankSize, RaTopProcess->queue->count, buf);
               else
                  snprintf (tbuf, RaScreenColumns, "%s", buf);
            } else
               sprintf (tbuf, " ");

            mvwaddnstr (RaHeaderWindow, 1, 0, tbuf, RaScreenColumns);
            wclrtoeol(RaHeaderWindow);
         }
/*
         if (parser->ArgusCurrentInput) {
            float secs, rate;
            char srcstr[128], *ptr;

            if (RaProbeUptime.tv_sec == 0) {
               start->tv_sec  = parser->ArgusCurrentInput->ArgusInitCon.argus_mar.startime.tv_sec;
               start->tv_usec = parser->ArgusCurrentInput->ArgusInitCon.argus_mar.startime.tv_usec;

               last->tv_sec   = parser->ArgusCurrentInput->ArgusInitCon.argus_mar.now.tv_sec;
               last->tv_usec  = parser->ArgusCurrentInput->ArgusInitCon.argus_mar.now.tv_usec;

               tvp.tv_sec  = last->tv_sec  - start->tv_sec;
               tvp.tv_usec = last->tv_usec - start->tv_usec;

               if (tvp.tv_usec < 0) {
                  tvp.tv_sec--;
                  tvp.tv_usec += 1000000;
               }
               if (tvp.tv_usec >= 1000000) {
                  tvp.tv_sec++;
                  tvp.tv_usec -= 1000000;
               }
               RaProbeUptime = tvp;
            }


            ptr = parser->ArgusCurrentInput->hostname ?
                  parser->ArgusCurrentInput->hostname :
                  parser->ArgusCurrentInput->filename ;

            if (!(ArgusSourceConnected)) {
               ArgusSourceConnected++;
               sprintf (parser->RaDebugString, "Source Connected %s", ptr);
            }

            if (ptr != NULL) {
               sprintf (srcstr, "%s", ptr);
               srcstr[64] = '\0';
            } else {
               srcstr[0] = '\0';
            }
            sprintf (tbuf, "Source %s  Version %d.%d  Queue %6d Display %6d TotalRecords %8lld  Rate %11.4f rps",
                                srcstr, parser->ArgusCurrentInput->ArgusInitCon.argus_mar.major_version,
                                parser->ArgusCurrentInput->ArgusInitCon.argus_mar.minor_version,
                                RaTopProcess->queue->count, RaSortItems,
                                parser->ArgusTotalRecords, rate/secs);

            if (ArgusDisplayStatus)
               sprintf (parser->RaDebugString, "%s", tbuf);

         } else {
            if (ArgusSourceConnected) {
               ArgusSourceConnected = 0;
               sprintf (parser->RaDebugString, "No Source Connected");
            }
         }
*/

         if (ArgusDisplayStatus) {
            struct timeval dtime;

            dtime.tv_sec   = RaTopStopTime.tv_sec  - RaTopStartTime.tv_sec;
            dtime.tv_usec  = RaTopStopTime.tv_usec - RaTopStartTime.tv_usec;

            if (dtime.tv_usec < 0) {
               dtime.tv_sec--;
               dtime.tv_usec += 1000000;
            }

            secs = (dtime.tv_sec * 1.0) + ((dtime.tv_usec * 1.0)/1000000.0);
            rate = (parser->ArgusTotalRecords * 1.0); 

            sprintf (tbuf, "ProcessQueue %6d DisplayQueue %6d TotalRecords %8lld  Rate %11.4f rps",
                                RaTopProcess->queue->count, RaSortItems,
                                parser->ArgusTotalRecords, rate/secs);

               sprintf (parser->RaDebugString, "%s", tbuf);
         }

         sprintf (strbuf, "%s", parser->RaDebugString);
         mvwaddnstr (RaWindow, RaScreenLines - 1, 0, strbuf, RaScreenColumns);
         wclrtoeol(RaWindow);
      }
#endif
   }

#if defined(ARGUS_CURSES)
   if (!ArgusParser->dflag && ArgusCursesEnabled) {
      if (RaWindowStatus) {
         wclrtoeol(RaAvailableWindow);
         wnoutrefresh(RaAvailableWindow);
      }

      wnoutrefresh(RaHeaderWindow);

      if (RaCursorWindow == NULL)
         RaCursorWindow = RaHeaderWindow;

      switch (RaInputStatus) {
         case RAGETTINGcolon:
         case RAGETTINGslash:
            wmove(RaWindow, RaScreenLines - 2, RaCommandIndex + 1);
            break;

         case RAGOTslash:
         case RAGOTcolon:
            if (RaWindowCursorY > 0) {
               int offset = (RaWindowCursorY % (RaDisplayLines + 1));
               if (offset > (RaSortItems - RaWindowStartLine)) {
                  RaWindowCursorY = (RaSortItems - RaWindowStartLine);
                  offset = (RaSortItems - RaWindowStartLine);
               }
               offset += RaHeaderWinSize;
               wmove (RaWindow, offset, RaWindowCursorX + (ArgusPrintRank ? ArgusRankSize + 1 : 1));
            } else {
               wmove(RaWindow, RaScreenLines - 1, 0);
            }
            break;

         default: {
            int len =  strlen(RaInputString);
            if (len > 0)
               wmove(RaWindow, RaScreenLines - 2, (RaCommandIndex - RaCursorOffset) + len);
            break;
         }
      }

      wrefresh(RaWindow);
      doupdate();
   }
#endif

#if defined(ARGUSDEBUG)
   ArgusDebug (3, "ArgusRefreshDisplay (0x%x) screen %d display %d", parser, RaScreenLines, RaDisplayLines); 
#endif
}


int
RaSearchDisplay (struct ArgusParserStruct *parser, struct ArgusQueueStruct *queue, 
                                 int dir, int *cursx, int *cursy, char *pattern)
{
   int retn = -1, x = 0, startline = *cursy;
   regmatch_t pm[1];
   struct ArgusRecordStruct *ns = NULL;
   regex_t pregbuf, *preg = &pregbuf;
   char buf[MAXSTRLEN], *ptr;

   if (regcomp(preg, pattern, REG_EXTENDED | REG_NEWLINE)) {
      sprintf (ArgusParser->RaDebugString, "RaSearchDisplay bad regular expression %s", pattern);
      return retn;
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&queue->lock);
#endif
   if (queue->array != NULL) {
      if (startline == 0) {
         *cursy = 1; startline = 1;
      }
  
      startline = (startline == 0) ? 1 : startline;
      if (queue->count >= startline) {
         if ((ns = (struct ArgusRecordStruct *) queue->array[startline - 1]) != NULL) {
            int offset = *cursx, found = 0;

            *(unsigned int *)buf = 0;
            ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);

            switch (dir) {
               case ARGUS_FORWARD:
                  if (regexec(preg, &buf[offset], 1, pm, 0) == 0) {
                     if (pm[0].rm_so == 0) {
                        if (regexec(preg, &buf[offset + 1], 1, pm, 0) == 0) {
                           offset += pm[0].rm_so + 1;
                           found++;
                        }
                     } else {
                        offset += pm[0].rm_so;
                        found++;
                     }
                     if (found) {
                        retn = *cursy;
                        *cursx = offset;
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&queue->lock);
#endif
                        return (retn);
                     }
                  }
                  break;

               case ARGUS_BACKWARD: {
                  char *lastmatch = NULL;
                  buf[offset] = '\0';
                  ptr = buf;
                  while ((ptr = strstr(ptr, pattern)) != NULL)
                     lastmatch = ptr++;

                  if (lastmatch) {
                     retn = *cursy;
                     *cursx = (lastmatch - buf);
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&queue->lock);
#endif
                     return (retn);
                  }
                  break;
               }
            }
         }

         switch (dir) {
            case ARGUS_FORWARD:
               for (x = startline; x < queue->count; x++) {
                  if ((ns = (struct ArgusRecordStruct *) queue->array[x]) != NULL) {
                     *(unsigned int *)buf = 0;
                     ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
      
                     if ((retn = regexec(preg, buf, 1, pm, 0)) == 0) {
                        retn = x + 1;
                        *cursx = pm[0].rm_so;
                        *cursy = retn;
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&queue->lock);
#endif
                        return (retn);
                        break;
                     }
                  }
               }
               break;

            case ARGUS_BACKWARD: {
               for (x = (startline - 2); x >= 0; x--) {
                  if ((ns = (struct ArgusRecordStruct *) queue->array[x]) != NULL) {
                     char *lastmatch = NULL;
                     *(unsigned int *)buf = 0;

                     ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);

                     ptr = buf;
                     while ((ptr = strstr(ptr, pattern)) != NULL)
                        lastmatch = ptr++;

                     if (lastmatch) {
                        retn = x + 1;
                        *cursx = (lastmatch - buf);
                        *cursy = retn;
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&queue->lock);
#endif
                        return (retn);
                     }
                  }
               }
               break;
            }
         }
      }
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&queue->lock);
#endif

   return (-1);
}

int ArgusProcessQueue (struct ArgusQueueStruct *, struct timeval *);
int ArgusProcessBins (struct ArgusRecordStruct *, struct RaBinProcessStruct *);
struct RaBinProcessStruct *ArgusNewRateBins (struct ArgusParserStruct *, struct ArgusRecordStruct *);


struct RaBinProcessStruct *
ArgusNewRateBins (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct RaBinProcessStruct *retn = NULL;

   if ((retn = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewRateBins: ArgusCalloc error %s", strerror(errno));
                        
   bcopy ((char *)RaBinProcess, (char *)retn, sizeof (*retn));

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&retn->lock, NULL);
#endif

   retn->nadp.RaStartTmStruct = RaBinProcess->nadp.RaStartTmStruct;
   retn->nadp.RaEndTmStruct   = RaBinProcess->nadp.RaEndTmStruct;

   retn->startpt.tv_sec = mktime(&RaBinProcess->nadp.RaStartTmStruct);
   retn->endpt.tv_sec   = mktime(&RaBinProcess->nadp.RaEndTmStruct);

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusNewRateBins (0x%x, 0x%x) returning %d", parser, ns, retn); 
#endif

   return(retn);
}


void ArgusShiftArray (struct ArgusParserStruct *, struct RaBinProcessStruct *);

int
ArgusProcessBins (struct ArgusRecordStruct *ns, struct RaBinProcessStruct *rbps)
{
   int retn = 0;
   int cnt   = (rbps->arraylen - rbps->index);
   int dtime = cnt * rbps->size;
   int rtime = (((ArgusParser->ArgusGlobalTime.tv_sec/rbps->size)) * rbps->size);

   if ((rbps->startpt.tv_sec + dtime) < rtime) {
      ArgusShiftArray(ArgusParser, rbps);
      ArgusUpdateScreen();

      rbps->status |= RA_DIRTYBINS;
      retn = 1;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessBins (0x%x, 0x%x) returning %d", ns, rbps, retn); 
#endif

   return (retn);
}


int
ArgusProcessQueue (struct ArgusQueueStruct *queue, struct timeval *ts)
{
   struct timeval tbuf, *tvp = &tbuf;
   int retn = 0, x, z;

   if ((ArgusParser->timeout.tv_sec) || (ArgusParser->timeout.tv_usec)) {
      struct ArgusRecordStruct *ns;
      struct timeval lasttime;
      int count, deleted = 0;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock);
#endif
      count = queue->count;

      for (x = 0, z = count; x < z; x++) {
         if ((ns = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
            lasttime = ns->qhdr.lasttime;
            *tvp = lasttime;
            tvp->tv_sec  += ArgusParser->timeout.tv_sec;
            tvp->tv_usec += ArgusParser->timeout.tv_usec;

            if (tvp->tv_usec > 1000000) {
               tvp->tv_sec++;
               tvp->tv_usec -= 1000000;
            }

            if ((tvp->tv_sec  < ts->tv_sec) ||
               ((tvp->tv_sec == ts->tv_sec) && (tvp->tv_usec < ts->tv_usec))) {

               retn++;

               if (!(ns->status & ARGUS_NSR_STICKY)) {
                  RaMySQLDeleteRecords(ArgusParser, ns);
                  deleted++;

               } else {
                  ArgusZeroRecord (ns);
                  ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
                  ns->qhdr.lasttime = lasttime;
               }

            } else {
               struct RaBinProcessStruct *rbps;
               int i, y;

               if ((rbps = ns->bins) != NULL) {
                  ArgusProcessBins (ns, rbps);
                  if (rbps->status & RA_DIRTYBINS) {
                     ArgusZeroRecord (ns);
                     for (i = rbps->index; i < rbps->arraylen; i++) {
                        struct RaBinStruct *bin;
                        if (((bin = rbps->array[i]) != NULL) && (bin->agg->queue != NULL)) {
                           struct ArgusRecordStruct *tns  = (struct ArgusRecordStruct *)bin->agg->queue->start;
                           for (y = 0; y < bin->agg->queue->count; y++) {
                              ArgusMergeRecords (ArgusParser->ArgusAggregator, ns, tns);
                              tns = (struct ArgusRecordStruct *)tns->qhdr.nxt;
                           }
                        }
                     }

                     ns->status |= ARGUS_RECORD_MODIFIED;
                     rbps->status &= ~RA_DIRTYBINS;
                     retn++;
                  }
               }
               ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
               ns->qhdr.lasttime = lasttime;
            }
         }
      }

      if (deleted) {
/*
         RaTopSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);
*/
         ArgusUpdateScreen();
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "ArgusProcessQueue (0x%x) returning %d", queue, retn); 
#endif

   return (retn);
}


extern void ArgusCloseInput(struct ArgusParserStruct *parser, struct ArgusInput *);
struct timeval RaProcessQueueTimer = {0, 250000};
void RaResizeScreen(void);

void
ArgusClientTimeout ()
{
   if (RaTopProcess != NULL) {
   struct ArgusQueueStruct *queue = RaTopProcess->queue;
      struct timeval tvbuf, *tvp = &tvbuf;

      gettimeofday(&ArgusParser->ArgusRealTime, 0);
      ArgusAdjustGlobalTime (ArgusParser, &ArgusParser->ArgusRealTime);

      *tvp = ArgusParser->ArgusGlobalTime;

      if (ArgusParser->RaClientUpdate.tv_sec != 0) {
         if (((ArgusParser->RaClientUpdate.tv_sec < tvp->tv_sec) ||
             ((ArgusParser->RaClientUpdate.tv_sec == tvp->tv_sec) &&
              (ArgusParser->RaClientUpdate.tv_usec < tvp->tv_usec)))) {

            if (ArgusParser->status & ARGUS_REAL_TIME_PROCESS) {
               if (ArgusProcessQueue(queue, tvp)) 
                  ArgusUpdateScreen();
            } else {
               if (ArgusProcessQueue(queue, &ArgusParser->ArgusRealTime)) 
                  ArgusUpdateScreen();
            }

            ArgusParser->RaClientUpdate.tv_sec  += RaProcessQueueTimer.tv_sec;
            ArgusParser->RaClientUpdate.tv_usec += RaProcessQueueTimer.tv_usec;

            while (ArgusParser->RaClientUpdate.tv_usec > 1000000) {
               ArgusParser->RaClientUpdate.tv_sec++;
               ArgusParser->RaClientUpdate.tv_usec -= 1000000;
            }
         }

#if defined(ARGUS_THREADS)
      if (ArgusParser->dflag || !(ArgusCursesEnabled))
         RaRefreshDisplay(ArgusParser);
#else
#if defined(ARGUS_CURSES)
         if (!ArgusParser->dflag)
            ArgusCursesProcess(NULL);
         else
            RaRefreshDisplay(ArgusParser);
#endif
#endif

      } else
         ArgusParser->RaClientUpdate.tv_sec = ArgusParser->ArgusGlobalTime.tv_sec;

      if (ArgusSQLQueryList != NULL) {
          struct ArgusSQLQueryStruct *sqry = NULL;
          char *sptr = NULL;
          int slen;

          while (!(ArgusListEmpty(ArgusSQLQueryList))) {
             if ((sqry = (void *) ArgusPopFrontList(ArgusSQLQueryList, ARGUS_LOCK)) != NULL) {
                if ((sptr = sqry->sptr) != NULL) {
                   slen = strlen(sptr);
#if defined(ARGUSDEBUG)
                   if (sqry->dptr != NULL)
                      ArgusDebug (4, "ArgusSQLQuery (%s)\n", sqry->dptr);
                   else
                      ArgusDebug (4, "ArgusSQLQuery (%s)\n", sqry->sptr);
#endif

                   if (ArgusSQLBulkBuffer != NULL) {
                      char *tptr = sptr;

                      if ((strncmp("INSERT", tptr, 6))) {
                         if (ArgusSQLBulkBufferIndex > 0) {
                            if (mysql_real_query(&mysql, ArgusSQLBulkBuffer, ArgusSQLBulkBufferIndex) != 0)
                               ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));

                            if (ArgusSQLBulkLastTable) {
                               free(ArgusSQLBulkLastTable);
                               ArgusSQLBulkLastTable   = NULL;
                            }
                            ArgusSQLBulkBufferIndex = 0;
                         }

                         if (mysql_real_query(&mysql, tptr, slen) != 0)
                            ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));

                      } else {
                         if (ArgusSQLBulkLastTable) {
                            if ((strncmp(ArgusSQLBulkLastTable, sqry->tbl, strlen(sqry->tbl))) ||
                               ((ArgusSQLBulkBufferIndex + slen) > ArgusSQLBulkInsertSize)) {
                               if (mysql_real_query(&mysql, ArgusSQLBulkBuffer, ArgusSQLBulkBufferIndex) != 0)
                                  ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));

                               if (ArgusSQLBulkLastTable) {
                                  free(ArgusSQLBulkLastTable);
                                  ArgusSQLBulkLastTable   = NULL;
                               }
                               ArgusSQLBulkBufferIndex = 0;
                            }
                         }

                         if (ArgusSQLBulkBufferIndex > 0) {
                            char *vptr = strstr(tptr, "VALUES (");
                            if (vptr != NULL) {
                               if ((vptr = strchr(vptr, '(')) != NULL)  {
                                  tptr = vptr;
                                  slen = strlen(tptr);
                                  sprintf(&ArgusSQLBulkBuffer[ArgusSQLBulkBufferIndex++], ",");
                               }
                            }
                         }
                         bcopy(tptr, &ArgusSQLBulkBuffer[ArgusSQLBulkBufferIndex], slen);
                         ArgusSQLBulkBufferIndex += slen;
                         if (ArgusSQLBulkLastTable == NULL)
                            ArgusSQLBulkLastTable = strdup(sqry->tbl);
                      }

                   } else
                      if (mysql_real_query(&mysql, sptr, slen) != 0)
                         ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));

                   free(sptr);
                   if (sqry->dptr != NULL)
                      free(sqry->dptr);
                   if (sqry->tbl != NULL)
                      free(sqry->tbl);
                }
                ArgusFree(sqry);
             }
          }
          if (ArgusSQLBulkBufferIndex > 0) {
             if (mysql_real_query(&mysql, ArgusSQLBulkBuffer, ArgusSQLBulkBufferIndex) != 0)
                ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));

             ArgusSQLBulkBufferIndex = 0;
             if (ArgusSQLBulkLastTable) {
                free(ArgusSQLBulkLastTable);
                ArgusSQLBulkLastTable = NULL;
             }
          }
       }
    }
   
#if defined(ARGUSDEBUG)
   ArgusDebug (12, "ArgusClientTimeout () returning\n"); 
#endif
}

void
ArgusUpdateScreen(void)
{
   RaWindowModified  = RA_MODIFIED;
   RaWindowImmediate = TRUE;
}

char RaLastSearchBuf[MAXSTRLEN], *RaLastSearch = RaLastSearchBuf;
char RaLastCommandBuf[MAXSTRLEN], *RaLastCommand = RaLastCommandBuf;
int RaIter = 1, RaDigitPtr = 0;
char RaDigitBuffer[16];

int ArgusProcessCommand (struct ArgusParserStruct *, int, int);

#if defined(ARGUS_CURSES)
void *
ArgusCursesProcess (void *arg)
{
   struct ArgusQueueStruct *queue = RaTopProcess->queue;
   char RaOutputBuffer[MAXSTRLEN];
   struct timeval tvbuf, *tvp = &tvbuf;
   int i = 0, ch;
   fd_set in;
#if defined(ARGUS_THREADS)
   sigset_t sigs_to_catch;
   int done = 0;
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusCursesProcess() starting");
#endif
   bzero(RaDigitBuffer, sizeof(RaDigitBuffer));
   bzero(RaLastSearchBuf, sizeof(RaLastSearchBuf));

#if defined(ARGUS_THREADS)

#if defined(ARGUSMYSQL)
   mysql_thread_init();
#endif

   sigemptyset(&sigs_to_catch);
   sigaddset(&sigs_to_catch, SIGWINCH);
   pthread_sigmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

   while (!done) {
#endif
      if ((RaScreenResize == TRUE) || ((RaScreenLines != RaScreenLines) || (RaScreenColumns != RaScreenColumns))) {
         RaResizeScreen();
         ArgusUpdateScreen();

#if defined(ARGUS_READLINE)
         rl_set_screen_size(RaScreenLines - 2, RaScreenColumns);
#endif
      }

      if (RaWindowModified) {
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&queue->lock);
#endif
         RaTopSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);
         if (RaSortItems) {
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns) 
                  ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
         }
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&queue->lock);
#endif
      }

      if (!(ArgusParser->RaTasksToDo)) {
         gettimeofday(&ArgusLastTime, 0);
         ArgusLastTime.tv_usec = 0;

      } else {
         if (ArgusCurrentTime.tv_sec != 0) {
            long long tUsec = 0;
            gettimeofday(&ArgusParser->ArgusRealTime, 0);

            if (ArgusLastRealTime.tv_sec > 0) {
               struct timeval dTime;

               dTime = *RaDiffTime(&ArgusParser->ArgusRealTime, &ArgusLastRealTime);
               tUsec = ((dTime.tv_sec * 1000000) + dTime.tv_usec) * RaUpdateRate;
               dTime.tv_sec  = tUsec / 1000000;
               dTime.tv_usec = tUsec % 1000000;

               ArgusCurrentTime.tv_sec  = ArgusLastTime.tv_sec  + dTime.tv_sec;
               ArgusCurrentTime.tv_usec = ArgusLastTime.tv_usec + dTime.tv_usec;

               if (ArgusCurrentTime.tv_usec > 1000000) {
                  ArgusCurrentTime.tv_sec++;
                  ArgusCurrentTime.tv_usec -= 1000000;
               }
            }
         }
      }

      tvp->tv_sec = 0; tvp->tv_usec = 75000;
      FD_ZERO(&in); FD_SET(0, &in);

      while (select(1, &in, 0, 0, tvp) > 0) {
         if ((ch = wgetch(RaWindow)) != ERR) {
            ArgusUpdateScreen();
            RaInputStatus = ArgusProcessCommand(ArgusParser, RaInputStatus, ch);
         }
      }

      switch (RaInputStatus) {
         default:
         case RAGOTslash:
         case RAGETTINGslash:
         case RAGETTINGcolon: {
            sprintf (RaOutputBuffer, "%s%s%s", RaInputString, RaCommandInputStr, RaCommandError);
            mvwaddnstr (RaWindow, RaScreenLines - 2, 0, RaOutputBuffer, RaScreenColumns);
            wclrtoeol(RaWindow);
            break;
         }

 
         case RANEWCOMMAND: 
         case RAGOTcolon: {
            wmove (RaWindow, RaScreenLines - 2, 0);
            break;
         }
      }
 
      getyx(RaHeaderWindow,RaCursorY,RaCursorX);
      wclrtoeol(RaHeaderWindow);

      if (RaCursesInit)
         if (ArgusParser)
            RaRefreshDisplay(ArgusParser);

#if defined(ARGUS_THREADS)
   }
#if defined(ARGUSMYSQL)
   mysql_thread_end();
#endif
#endif
 
   return (NULL);
}


int
ArgusProcessCommand (struct ArgusParserStruct *parser, int status, int ch)
{
   int retn = status, x;

   if (status == RAGETTINGh) {
      RaWindowStatus = 1;
      wclear(RaWindow);

      RaInputString = RANEWCOMMANDSTR;
      bzero(RaCommandInputStr, MAXSTRLEN);
      RaCommandIndex = 0;
      RaCursorOffset = 0;
      RaWindowCursorY = 0;
      RaWindowCursorX = 0;
      mvwaddnstr (RaWindow, RaScreenLines - 2, 0, " ", RaScreenColumns);
      wclrtoeol(RaWindow);

      ArgusUpdateScreen();
      RaRefreshDisplay(ArgusParser);
      return (RAGOTslash);
   }

   if ((ch == '\n') || (ch == '\r')) {
      RaCursorOffset = 0;
      RaCommandInputStr[RaCommandIndex] = '\0';
      switch (retn) {
         case RAGETTINGN: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            if (ptr != RaCommandInputStr) {
               RaDisplayLines = ((value < (RaScreenLines - (RaHeaderWinSize + 1)) - 1) ?
                                  value : (RaScreenLines - (RaHeaderWinSize + 1)) - 1);
               ArgusUpdateScreen();
            }
      
            break;
         }

         case RAGETTINGS: {
            if (!(ArgusAddHostList (ArgusParser, RaCommandInputStr, (ArgusParser->Cflag ? ARGUS_CISCO_DATA_SOURCE : ARGUS_DATA_SOURCE)))) {
               ArgusLog (LOG_ALERT, "%s%s host not found", RaInputString, RaCommandInputStr);
            } else {
               ArgusDeleteHostList(ArgusParser);
               ArgusAddHostList (ArgusParser, RaCommandInputStr, (ArgusParser->Cflag ? ARGUS_CISCO_DATA_SOURCE : ARGUS_DATA_SOURCE));
               ArgusParser->Sflag = 1;
               ArgusParser->RaParseDone = 0;
            }
            break;
         }

         case RAGETTINGa: {
            if (!(strncasecmp(RaCommandInputStr, "Totals", 6))) {
               RaScreenResize = TRUE;
               ArgusPrintTotals++;
               RaHeaderWinSize++;
               ArgusUpdateScreen();
            }
         }
         break;

         case RAGETTINGd: {
            struct ArgusInput *input;
            char strbuf[MAXSTRLEN];

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (strbuf, " %s:%d", input->hostname, input->portnum);
                  if ((strstr (RaCommandInputStr, strbuf))) {
                     ArgusRemoveFromQueue (ArgusParser->ArgusActiveHosts, &input->qhdr, ARGUS_LOCK);
                     ArgusCloseInput(ArgusParser, input);
                     break;
                  }
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
            }
         }
         break;

         case RAGETTINGD: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            if (ptr != RaCommandInputStr)
               ArgusParser->debugflag = value;
            break;
         }

         case RAGETTINGc: {
#if defined(ARGUSMYSQL)
            MYSQL_RES *mysqlRes;
            char *hptr, *ptr = NULL, sbuf[2048];
            int retn = 0;

            if ((hptr = strchr (RaCommandInputStr, '@')) != NULL) {
               *hptr++ = '\0'; 
               if (RaHost != NULL)
                  free(RaHost);
               RaHost = strdup(hptr);
            }
   
            if ((ptr = strstr (RaCommandInputStr, "NTAIS")) != NULL) {
               if ((ptr = strchr (RaCommandInputStr, ':')) != NULL) {
                  *ptr++ = '\0';
                  if (RaDatabase != NULL)
                     free(RaDatabase);
                  RaDatabase = strdup(ptr);
               }
               if ((ptr = strchr (ptr, ':')) != NULL) {
                  *ptr++ = '\0'; 
                  if (RaTable != NULL)
                     free (RaTable);
                  RaTable = strdup(ptr);
               }

            } else {
               if ((ptr = strchr (RaCommandInputStr, ':')) != NULL) {
                  *ptr++ = '\0'; 
                  if (RaTable != NULL)
                     free (RaTable);
                  RaTable = strdup(ptr);
               }

               if (RaDatabase != NULL)
                  free (RaDatabase);
               RaDatabase = strdup(RaCommandInputStr);
            }

            RaMySQLInit ();
            if (RaMySQL) {
               if ((RaHost != NULL) && strcmp(RaHost, "localhost")) {
                  if (ArgusParser->ntais == NULL)
                     ArgusParser->ntais = "/tmp/archive";
                  sprintf (RaLocalArchBuf, "%s/%s/%s", ArgusParser->ntais, RaDatabase, RaHost);
                  RaLocalArchive = RaLocalArchBuf;
               } else {
                  RaLocalArchive = RaArchive;
               }
               if (RaLocalArchive != NULL) {
                  snprintf (ArgusArchiveBuf, MAXPATHNAMELEN - 1, "%s", RaLocalArchive);
               }
               if (RaRoleString)
                  sprintf (sbuf, "SELECT MAX(second) FROM %s_Seconds", RaRoleString);
               else
                  sprintf (sbuf, "SELECT MAX(second) FROM Seconds");

               if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) == 0) {
                  if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
                     if ((retn = mysql_num_fields(mysqlRes)) == 1) {
                        if ((row = mysql_fetch_row(mysqlRes)) != NULL) {
                           if (row[0] != NULL) {
                              char *endptr = NULL;
                              RaSQLMaxSecs = strtol(row[0], &endptr, 10);
                              if (row[0] == endptr)
                                 ArgusLog(LOG_ERR, "mysql database error: MAX(seconds) returned %s", sbuf);
                           }
                        }
                     }
                     mysql_free_result(mysqlRes);
                  }
               }
            }
#endif
            break;
         }

         case RAGETTINGf: {
            struct nff_program lfilter;
            char *ptr, *str = NULL;
            int ind = ARGUS_REMOTE_FILTER;
            int retn, i;

            bzero ((char *) &lfilter, sizeof (lfilter));
            ptr = RaCommandInputStr;
            while (isspace((int)*ptr)) ptr++;

            if ((str = strstr (ptr, "local")) != NULL) {
               ptr = strdup(&str[strlen("local ")]);
               ind = ARGUS_LOCAL_FILTER;
            } else 
            if ((str = strstr (ptr, "display")) != NULL) {
               ptr = strdup(&str[strlen("display ")]);
               ind = ARGUS_DISPLAY_FILTER;
            } else 
            if ((str = strstr (ptr, "remote")) != NULL) {
               ptr = strdup(&str[strlen("remote ")]);
               ind = ARGUS_REMOTE_FILTER;
            } else 
            if ((str = strstr (ptr, "none")) != NULL) {
               ind = RaFilterIndex;
            }

            if ((retn = ArgusFilterCompile (&lfilter, ptr, 1)) < 0)
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGfSTR, RaCommandInputStr);
            else {
               sprintf (ArgusParser->RaDebugString, "%s %s filter accepted", RAGETTINGfSTR, RaCommandInputStr);
               str = ptr;
               while (isspace((int)*str)) str++;
               
               switch (ind) {
                  case ARGUS_LOCAL_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusLocalFilter !=  NULL) {
                        free(ArgusParser->ArgusLocalFilter);
                        ArgusParser->ArgusLocalFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusLocalFilter = ptr;
                     else
                        free(ptr);
                     break;

                  case ARGUS_DISPLAY_FILTER:
                     if (ArgusParser->ArgusDisplayCode.bf_insns != NULL)
                        free (ArgusParser->ArgusDisplayCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusDisplayCode, sizeof(lfilter));
                     bcopy((char *)&lfilter, (char *)&ArgusSorter->filter, sizeof(lfilter));

                     if (ArgusParser->ArgusDisplayFilter !=  NULL) {
                        free(ArgusParser->ArgusDisplayFilter);
                        ArgusParser->ArgusDisplayFilter = NULL;
                     }
                     if (strlen(str) > 0) {
                        ArgusParser->ArgusDisplayFilter = ptr;
                     } else
                        free(ptr);
                     break;

                  case ARGUS_REMOTE_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);
                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusRemoteFilter !=  NULL) {
                        free(ArgusParser->ArgusRemoteFilter);
                        ArgusParser->ArgusRemoteFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusRemoteFilter = ptr;
                     else
                        free(ptr);
                     break;
               }
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
            RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < RaTopProcess->queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)RaTopProcess->queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns)
                  ArgusMergeRecords (parser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
            RaWindowStatus = 1;
            wclear(RaAvailableWindow);
            ArgusUpdateScreen();
            RaRefreshDisplay(ArgusParser);
            break;
         }
                      
         case RAGETTINGm: {
            struct ArgusRecordStruct *ns = NULL;
            char strbuf[MAXSTRLEN], *tok = NULL, *ptr;
            struct ArgusModeStruct *mode = NULL, *modelist = NULL, *list; 
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
            int i;                                  

            ArgusParser->RaMonMode = 0;

            if (strcmp(agg->modeStr, RaCommandInputStr)) {
               strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

               if ((mode = ArgusParser->ArgusMaskList) != NULL)
                  ArgusDeleteMaskList(ArgusParser);

               agg->mask = 0;
               agg->saddrlen = 0;
               agg->daddrlen = 0;

               if ((ptr = strbuf) != NULL) {
                  while ((tok = strtok (ptr, " \t")) != NULL) {
                     if ((mode = (struct ArgusModeStruct *) ArgusCalloc (1, sizeof(struct ArgusModeStruct))) != NULL) {
                        if ((list = modelist) != NULL) {
                           while (list->nxt)
                              list = list->nxt;
                           list->nxt = mode;
                        } else
                           modelist = mode;
                        mode->mode = strdup(tok);
                     }
                     ptr = NULL;
                  }
               } else {
                  if ((modelist = ArgusParser->ArgusMaskList) == NULL)
                     agg->mask  = ( ARGUS_MASK_SRCID_INDEX | ARGUS_MASK_PROTO_INDEX |
                                               ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_SPORT_INDEX |
                                               ARGUS_MASK_DADDR_INDEX | ARGUS_MASK_DPORT_INDEX );
               }

               ArgusInitAggregatorStructs(agg);

               if ((mode = modelist) != NULL) {
                  while (mode) {
                     char *ptr = NULL, **endptr = NULL;
                     int value = 0;

                     if ((ptr = strchr(mode->mode, '/')) != NULL) {
                        *ptr++ = '\0';
                        if ((value = strtol(ptr, endptr, 10)) == 0)
                           if (*endptr == ptr)
                              usage();
                     }
                     if (!(strncasecmp (mode->mode, "none", 4))) {
                        agg->mask  = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "macmatrix", 9))) {
                        agg->ArgusMatrixMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SMAC);
                        agg->mask |= (0x01LL << ARGUS_MASK_DMAC);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "mac", 3))) {
                        ArgusParser->RaMonMode++;
                        if (agg->correct != NULL) {
                           free(agg->correct);
                           agg->correct = NULL;
                        }
                        agg->mask |= (0x01LL << ARGUS_MASK_SMAC);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "addr", 4))) {
                        ArgusParser->RaMonMode++;
                        if (agg->correct != NULL) {
                           free(agg->correct);
                           agg->correct = NULL;
                        }
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "matrix", 6))) {
                        agg->ArgusMatrixMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        agg->mask |= (0x01LL << ARGUS_MASK_DADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else {
                        struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;

                        for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                           if (!(strncasecmp (mode->mode, ArgusMaskDefs[i].name, ArgusMaskDefs[i].slen))) {
                              agg->mask |= (0x01LL << i);
                              switch (i) {
                                 case ARGUS_MASK_SADDR:
                                    if (value > 0)
                                       agg->saddrlen = value;
                                    break;
                                 case ARGUS_MASK_DADDR:
                                    if (value > 0)
                                       agg->daddrlen = value;
                                    break;

                                 case ARGUS_MASK_SMPLS:
                                 case ARGUS_MASK_DMPLS: {
                                    int x, RaNewIndex = 0;
                                    char *ptr;

                                    if ((ptr = strchr(mode->mode, '[')) != NULL) {
                                       char *cptr = NULL;
                                       int sind = -1, dind = -1;
                                       *ptr++ = '\0';
                                       while (*ptr != ']') {
                                          if (isdigit((int)*ptr)) {
                                             dind = strtol(ptr, (char **)&cptr, 10);
                                             if (cptr == ptr)
                                                usage ();
      
                                             if (sind < 0)
                                                sind = dind;

                                             for (x = sind; x <= dind; x++)
                                                RaNewIndex |= 0x01 << x;

                                             ptr = cptr;
                                             if (*ptr != ']')
                                                ptr++;
                                             if (*cptr != '-')
                                                sind = -1;
                                          } else
                                             usage ();
                                       }
                                       ArgusIpV4MaskDefs[i].index = RaNewIndex;
                                       ArgusIpV6MaskDefs[i].index = RaNewIndex;
                                       ArgusEtherMaskDefs[i].index = RaNewIndex;
                                    }
                                    break;
                                 }
                              }
                              break;
                           }
                        }
                     }
                     mode = mode->nxt;
                  }
               }

               ArgusParser->ArgusMaskList = modelist;

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_NOLOCK)) != NULL)
                  RaMySQLDeleteRecords(ArgusParser, ns);

               ArgusEmptyHashTable(RaTopProcess->htable);
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->ns = NULL;

#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif

#if defined(ARGUSMYSQL)
               if (RaSQLSaveTable != NULL)
                  if (!(strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$')))
                     ArgusCreateSQLSaveTable(RaSQLSaveTable);
#endif
               werase(RaWindow);
               ArgusUpdateScreen();
            }
            break;
         }

         case RAGETTINGM: {
            struct ArgusModeStruct *mode = NULL;
            char strbuf[MAXSTRLEN], *str = strbuf, *tok = NULL;
            char *tzptr;
            int retn = 0;

            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if ((tzptr = strstr(strbuf, "TZ=")) != NULL) {
               if (ArgusParser->RaTimeZone)
                  free (ArgusParser->RaTimeZone);
               ArgusParser->RaTimeZone = strdup(tzptr);
               tzptr = getenv("TZ");
#if defined(HAVE_SETENV)
               if ((retn = setenv("TZ", (ArgusParser->RaTimeZone + 3), 1)) < 0)
                  sprintf (ArgusParser->RaDebugString, "setenv(TZ, %s, 1) error %s", 
                     ArgusParser->RaTimeZone + 3, strerror(errno));
#else
               if ((retn = putenv(ArgusParser->RaTimeZone)) < 0)
                  sprintf (ArgusParser->RaDebugString, "setenv(TZ, %s, 1) error %s", 
                     ArgusParser->RaTimeZone + 3, strerror(errno));
#endif
               if (retn == 0) {
                  tzset();
                  sprintf (ArgusParser->RaDebugString, "Timezone changed from %s to %s", 
                             tzptr, getenv("TZ"));
               }

               ArgusUpdateScreen();
               break;
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               ArgusDeleteModeList(ArgusParser);
               ArgusParser->RaCumulativeMerge = 1;
            }

            if (strlen(strbuf) > 0) {
               while ((tok = strtok(str, " \t\n")) != NULL) {
                  if (!(strncasecmp (tok, "none", 4)))
                     ArgusDeleteModeList(ArgusParser);
                  else if (!(strncasecmp (tok, "default", 7))) {
                     ArgusDeleteModeList(ArgusParser);
                  } else
                     ArgusAddModeList (ArgusParser, tok);
                  str = NULL;
               }
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               struct ArgusAdjustStruct *nadp = NULL;
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
                     int size = -1;
                     nadp = &RaBinProcess->nadp;

                     nadp = &RaBinProcess->nadp;

                     switch (ind) {
                        case ARGUSSPLITRATE:  {   /* "%d:%d[yMwdhms]" */
                           struct ArgusModeStruct *tmode = NULL; 
                           nadp->mode = ind;
                           if ((tmode = mode->nxt) != NULL) {
                              mptr = tmode->mode;
                              if (isdigit((int)*tmode->mode)) {
                                 char *ptr = NULL;
                                 nadp->len = strtol(tmode->mode, (char **)&ptr, 10);
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
                                          size = nadp->value * 31556926;
                                          break;
                                       case 'M':
                                          nadp->qual = ARGUSSPLITMONTH; 
                                          size = nadp->value * 2629744;
                                          break;
                                       case 'w':
                                          nadp->qual = ARGUSSPLITWEEK;  
                                          size = nadp->value * 604800;
                                          break;
                                       case 'd':
                                          nadp->qual = ARGUSSPLITDAY;   
                                          size = nadp->value * 86400;
                                          break;
                                       case 'h':
                                          nadp->qual = ARGUSSPLITHOUR;  
                                          size = nadp->value * 3600;
                                          break;
                                       case 'm':
                                          nadp->qual = ARGUSSPLITMINUTE;
                                          size = nadp->value * 60;
                                          break;
                                        default:
                                          nadp->qual = ARGUSSPLITSECOND;
                                          size = nadp->value;
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
                                 just a bit bigger than (nadp->len * size) */

                              ArgusParser->timeout.tv_sec  = (nadp->len * size);
                              ArgusParser->timeout.tv_usec = 0;
                           }

                           ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                           ArgusSorter->ArgusSortAlgorithms[1] = NULL;
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
                           ArgusSorter->ArgusSortAlgorithms[0] = NULL;
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
                     if (!(strncasecmp (mode->mode, "nomerge", 7))) {
                        ArgusParser->RaCumulativeMerge = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "merge", 5))) {
                        ArgusParser->RaCumulativeMerge = 1;
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
                              ArgusParser->ArgusTimeMultiplier = value;
                        }

                     }
                  }

                  mode = mode->nxt;
               }
            }

            break;
         }

         case RAGETTINGp: {
            int value = 0;
            char *endptr = NULL;

            value = strtod(RaCommandInputStr, &endptr);

            if (RaCommandInputStr != endptr) {
               ArgusParser->pflag = value;
            } else
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);

            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGR: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  RaProcessRecursiveFiles (ptr);
                  str = NULL;
               }
            }
            break;
         }

         case RAGETTINGr: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            glob_t globbuf;

            bzero (strbuf, MAXSTRLEN);
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               struct ArgusRecordStruct *ns = NULL;

               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  glob (ptr, 0, NULL, &globbuf);
                  if (globbuf.gl_pathc > 0) {
                     int i;
                     for (i = 0; i < globbuf.gl_pathc; i++)
                        ArgusAddFileList (ArgusParser, globbuf.gl_pathv[i], ARGUS_DATA_SOURCE, -1, -1);
                  } else 
                     sprintf (ArgusParser->RaDebugString, "%s no files found for %s", RAGETTINGrSTR, ptr);
                  str = NULL;
               }
               ArgusParser->RaTasksToDo = 1;
               ArgusParser->Sflag = 0;
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_LOCK)) != NULL)  {
                  RaMySQLDeleteRecords(ArgusParser, ns);
               }
               ArgusEmptyHashTable(RaTopProcess->htable);

               if (ArgusParser->ns) {
                  ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                  ArgusParser->ns = NULL;
               }

               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->status &= ~ARGUS_FILE_LIST_PROCESSED;
               ArgusLastTime.tv_sec  = 0;
               ArgusLastTime.tv_usec = 0;
            }
            break;
         }

         case RAGETTINGs: {
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int (*srtalg[ARGUS_MAX_SORT_ALG])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
            int i, x, ind = 0;
            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero(srtalg, sizeof(srtalg));
            while ((tok = strtok(ptr, " ")) != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                  if (!strncmp (ArgusSortKeyWords[x], tok, strlen(ArgusSortKeyWords[x]))) {
                     srtalg[ind++] = ArgusSortAlgorithmTable[x];
                     break;
                  }
               }
               if (x == ARGUS_MAX_SORT_ALG) {
                  bzero(srtalg, sizeof(srtalg));
                  ArgusLog (LOG_ALERT, "sort keyword %s not valid", tok);
                  break;
               }
               ptr = NULL;
            }

            if (srtalg[0] != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++)
                  ArgusSorter->ArgusSortAlgorithms[x] = srtalg[x];
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
            RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < RaTopProcess->queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)RaTopProcess->queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns)
                  ArgusMergeRecords (parser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGT: {
            double sec, usec, value;
            char *ptr = NULL;

            value = strtod(RaCommandInputStr, (char **)&ptr);
            if (ptr != RaCommandInputStr) {
               usec = modf(value, &sec);
               ArgusParser->timeout.tv_sec  = sec;
               ArgusParser->timeout.tv_usec = usec;
            }
            break;
         }

         case RAGETTINGt: {
            time_t secs = 0;

            if (ArgusParser->timearg) {
               free (ArgusParser->timearg);
               ArgusParser->timearg = NULL;
            }

            if (strlen(RaCommandInputStr))
               ArgusParser->timearg = strdup(RaCommandInputStr);

#if defined(ARGUSMYSQL)
            if (ArgusParser->timearg != NULL) {
               ArgusParser->tflag = 1;

               if (!(RaStatus)) {
                  secs = RaSQLMaxSecs;
                  ArgusParser->RaTmStruct  = localtime (&secs);
               } else {
                  secs = ArgusParser->ArgusRealTime.tv_sec;
                  ArgusParser->RaTmStruct  = localtime (&secs);
               }

               ArgusCheckTimeFormat (ArgusParser->RaTmStruct, ArgusParser->timearg);
               RaStartTime.tv_sec = ArgusParser->startime_t;
               RaEndTime.tv_sec = ArgusParser->lasttime_t;
               RaStartTime.tv_usec = 0;
               RaEndTime.tv_usec   = 0;

            } else {
               char stimebuf[MAXSTRLEN];
               if (RaStatus) {
                  gettimeofday(&RaEndTime, 0L);
                  RaStartTime.tv_sec  = RaEndTime.tv_sec - 60;
               } else {
                  RaEndTime.tv_sec  = RaSQLMaxSecs;
                  RaStartTime.tv_sec = RaEndTime.tv_sec - 60;
               }

               ArgusParser->startime_t = RaStartTime.tv_sec;
               ArgusParser->lasttime_t = RaEndTime.tv_sec;
               RaStartTime.tv_usec = 0;
               RaEndTime.tv_usec   = 0;
                                 
               secs = RaStartTime.tv_sec;
               ArgusParser->RaTmStruct  = localtime (&secs);
               strftime ((char *) stimebuf, 32, "%Y/%m/%d.%T", ArgusParser->RaTmStruct);
               sprintf (&stimebuf[strlen(stimebuf)], "+60s");
               ArgusParser->timearg  = strdup(stimebuf);
            }

            if (RaMySQL != NULL) {
               struct ArgusRecordStruct *ns = NULL;
               struct RaMySQLFileStruct *fstruct = NULL;
               ArgusDeleteFileList(ArgusParser);

               ArgusParser->RaTasksToDo = 1;
               ArgusParser->Sflag = 0;

               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_LOCK)) != NULL)
                  RaMySQLDeleteRecords(ArgusParser, ns);

               ArgusEmptyHashTable(RaTopProcess->htable);

               if (ArgusParser->ns != NULL) {
                  ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                  ArgusParser->ns = NULL;
               }

               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->status &= ~ARGUS_FILE_LIST_PROCESSED;
               ArgusLastTime.tv_sec  = 0;
               ArgusLastTime.tv_usec = 0;

               ArgusDeleteQueue (ArgusModelerQueue);
               if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
                                    ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

               RaSQLQuerySecondsTable (ArgusParser->startime_t , ArgusParser->lasttime_t);

               if (ArgusModelerQueue->count) {
                  struct RaMySQLSecondsTable *sqry = NULL;
                  struct RaMySQLFileStruct *fstruct = NULL;
                  int retn, i, fileid = -1;
                  MYSQL_RES *mysqlRes;
                  char buf[2048], sbuf[2048];
                  struct stat statbuf;

                  sqry = (struct RaMySQLSecondsTable *) ArgusModelerQueue->start;
                  for (i = 0; i < ArgusModelerQueue->count; i++) {
                     if (fileid != sqry->fileindex) {
                        char *str = NULL;
                        fileid = sqry->fileindex;
                        bzero (buf, sizeof(buf));
                        if (RaRoleString) {
                           str = "SELECT filename from %s_Filename WHERE id = %d",
                           sprintf (buf, str, RaRoleString, sqry->fileindex);
                        } else {
                           str = "SELECT filename from Filename WHERE id = %d",
                           sprintf (buf, str, sqry->fileindex);
                        }
                        if ((retn = mysql_real_query(&mysql, buf, strlen(buf))) != 0)
                           ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));

                        else {
                           if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
                              if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                                 while ((row = mysql_fetch_row(mysqlRes))) {
                                    char file[MAXSTRLEN];
                                    char filenamebuf[MAXSTRLEN];
                                    char directorypath[MAXSTRLEN];
                                    char *ptr = NULL;
                                    unsigned long *lengths;
                      
                                    lengths = mysql_fetch_lengths(mysqlRes);
                                    if (RaFormat) {
                                       char fbuf[1024];
                                       time_t secs;
                                       bzero (fbuf, sizeof(fbuf));
                                       if ((ptr = strstr(RaFormat, "$srcid")) != NULL) {
                                          struct RaMySQLProbeTable *psqry = (void *)ArgusProbeQueue->start;
                                          RaProbeString = NULL;
                                          bcopy (RaFormat, fbuf, (ptr - RaFormat));
                                          if (psqry) {
                                             for (x = 0; x < ArgusProbeQueue->count; x++) {
                                                if ((psqry->probe == sqry->probe) || (sqry->probe == 0)) {
                                                   RaProbeString = psqry->name;
                                                   break;
                                                }
                                                psqry = (void *)psqry->qhdr.nxt;
                                             }
                                             if (RaProbeString)
                                                sprintf (&fbuf[strlen(fbuf)], "%s", RaProbeString);
                                          }
                                          
                                          bcopy (&ptr[6], &fbuf[strlen(fbuf)], strlen(&ptr[6]));
                                       } else {
                                          bcopy (RaFormat, fbuf, strlen(RaFormat));
                                       }

                                       secs = (sqry->second/RaPeriod) * RaPeriod;
                                       strftime (directorypath, MAXSTRLEN, fbuf, localtime(&secs));
                                    }

                                    for (x = 0; x < retn; x++)
                                       snprintf(sbuf, 2048, "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

                                    if ((fstruct = (void *) ArgusCalloc (1, sizeof(*fstruct))) == NULL)
                                       ArgusLog(LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

                                    if ((ptr = strchr(sbuf, '.')) == NULL)
                                       ArgusLog(LOG_ERR, "ArgusClientInit: Filename format error %s", sbuf);

                                    if (RaFormat) 
                                       sprintf (file, "%s/%s", directorypath, sbuf);
                                    else
                                       sprintf (file, "%s", sbuf);

                                    while (file[strlen(file) - 1] == ' ')
                                       file[strlen(file) - 1] = '\0';

                                    if (!(strncmp(&file[strlen(file) - 3], ".gz", 3))) 
                                       file[strlen(file) - 3] = '\0';

                                    if (RaRoleString) {
                                       sprintf (filenamebuf, "%s/%s/%s", ArgusArchiveBuf, RaRoleString, file);
                                    } else {
                                       sprintf (filenamebuf, "%s/%s", ArgusArchiveBuf, file);
                                    }

                                    if ((stat (filenamebuf, &statbuf)) != 0) {
                                       char compressbuf[MAXSTRLEN];
                                       sprintf (compressbuf, "%s.gz", filenamebuf);
                                       if ((stat (compressbuf, &statbuf)) == 0) {
                                          if ((sqry->ostart >= 0) || (sqry->ostop > 0)) {
                                             char command[MAXSTRLEN];
                                             sprintf (command, "gunzip %s", compressbuf);
#ifdef ARGUSDEBUG
                                             ArgusDebug (2, "ArgusClientInit: local decomression command %s\n", command);
#endif
                                             if (system(command) < 0)
                                                ArgusLog(LOG_ERR, "ArgusClientInit: system error", strerror(errno));
                                          } else {
                                             sprintf (filenamebuf, "%s", compressbuf);
                                          }

                                       } else {
                                          if (RaHost) {
                                             char command[MAXSTRLEN];
                                             sprintf (command, "/usr/local/bin/ra -S %s:561%s/%s -w %s/%s", RaHost, RaArchive, file, ArgusArchiveBuf, file);
#ifdef ARGUSDEBUG
                                             ArgusDebug (2, "ArgusClientInit: remote file caching command  %s\n", command);
#endif
                                             if (system(command) < 0)
                                                ArgusLog(LOG_ERR, "ArgusClientInit: system error", strerror(errno));
                                          }
                                       }
                                    }

                                    fstruct->filename = strdup (filenamebuf);
                                    fstruct->fileindex = sqry->fileindex;
                                    fstruct->ostart = sqry->ostart;
                                    fstruct->ostop  = sqry->ostop;
                                    ArgusAddToQueue (ArgusFileQueue, &fstruct->qhdr, ARGUS_LOCK);
                                 }
                              }

                              mysql_free_result(mysqlRes);
                           }
                        }

                     } else {
                        fstruct = (struct RaMySQLFileStruct *) ArgusFileQueue->start;
                        for (x = 0; x < ArgusFileQueue->count; x++) {
                           if (fstruct->fileindex == fileid)
                              break;
                           fstruct = (struct RaMySQLFileStruct *) fstruct->qhdr.nxt;
                        }

                        if (fstruct->fileindex == fileid) {
                           if (fstruct->ostart > sqry->ostart)
                              fstruct->ostart = sqry->ostart;
                           if (fstruct->ostop < sqry->ostop)
                              fstruct->ostop = sqry->ostop;
                        }
                     }

                     sqry = (struct RaMySQLSecondsTable *) sqry->qhdr.nxt;
                  }
               }

               if (RaSQLMaxSecs < RaEndTime.tv_sec) {
                  if (RaSource != NULL) {
                     if ((fstruct = (void *) ArgusCalloc (1, sizeof(*fstruct))) == NULL)
                        ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));
                               
                     fstruct->filename = RaSource;
                     fstruct->fileindex = -1;
                     fstruct->ostart = -1;
                     fstruct->ostop  = -1;
                     ArgusAddToQueue (ArgusFileQueue, &fstruct->qhdr, ARGUS_LOCK);
                  }
               }

               if (ArgusFileQueue->count) {
                  struct RaMySQLFileStruct *fptr = NULL;

                  while ((fstruct = (struct RaMySQLFileStruct *) ArgusPopQueue(ArgusFileQueue, ARGUS_LOCK)) != NULL) {
                     fptr = (struct RaMySQLFileStruct *) ArgusFileQueue->start;

                     for (x = 0; x < ArgusFileQueue->count; x++) {
                        if (fstruct->fileindex == fptr->fileindex) {
                           if (fstruct->ostart < fptr->ostart)
                              fptr->ostart = fstruct->ostart;
                           if (fstruct->ostop > fptr->ostop)
                              fptr->ostop = fstruct->ostop;

                           if (fstruct->filename != NULL)
                              free (fstruct->filename);
                           ArgusFree(fstruct); 
                           fstruct = NULL;
                           break;
                        }
                        fptr = (struct RaMySQLFileStruct *) fptr->qhdr.nxt;
                     }

                     if (fstruct != NULL) {
                        ArgusAddFileList(ArgusParser, fstruct->filename, ARGUS_DATA_SOURCE,
                           fstruct->ostart, fstruct->ostop);
#ifdef ARGUSDEBUG
                        ArgusDebug (2, "ArgusClientInit: filename %s ostart %d  ostop %d\n",
                           fstruct->filename, fstruct->ostart, fstruct->ostop);
#endif
                     }
                  }

               } else {
               }
            }
#else
               ArgusCheckTimeFormat (ArgusParser->RaTmStruct, ArgusParser->timearg);
#endif
            break;
         }

         case RAGETTINGu: {
            double value = 0.0, ivalue, fvalue;
            char *endptr = NULL;
#if defined(ARGUS_READLINE)
            int keytimeout;
#endif
 
            value = strtod(RaCommandInputStr, &endptr);
 
            if (RaCommandInputStr != endptr) {
               fvalue = modf(value, &ivalue);
 
               RaTopUpdateInterval.tv_sec  = (int) ivalue;
               RaTopUpdateInterval.tv_usec = (int) (fvalue * 1000000.0);

#if defined(ARGUS_READLINE)
               keytimeout = RaTopUpdateInterval.tv_sec * 1000000 + RaTopUpdateInterval.tv_usec;
               keytimeout = (keytimeout == 1000000) ? keytimeout - 1 : keytimeout;
               rl_set_keyboard_input_timeout (keytimeout);
#endif
               sprintf (ArgusParser->RaDebugString, "%s %s interval accepted", RAGETTINGuSTR, RaCommandInputStr);
               RaTopUpdateTime = ArgusParser->ArgusRealTime;
 
            } else
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);

            break;
         }


         case RAGETTINGU: {
            double value = 0.0;
            char *endptr = NULL;
 
            value = strtod(RaCommandInputStr, &endptr);
 
            if (RaCommandInputStr != endptr) {
               RaUpdateRate = value;
               sprintf (ArgusParser->RaDebugString, "%s %s accepted", RAGETTINGUSTR, RaCommandInputStr);
 
            } else
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGUSTR, RaCommandInputStr);

            break;
         }

         
         case RAGETTINGw: {
            struct ArgusListStruct *wlist = ArgusParser->ArgusWfileList;
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusRecord *argusrec = NULL;
            struct ArgusRecordStruct *ns;
            static char sbuf[0x10000];
            int i;

            if (RaTopProcess->queue->count > 0) {
               ArgusParser->ArgusWfileList = NULL;
               setArgusWfile (ArgusParser, RaCommandInputStr, NULL);
               wfile = (struct ArgusWfileStruct *) ArgusParser->ArgusWfileList->start;
/*
               RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_LOCK);
*/
               for (i = 0; i < RaTopProcess->queue->count; i++) {
                  int pass = 1;

                  if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[i]) == NULL)
                     break;

                  if (wfile->filterstr) {
                     struct nff_insn *wfcode = wfile->filter.bf_insns;
                     pass = ArgusFilterRecord (wfcode, ns);
                  }

                  if (pass != 0) {
                     if ((argusrec = ArgusGenerateRecord (ns, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        ArgusWriteNewLogfile (ArgusParser, ns->input, wfile, argusrec);

                     }
                  }
               }
            
               fflush(wfile->fd);
               fclose(wfile->fd);
               clearArgusWfile(ArgusParser);
               ArgusParser->ArgusWfileList = wlist;
            }

            break;   
         }

         case RAGETTINGF: {
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int x;
            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero ((char *)ArgusParser->RaSOptionStrings, sizeof(ArgusParser->RaSOptionStrings));
            ArgusParser->RaSOptionIndex = 0;
            ArgusPrintRank = 0;
            while ((tok = strtok(ptr, " ")) != NULL) {
               if ((strstr (tok, "rank"))) {
                  if (*tok == '-')
                     ArgusPrintRank = 0;
                  else
                     ArgusPrintRank++;
               } else
                  if (ArgusParser->RaSOptionIndex <  ARGUS_MAX_S_OPTIONS)
                     ArgusParser->RaSOptionStrings[ArgusParser->RaSOptionIndex++] = tok;
               ptr = NULL;
            }

            if (ArgusParser->RaSOptionIndex > 0) {
               ArgusProcessSOptions(ArgusParser);
               for (x = 0; x < ArgusParser->RaSOptionIndex; x++) 
                  if (ArgusParser->RaSOptionStrings[x] != NULL) 
                     ArgusParser->RaSOptionStrings[x] = NULL;
               ArgusParser->RaSOptionIndex = 0;
            }
            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGcolon: {
            char *endptr = NULL;
            int linenum, startline;

            linenum = (int)strtol(RaCommandInputStr, &endptr, 10);
            if (RaCommandInputStr == endptr) {
               switch (*RaCommandInputStr) {
                  case 'q': {
                     bzero (RaCommandInputStr, MAXSTRLEN);
                     ArgusUpdateScreen();
                     RaParseComplete(SIGINT);
                     break;
                  }
               }
            } else {
               if ((linenum >= RaWindowStartLine) && (linenum <= (RaWindowStartLine + RaDisplayLines)))
                  RaWindowCursorY = linenum - RaWindowStartLine;
               else {
                  startline = ((linenum - 1)/ RaDisplayLines) * RaDisplayLines;
                  startline = (RaTopProcess->queue->count > startline) ? startline : RaTopProcess->queue->count - RaDisplayLines;
                  startline = (startline > 0) ? startline : 0;
                  RaWindowStartLine = startline;
                  if ((RaWindowCursorY = linenum % RaDisplayLines) == 0)
                     RaWindowCursorY = RaDisplayLines;
               }
               retn = RAGOTcolon;
               ArgusUpdateScreen();
            }
            break;
         }

         case RAGETTINGslash: {
            int linenum = RaWindowCursorY;
            int cursx = RaWindowCursorX, cursy = RaWindowCursorY + RaWindowStartLine;

            if ((linenum = RaSearchDisplay(ArgusParser, RaTopProcess->queue, ArgusSearchDirection,
                     &cursx, &cursy, RaCommandInputStr)) < 0) {
               if (ArgusSearchDirection == ARGUS_FORWARD) {
                  sprintf (ArgusParser->RaDebugString, "search hit BOTTOM, continuing at TOP");
                  cursx = 0; cursy = 0;
               } else {
                  sprintf (ArgusParser->RaDebugString, "search hit TOP, continuing at BOTTOM");
                  cursx = RaScreenColumns; cursy = RaTopProcess->queue->count;
               }
               linenum = RaSearchDisplay(ArgusParser, RaTopProcess->queue, ArgusSearchDirection,
                     &cursx, &cursy, RaCommandInputStr);
            }

            if (linenum >= 0) {
               int startline = ((cursy - 1)/ RaDisplayLines) * RaDisplayLines;
               startline = (RaTopProcess->queue->count > startline) ? startline : RaTopProcess->queue->count - RaDisplayLines;
               startline = (startline > 0) ? startline : 0;
               retn = RAGOTslash;
               RaWindowStartLine = startline;
               if ((RaWindowCursorY = cursy % RaDisplayLines) == 0)
                  RaWindowCursorY = RaDisplayLines;
               RaWindowCursorX = cursx;
               ArgusUpdateScreen();
            } else {
               sprintf (ArgusParser->RaDebugString, "Pattern not found: %s", RaCommandInputStr);
               retn = RAGOTslash;
               RaInputString = RANEWCOMMANDSTR;
               bzero(RaCommandInputStr, MAXSTRLEN);
               RaCommandIndex = 0;
               RaCursorOffset = 0;
               RaWindowCursorY = 0;
               RaWindowCursorX = 0;
               mvwaddnstr (RaWindow, RaScreenLines - 2, 0, " ", RaScreenColumns);
               wclrtoeol(RaWindow);
            }

            retn = RAGOTslash;
            RaInputString = "/";
            break;
         }
      }

      if ((retn != RAGOTslash) && (retn != RAGOTcolon)) {
         retn = RAGOTslash;
         RaInputString = RANEWCOMMANDSTR;
         RaCommandInputStr[0] = '\0';
      }

   } else {
      switch (ch) {
         case 0x0C: {
            RaWindowStatus = 1;
            wclear(RaWindow);
            ArgusUpdateScreen();
            RaRefreshDisplay(ArgusParser);
            break;
         }

#if defined(ARGUS_READLINE)
         case 0x1B: { /* process ESC */
            struct timeval tvbuf, *tvp = &tvbuf;
            int eindex = 0;
            int escbuf[16];
            fd_set in;

            bzero(escbuf, sizeof(escbuf));
            tvp->tv_sec = 0; tvp->tv_usec = 10000;
            FD_ZERO(&in); FD_SET(0, &in);
            while ((select(1, &in, 0, 0, tvp) > 0) && (eindex < 2)) {
               if ((ch = wgetch(RaWindow)) != ERR) {
                  escbuf[eindex++] = ch;
               }
               FD_ZERO(&in); FD_SET(0, &in);
            }

            if (eindex == 2) {
               int offset;
               switch (escbuf[0]) {
                  case '[': /* process ESC */
                     switch (escbuf[1]) {
                        case 'A': /* cursor up */
                           RaWindowCursorY--;
                           if (RaWindowCursorY < 1) {
                              RaWindowCursorY = 1;
                              if (RaWindowStartLine > 0) {
                                 RaWindowStartLine--;
                                 wscrl(RaAvailableWindow, -1);
                                 ArgusUpdateScreen();
                              } else
                                 beep();
                           }
                           break;
                        case 'B': /* cursor down */
                           RaWindowCursorY++;
                           if ((RaTopProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
                              int maxwincount = RaTopProcess->queue->count - RaWindowStartLine;
                              if (RaWindowCursorY > maxwincount) {
                                 RaWindowCursorY = maxwincount;
                                 beep();
                              }

                           } else {
                              if (RaWindowCursorY > RaDisplayLines) {
                                 if ((RaTopProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                                    RaWindowStartLine++;
                                    wscrl(RaAvailableWindow, 1);
                                    ArgusUpdateScreen();
                                 } else
                                    beep();

                                 RaWindowCursorY = RaDisplayLines;
                              }
                           }
                           break;
                        case 'C': { /* cursor forward */
                           int startline = RaWindowCursorY + RaWindowStartLine;
                           struct ArgusRecordStruct *ns;

                           if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {
                              char buf[MAXSTRLEN];
                              int len;

                              *(unsigned int *)buf = 0;
                              ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);

                              len = strlen(buf);
                              RaWindowCursorX++;
                              if (RaWindowCursorX >= len) {
                                 RaWindowCursorX = len - 1;
                                 beep();
                              }
                           }
                           ArgusUpdateScreen();
                           break;
                        }

                        case 'D': /* cursor backward */
                           RaWindowCursorX--;
                           if (RaWindowCursorX < 0) {
                              RaWindowCursorX = 0;
                              beep();
                           }
                           ArgusUpdateScreen();
                           break;
                     }
                     break;
                  default:
                     break;
               }
               offset = (RaWindowCursorY % (RaDisplayLines + 1));
               if (offset > (RaSortItems - RaWindowStartLine)) {
                  RaWindowCursorY = (RaSortItems - RaWindowStartLine);
                  offset = (RaSortItems - RaWindowStartLine);
               }
               offset += RaHeaderWinSize;
               wmove (RaWindow, offset, RaWindowCursorX + (ArgusPrintRank ? ArgusRankSize + 1 : 1));
            }
            break;
         }
#endif

         case 0x04: {
            bzero (RaCommandInputStr, MAXSTRLEN);
            RaCommandIndex = 0;
            RaCursorOffset = 0;
            break;
         }

         case KEY_UP: {
            int done = 0, start = RaFilterIndex;
            switch (retn) {
               case RAGETTINGf: {
                  do {
                     RaFilterIndex = ((RaFilterIndex + 1) > ARGUS_DISPLAY_FILTER) ? ARGUS_REMOTE_FILTER : RaFilterIndex + 1;
                     switch (RaFilterIndex) {
                        case ARGUS_REMOTE_FILTER:
                           if (ArgusParser->ArgusRemoteFilter) {
                              sprintf (RaCommandInputStr, "remote %s ", ArgusParser->ArgusRemoteFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_REMOTE_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }

                        case ARGUS_LOCAL_FILTER:
                           if (ArgusParser->ArgusLocalFilter) {
                              sprintf (RaCommandInputStr, "local %s ", ArgusParser->ArgusLocalFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_LOCAL_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }
                        case ARGUS_DISPLAY_FILTER:
                           if (ArgusParser->ArgusDisplayFilter) {
                              sprintf (RaCommandInputStr, "display %s ", ArgusParser->ArgusDisplayFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_DISPLAY_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }
                     }
                  } while ((start != RaFilterIndex) && !done);
                  break;
               }

               default: {
                  RaWindowCursorY--;
                  if (RaWindowCursorY < 1) {
                     RaWindowCursorY = 1;
                     if (RaWindowStartLine > 0) {
                        RaWindowStartLine--;
                        wscrl(RaAvailableWindow, -1);
                        ArgusUpdateScreen();
                     } else
                        beep();
                  }
                  break;
               }
            }
            break;
         }

         case KEY_DOWN: {
            int trips = 0, done = 0, start = RaFilterIndex;
            switch (retn) {
               case RAGETTINGf: {
                  do {
                     RaFilterIndex = ((RaFilterIndex - 1) < ARGUS_REMOTE_FILTER) ? ARGUS_DISPLAY_FILTER : RaFilterIndex - 1;
                     switch (RaFilterIndex) {
                        case ARGUS_DISPLAY_FILTER:
                           if (ArgusParser->ArgusDisplayFilter) {
                              sprintf (RaCommandInputStr, " display %s", ArgusParser->ArgusDisplayFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_DISPLAY_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }

                        case ARGUS_LOCAL_FILTER:
                           if (ArgusParser->ArgusLocalFilter) {
                              sprintf (RaCommandInputStr, " local %s", ArgusParser->ArgusLocalFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_LOCAL_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }

                        case ARGUS_REMOTE_FILTER:
                           if (ArgusParser->ArgusRemoteFilter) {
                              sprintf (RaCommandInputStr, " remote %s", ArgusParser->ArgusRemoteFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_REMOTE_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }
                     }
                     trips++;
                  } while ((start != RaFilterIndex) && !done && (trips < 3));
                  break;
               }
               default: {
                  RaWindowCursorY++;
                  if ((RaTopProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
                     int maxwincount = RaTopProcess->queue->count - RaWindowStartLine;
                     if (RaWindowCursorY > maxwincount) {
                        RaWindowCursorY = maxwincount;
                        beep();
                     }

                  } else {
                     if (RaWindowCursorY > RaDisplayLines) {
                        if ((RaTopProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                           RaWindowStartLine++;
                           wscrl(RaAvailableWindow, 1);
                           ArgusUpdateScreen();
                        } else
                           beep();

                        RaWindowCursorY = RaDisplayLines;
                     }
                  }
                  break;
               }
            }
            break;
         }

         case KEY_LEFT:
            if (++RaCursorOffset > RaCommandIndex)
              RaCursorOffset = RaCommandIndex;
            break;

         case KEY_RIGHT:
            if (--RaCursorOffset < 0)
               RaCursorOffset = 0;
            break;

         case 0x07: {
            ArgusDisplayStatus = (ArgusDisplayStatus ? 0 : 1);
            ArgusUpdateScreen();
            break;
         }

         default: {
            switch (ch) {
               case '\b':
               case 0x7F:
               case KEY_DC:
               case KEY_BACKSPACE: {
                  if (RaCursorOffset == 0) {
                     RaCommandInputStr[RaCommandIndex--] = '\0';
                     RaCommandInputStr[RaCommandIndex] = '\0';
                  } else {
                     if (RaCursorOffset < RaCommandIndex) {
                        int z, start; 
                        start = RaCommandIndex - (RaCursorOffset + 1);
                        if (start < 0)
                           start = 0;
                        for (z = start; z < (RaCommandIndex - 1); z++)
                           RaCommandInputStr[z] = RaCommandInputStr[z + 1];
                        RaCommandInputStr[RaCommandIndex--] = '\0';
                        RaCommandInputStr[RaCommandIndex] = '\0';
                        if (RaCursorOffset > RaCommandIndex)
                           RaCursorOffset = RaCommandIndex;
                     }
                  }

                  if (RaCommandIndex < 0) {
                     if ((retn == RAGETTINGslash) || (retn == RAGETTINGcolon)) {
                        mvwaddstr (RaWindow, RaScreenLines - 2, 0, " ");
                        retn = RAGOTslash;
                        RaInputString = RANEWCOMMANDSTR;
                        RaCommandIndex = 0;
                        RaCursorOffset = 0;
                     }
                     RaCommandIndex = 0;
                  }
                  break;
               }

               case 0x15:
               case KEY_DL: {
                  bzero (RaCommandInputStr, MAXSTRLEN);
                  RaCommandIndex = 0;
                  RaCursorOffset = 0;
                  break;
               }
    
               default: {
                  int iter;
                  if (retn == RAGOTslash) {
                     if (isdigit(ch) && (ch != '0')) {
                        if (RaDigitPtr < 16)
                           RaDigitBuffer[RaDigitPtr++] = ch;
                     } else {
                        if (RaDigitPtr) {
                           char *ptr;
                           RaIter= strtol(RaDigitBuffer, (char **)&ptr, 10);
                           if (ptr == RaDigitBuffer)
                              RaIter = 1;
                           bzero(RaDigitBuffer, sizeof(RaDigitBuffer));
                           RaDigitPtr = 0;
                        } else
                           RaIter = 1;

#if defined(ARGUSDEBUG)
                        ArgusDebug (6, "ArgusProcessCommand: calling with %d iterations", RaIter);
#endif
                     }
                  } else
                     RaIter = 1;

                  for (iter = 0; iter < RaIter; iter++) {
                     int olddir = -1;

                     switch (retn) {
                        case RAGOTcolon:
                        case RAGOTslash: {
                           switch (ch) {
                              case 0x07: {
                                 ArgusDisplayStatus = (ArgusDisplayStatus ? 0 : 1);
                                 ArgusUpdateScreen();
                                 break;
                              }
                              case '%': {
                                 ArgusParser->Pctflag = (ArgusParser->Pctflag == 1) ? 0 : 1;
                                 if (ArgusParser->Pctflag)
                                    RaInputString = "Toggle percent on";
                                 else
                                    RaInputString = "Toggle percent off";
                                 break;
                              }
/*
                              case 'h':
                                 retn = RAGETTINGh;
                                 RaInputString = RAGETTINGhSTR;
                                 RaWindowStatus = 0;
                                 RaOutputHelpScreen();
                                 break;
*/
                              case 'H':
                                 ArgusParser->Hflag = ArgusParser->Hflag ? 0 : 1;
                                 break;
                              case 'P': {
                                 double rate  = RaUpdateRate;
                                 double pause = ArgusParser->Pauseflag;

                                 ArgusParser->Pauseflag = (pause > 0.0) ? 0.0 : rate;
                                 RaUpdateRate = (rate > 0.0) ? 0.0 : pause;

                                 if (ArgusParser->Pauseflag)
                                    RaInputString = "Paused";
                                 else
                                    RaInputString = "";
                                 break;
                              }
                              case 'v':
                                 if (ArgusParser->vflag) {
                                    ArgusParser->vflag = 0;
                                    ArgusReverseSortDir = 0;
                                 } else {
                                    ArgusParser->vflag = 1;
                                    ArgusReverseSortDir++;
                                 }
#if defined(ARGUS_THREADS)
                                 pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
                                 RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
#if defined(ARGUS_THREADS)
                                 pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
                                 break;

                              case 'N': 
                                 olddir = ArgusSearchDirection;
                                 ArgusSearchDirection = (ArgusSearchDirection == ARGUS_FORWARD) ?  ARGUS_BACKWARD : ARGUS_FORWARD;
                              case 'n': {
                                 if ((retn == RAGOTslash) && strlen(RaCommandInputStr)) {
                                    int linenum;
                                    int cursx = RaWindowCursorX, cursy = RaWindowCursorY + RaWindowStartLine;
                                    if ((linenum = RaSearchDisplay(ArgusParser, RaTopProcess->queue,
                                          ArgusSearchDirection, &cursx, &cursy, RaCommandInputStr)) < 0) {

                                       if (ArgusSearchDirection == ARGUS_FORWARD) {
                                          sprintf (ArgusParser->RaDebugString, "search hit BOTTOM, continuing at TOP");
                                          cursx = 0; cursy = 0;
                                       } else {
                                          sprintf (ArgusParser->RaDebugString, "search hit TOP, continuing at BOTTOM");
                                          cursx = RaScreenColumns; cursy = RaTopProcess->queue->count;
                                       }
                                       linenum = RaSearchDisplay(ArgusParser, RaTopProcess->queue,
                                          ArgusSearchDirection, &cursx, &cursy, RaCommandInputStr);
                                    }
                                    if (linenum >= 0) {
                                       if ((linenum < RaWindowStartLine) || ((linenum > RaWindowStartLine + RaDisplayLines))) {
                                          int startline = ((cursy - 1)/ RaDisplayLines) * RaDisplayLines;
                                          startline = (RaTopProcess->queue->count > startline) ? startline : RaTopProcess->queue->count - RaDisplayLines;
                                          startline = (startline > 0) ? startline : 0;
                                          RaWindowStartLine = startline;

                                          if ((RaWindowCursorY = cursy % RaDisplayLines) == 0)
                                             RaWindowCursorY = RaDisplayLines;

                                       } else
                                          RaWindowCursorY = cursy - RaWindowStartLine;

                                       RaWindowCursorX = cursx;
                                       ArgusUpdateScreen();
                                    } 
                                 }
                                 if (olddir != -1)
                                    ArgusSearchDirection = olddir;
                                 break;
                              }

                              case KEY_LEFT:
                              case 'h': {
                                 RaWindowCursorX--;
                                 if (RaWindowCursorX < 0) {
                                    RaWindowCursorX = 0;
                                    beep();
                                 }
                                 break;
                              }
                              case 'j': 
                              case 0x05:
                              case 0x0E:
                              case KEY_DOWN: {
                                 RaWindowCursorY++;
                                 if ((RaTopProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
                                    int maxwincount = RaTopProcess->queue->count - RaWindowStartLine;
                                    if (RaWindowCursorY > maxwincount) {
                                       RaWindowCursorY = maxwincount;
                                       beep();
                                    }

                                 } else {
                                    if (RaWindowCursorY > RaDisplayLines) {
                                       if ((RaTopProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                                          RaWindowStartLine++;
                                          wscrl(RaAvailableWindow, 1);
                                          ArgusUpdateScreen();
                                       } else
                                          beep();

                                       RaWindowCursorY = RaDisplayLines;
                                    }
                                 }
                                 break;
                              }

                              case 0x19:
                              case KEY_UP:
                              case 'k': {
                                 RaWindowCursorY--;
                                 if (RaWindowCursorY < 1) {
                                    RaWindowCursorY = 1;
                                    if (RaWindowStartLine > 0) {
                                       RaWindowStartLine--;
                                       wscrl(RaAvailableWindow, -1);
                                       ArgusUpdateScreen();
                                    } else
                                       beep();
                                 }
                                 break;
                              }

                              case KEY_RIGHT:
                              case 'l': {
                                 int startline = RaWindowCursorY + RaWindowStartLine;
                                 struct ArgusRecordStruct *ns;

                                 if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {
                                    char buf[MAXSTRLEN];
                                    int len;

                                    *(unsigned int *)buf = 0;
                                    ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);

                                    len = strlen(buf);
                                    RaWindowCursorX++;
                                    if (RaWindowCursorX >= len) {
                                       RaWindowCursorX = len - 1;
                                       beep();
                                    }
                                 }
                                 break;
                              }

                              case 'g':
                              case KEY_HOME:
                                 if (RaWindowStartLine != 0) {
                                    RaWindowStartLine = 0;
                                    RaWindowModified++;
                                 } else
                                    beep();
                                 break;

                              case 'G':
                              case KEY_END:
                                 if (RaWindowStartLine != (RaTopProcess->queue->count - RaDisplayLines)) {
                                    RaWindowStartLine = RaTopProcess->queue->count - RaDisplayLines;
                                    if (RaWindowStartLine < 0)
                                       RaWindowStartLine = 0;
                                    RaWindowModified++;
                                 } else
                                    beep();
                                 break;
                              case 0x06:
                              case 0x04:
                              case ' ':
                              case KEY_NPAGE: {
                                 int count = (RaSortItems - RaWindowStartLine) - 1;
                                 if (count > RaDisplayLines) {
                                    RaWindowStartLine += RaDisplayLines;
                                    wscrl(RaWindow, RaDisplayLines);
                                    RaWindowModified++;
                                 } else {
                                    if (count) {
                                       RaWindowStartLine += count;
                                       wscrl(RaWindow, count);
                                       RaWindowModified++;
                                    } else
                                       beep();
                                 }
                                 break;
                              }

                              case 0x02:
                              case 0x15:
                              case KEY_PPAGE:
                                 if (RaWindowStartLine > 0) { 
                                    wscrl(RaWindow, (RaDisplayLines > RaWindowStartLine) ? -RaWindowStartLine : -RaDisplayLines);
                                    RaWindowStartLine -= RaDisplayLines;
                                    if (RaWindowStartLine < 0)
                                       RaWindowStartLine = 0;
                                    RaWindowModified++;
                                 } else
                                    beep();
                                 break;

                              case 'b': {
                                 int startline = RaWindowCursorY + RaWindowStartLine;
                                 struct ArgusRecordStruct *ns;

                                 if ((RaWindowCursorX == 0)) {
                                    if (RaWindowCursorY > 1) {
                                          RaWindowCursorY--;
                                    } else {
                                       if (RaWindowStartLine > 0) {
                                          RaWindowStartLine--;
                                          ArgusUpdateScreen();
                                       } else {
                                          beep();
                                          break;
                                       }
                                    }

                                    startline = RaWindowCursorY + RaWindowStartLine;
                                    if (startline == 0) {
                                       startline = 1;
                                    }
                                 }

                                 if (RaSortItems >= startline) {
                                    if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {
                                       char buf[MAXSTRLEN], *ptr;
                                       *(unsigned int *)buf = 0;
                                       ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);

                                       if (RaWindowCursorX == 0)
                                          RaWindowCursorX = strlen(buf) - 1;

                                       if ((ptr = &buf[RaWindowCursorX]) != NULL) {
                                          while ((ptr > buf) && isspace((int)*(ptr - 1)))
                                             ptr--;

                                          if (ispunct((int)*(--ptr))) {
                                             while ((ptr > buf) && ispunct((int)*(ptr - 1)))
                                                ptr--;
                                          } else {
                                             while ((ptr > buf) && !(isspace((int)*(ptr - 1)) || ispunct((int)*(ptr - 1))))
                                                ptr--;
                                          }
                                          RaWindowCursorX = ptr - buf;
                                       }
                                    }
                                 }
                                 break;
                              }

                              case 'w': {
                                 int startline = RaWindowCursorY + RaWindowStartLine;
                                 struct ArgusRecordStruct *ns;

                                 if (startline == 0)
                                    startline = 1;

                                 if (RaSortItems >= startline) {
                                    int done = 0;
                                    int shifted = 0;

                                    while (!done) {
                                       if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {
                                          char buf[MAXSTRLEN], *ptr;
                                          int cursor, passpunct = 0;

                                          *(unsigned int *)buf = 0;
                                          ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);

                                          if (!shifted) {
                                             cursor = RaWindowCursorX + 1;
                                             if (ispunct((int)buf[RaWindowCursorX]))
                                                passpunct = 1;
                                          } else
                                             cursor = RaWindowCursorX;

                                          if ((ptr = &buf[cursor]) != NULL) {
                                             if (!shifted)
                                                while ((*ptr != '\0') && !(isspace((int)*ptr)) && (passpunct ? ispunct((int)*ptr) : !(ispunct((int)*ptr))))
                                                   ptr++;
                                             while (isspace((int)*ptr) && (*ptr != '\0'))
                                                ptr++;
                                             if (*ptr != '\0') {
                                                RaWindowCursorX = ptr - buf;
                                                done++;
                                             } else {
                                                if (RaWindowCursorY == RaDisplayLines) {
                                                   if (RaTopProcess->queue->array[startline] != NULL) {
                                                      shifted++;
                                                      startline++;
                                                      RaWindowStartLine++;
                                                      ArgusUpdateScreen();
                                                      RaWindowCursorX = 0;
                                                   }
                                                } else {
                                                   shifted++;
                                                   startline++;
                                                   RaWindowCursorY++;
                                                   RaWindowCursorX = 0;
                                                }
                                             }
                                          }
                                       }
                                    }
                                 }
                                 break;
                              }

                              case '0':
                              case '^': {
                                 RaWindowCursorX = 0;
                                 break;
                              }
                              case '$': {
                                 int startline = RaWindowCursorY + RaWindowStartLine;
                                 struct ArgusRecordStruct *ns;

                                 if (startline == 0)
                                    startline = 1;

                                 if (RaSortItems >= startline) {
                                    if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {
                                       char buf[MAXSTRLEN];
                                       *(unsigned int *)buf = 0;
                                       ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);
                                       if ((RaWindowCursorX = strlen(buf) - 1) < 0)
                                          RaWindowCursorX = 0;
                                    }
                                 }
                                 break;
                              }

                              case '?':
#if defined(ARGUS_READLINE)
                                 argus_getsearch_string(ARGUS_BACKWARD);
#else
                                 retn = RAGETTINGslash;
                                 RaInputString = "?";
                                 ArgusSearchDirection = ARGUS_BACKWARD;
                                 bzero(RaCommandInputStr, MAXSTRLEN);
                                 RaCommandIndex = 0;
                                 RaWindowCursorX = 0;
#endif
                                 break;

                              case '/':
#if defined(ARGUS_READLINE)
                                 argus_getsearch_string(ARGUS_FORWARD);
#else
                                 retn = RAGETTINGslash;
                                 RaInputString = "/";
                                 ArgusSearchDirection = ARGUS_FORWARD;
                                 bzero(RaCommandInputStr, MAXSTRLEN);
                                 RaCommandIndex = 0;
                                 RaWindowCursorX = 0;
#endif
                                 break;

                              case ':': {
#if defined(ARGUS_READLINE)
                                 argus_command_string();
#else
                                 retn = RAGETTINGcolon;
                                 RaInputString = ":";
                                 bzero(RaCommandInputStr, MAXSTRLEN);
                                 RaCommandIndex = 0;
                                 RaWindowCursorX = 0;
#endif
                                 break;
                              }
                           }
                           break;
                        }

                        case RAGETTINGq:
                           if (*RaCommandInputStr == 'y') {
                              RaParseComplete(SIGINT);
                           } else {
                              retn = RAGOTslash;
                              RaInputString = RANEWCOMMANDSTR;
                              RaCommandInputStr[0] = '\0';
                              RaCommandIndex = 0;
                           }
                           break;


                        case RAGETTINGcolon: {
                           if (RaCommandIndex == 0) {
                              switch (ch) {
                                 case '%': {
                                    ArgusParser->Pctflag = (ArgusParser->Pctflag == 1) ? 0 : 1;
                                    if (ArgusParser->Pctflag)
                                       RaInputString = "Toggle percent on";
                                    else
                                       RaInputString = "Toggle percent off";
                                    break;
                                 }

                                 case 'a': {
                                    retn = RAGETTINGa;
                                    RaInputString = RAGETTINGaSTR;
                                    break;
                                 }
#if defined(ARGUSMYSQL)
                                 case 'B':
                                    RaInputStatus = RAGETTINGB;
                                    RaInputString = RAGETTINGBSTR;
                                    break;
#endif

                                 case 'c': {
#if defined(ARGUSMYSQL)
                                    if (RaMySQL == NULL) {
                                       char strbuf[MAXSTRLEN];

                                       RaInputStatus = RAGETTINGc;
                                       RaInputString = RAGETTINGcSTR;

                                       if (ArgusParser->writeDbstr != NULL)
                                          sprintf (&strbuf[strlen(strbuf)], "-w %s", ArgusParser->writeDbstr);

                                       sprintf (RaCommandInputStr, "%s", strbuf);
                                       RaCommandIndex = strlen(RaCommandInputStr);
                                    }
#endif
                                    break;
                                 }

                                 case 'd': {
                                    retn = RAGETTINGd;
                                    RaInputString = RAGETTINGdSTR;

                                    if (ArgusParser->ArgusRemoteHostList) {
                                       struct ArgusInput *input = (void *)ArgusParser->ArgusActiveHosts->start;
                                       do {
                                          sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s:%d", input->hostname, input->portnum);
                                          RaCommandIndex = strlen(RaCommandInputStr); 
                                          input = (void *)input->qhdr.nxt;
                                       } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
                                    } else {
#if defined(ARGUSMYSQL)
                                       if (RaMySQL) {
                                          sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", RaDatabase);
                                          if (RaHost)
                                             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "@%s", RaHost);
                                          RaCommandIndex = strlen(RaCommandInputStr);
                                       }
#endif
                                    }

                                    break;
                                 }
                   
                                 case 'D': {
                                    retn = RAGETTINGD;
                                    RaInputString = RAGETTINGDSTR;
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->debugflag);
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;
                                 }

                                 case 'f': {
                                    retn = RAGETTINGf;
                                    RaInputString = RAGETTINGfSTR;
                                    RaFilterIndex = 3;
                                    if (ArgusParser->ArgusRemoteFilter) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " remote %s", ArgusParser->ArgusRemoteFilter);
                                       RaCommandIndex = strlen(RaCommandInputStr); 
                                       RaFilterIndex = ARGUS_REMOTE_FILTER;
                                    } else
                                    if (ArgusParser->ArgusLocalFilter) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " local %s", ArgusParser->ArgusLocalFilter);
                                       RaCommandIndex = strlen(RaCommandInputStr); 
                                       RaFilterIndex = ARGUS_LOCAL_FILTER;
                                    } else
                                    if (ArgusParser->ArgusDisplayFilter) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " display %s", ArgusParser->ArgusDisplayFilter);
                                       RaCommandIndex = strlen(RaCommandInputStr); 
                                       RaFilterIndex = ARGUS_DISPLAY_FILTER;
                                    }
                                    break;
                                 }

                                 case 'm': {
                                    struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
                                    struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
                                    int i;

                                    retn = RAGETTINGm;
                                    RaInputString = RAGETTINGmSTR;

                                    if (agg->modeStr != NULL) {
                                       sprintf (RaCommandInputStr, "%s", agg->modeStr);
                                    } else {
                                       for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                                          if (agg->mask & (0x01LL << i)) {
                                             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", ArgusMaskDefs[i].name);

                                             switch (i) {
                                                case ARGUS_MASK_SADDR:
                                                   if (agg->saddrlen > 0)
                                                      sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->saddrlen);
                                                   break;
                                                case ARGUS_MASK_DADDR:
                                                   if (agg->daddrlen > 0)
                                                      sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->daddrlen);
                                                   break;
                                             }
                                          }
                                       }
                                       agg->modeStr = strdup(RaCommandInputStr);
                                    }

                                    RaCommandIndex = strlen(RaCommandInputStr);
                                    break;
                                 }

                                 case 'M': {
                                    struct ArgusModeStruct *mode;
                                    retn = RAGETTINGM;
                                    RaInputString = RAGETTINGMSTR;
                           
                                    if ((mode = ArgusParser->ArgusModeList) != NULL) {
                                       while (mode) {
                                          sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", mode->mode);
                                          mode = mode->nxt;
                                       }
                                    }
                                    RaCommandIndex = strlen(RaCommandInputStr);
                                    break;
                                 }

                                 case 'N':
                                    retn = RAGETTINGN;
                                    RaInputString = RAGETTINGNSTR;
                                    break;

                                 case 'p': {
                                    retn = RAGETTINGp;
                                    RaInputString = RAGETTINGpSTR;
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->pflag);
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;
                                 }

                                 case 'P': {
                                    double rate  = RaUpdateRate;
                                    double pause = ArgusParser->Pauseflag;

                                    ArgusParser->Pauseflag = (pause > 0.0) ? 0.0 : rate;
                                    RaUpdateRate = (rate > 0.0) ? 0.0 : pause;

                                    if (ArgusParser->Pauseflag)
                                       RaInputString = "Paused";
                                    else
                                       RaInputString = "";
                                    break;
                                 }

                                 case 't':
                                    retn = RAGETTINGt;
                                    RaInputString = RAGETTINGtSTR;
                                    if (ArgusParser->timearg) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusParser->timearg);
                                       RaCommandIndex = strlen(RaCommandInputStr); 
                                    }
                                    break;

                                 case 'T':
                                    retn = RAGETTINGT;
                                    RaInputString = RAGETTINGTSTR;
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.%6d", 
                                       (int)ArgusParser->timeout.tv_sec, (int)ArgusParser->timeout.tv_usec);
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;

                                 case 'R': {
                                    struct ArgusInput *input = ArgusParser->ArgusInputFileList;
                                    retn = RAGETTINGR;
                                    RaInputString = RAGETTINGRSTR;
                                    while (input) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", input->filename);
                                       RaCommandIndex = strlen(RaCommandInputStr); 
                                       input = (void *)input->qhdr.nxt;
                                    }
                                    break;
                                 }

                                 case 'r': {
                                    struct ArgusInput *input = ArgusParser->ArgusInputFileList;
                                    retn = RAGETTINGr;
                                    RaInputString = RAGETTINGrSTR;
                                    while (input) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", input->filename);
                                       RaCommandIndex = strlen(RaCommandInputStr); 
                                       input = (void *)input->qhdr.nxt;
                                    }
                                    break;
                                 }

                                 case 'S': {
                                    struct ArgusInput *input = ArgusParser->ArgusRemoteHostList;
                                    retn = RAGETTINGS;
                                    RaInputString = RAGETTINGSSTR;
                                    while (input) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s:%d", input->hostname, input->portnum);
                                       RaCommandIndex = strlen(RaCommandInputStr); 
                                       input = (void *)input->qhdr.nxt;
                                    }
                                    break;
                                 }

                                 case 's': {
                                    int x, y;
                                    retn = RAGETTINGs;
                                    RaInputString = RAGETTINGsSTR;
                                    for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                                       if (ArgusSorter->ArgusSortAlgorithms[x]) {
                                          for (y = 0; y < ARGUS_MAX_SORT_ALG; y++) {
                                             if (ArgusSorter->ArgusSortAlgorithms[x] == ArgusSortAlgorithmTable[y]) {
                                                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", 
                                                      ArgusSortKeyWords[y]);
                                                break;
                                             }
                                          }
                                       }
                                    }
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;
                                 }

                                 case 'u':
                                    retn = RAGETTINGu;
                                    RaInputString = RAGETTINGuSTR;
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.", (int) RaTopUpdateInterval.tv_sec);
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%06d",(int) RaTopUpdateInterval.tv_usec);
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;

                                 case 'U':
                                    retn = RAGETTINGU;
                                    RaInputString = RAGETTINGUSTR;
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%2.2f", RaUpdateRate);
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;

                                 case 'w':
                                    retn = RAGETTINGw;
                                    RaInputString = RAGETTINGwSTR;
                                    break;

                                 case 'F': 
                                    retn = RAGETTINGF;
                                    RaInputString = RAGETTINGFSTR;

                                    if (ArgusPrintRank)
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "rank:%d ", ArgusRankSize);

                                    for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                                       int y;
                                       if (parser->RaPrintAlgorithmList[x] != NULL) {
                                          for (y = 0; y < MAX_PRINT_ALG_TYPES; y++) {
                                             if ((void *) parser->RaPrintAlgorithmList[x]->print == (void *) RaPrintAlgorithmTable[y].print) {
                                                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ",
                                                   RaPrintAlgorithmTable[y].field, RaPrintAlgorithmTable[y].length);
                                                break;
                                             }
                                          }
                                       } else
                                          break;
                                    }
                                    RaCommandIndex = strlen(RaCommandInputStr);
                                    break;

                                 case 'Q':
                                    retn = RAGETTINGq;
                                    RaInputString = RAGETTINGqSTR;
                                    break;

                                 case 'H':
                                    ArgusParser->Hflag = ArgusParser->Hflag ? 0 : 1;
                                    break;

                                 case 'h':
                                    retn = RAGETTINGh;
                                    RaInputString = RAGETTINGhSTR;
                                    RaWindowStatus = 0;
                                    RaOutputHelpScreen();
                                    break;

                                 case 'n':
                                    if (++ArgusParser->nflag > 3) {
                                       ArgusParser->nflag = 0;
                                    }
                                    break;

                                 case 'v': 
                                    if (ArgusParser->vflag) {
                                       ArgusParser->vflag = 0;
                                       ArgusReverseSortDir = 0;
                                    } else {
                                       ArgusParser->vflag = 1;
                                       ArgusReverseSortDir++;
                                    }
#if defined(ARGUS_THREADS)
                                    pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
                                    RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
#if defined(ARGUS_THREADS)
                                    pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
                                    break;

                                 case '=':  {
                                    struct ArgusRecordStruct *ns = NULL;

                                    werase(RaWindow);
                                    ArgusUpdateScreen();

                                    while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_LOCK)) != NULL)
                                       RaMySQLDeleteRecords(ArgusParser, ns);

                                    ArgusEmptyHashTable(RaTopProcess->htable);

                                    if (ArgusParser->ns != NULL) {
                                       ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                                       ArgusParser->ns = NULL;
                                    }

                                    ArgusParser->RaClientUpdate.tv_sec = 0;
                                    ArgusParser->ArgusTotalRecords = 0;
                                    RaTopStartTime.tv_sec = 0;
                                    RaTopStartTime.tv_usec = 0;
                                    RaTopStopTime.tv_sec = 0;
                                    RaTopStopTime.tv_usec = 0;
                                    break;
                                 }

                                 case 'z':  
                                    if (++ArgusParser->zflag > 1) {
                                       ArgusParser->zflag = 0;
                                    }
                                    break;

                                 case 'Z':  
                                    switch (ArgusParser->Zflag) {
                                       case '\0': ArgusParser->Zflag = 'b'; break;
                                       case  'b': ArgusParser->Zflag = 's'; break;
                                       case  's': ArgusParser->Zflag = 'd'; break;
                                       case  'd': ArgusParser->Zflag = '\0'; break;
                                    }
                                    break;

                                 default:
                                    RaCommandInputStr[RaCommandIndex++] = ch;
                                    break;

                              }
                              break;
                           }

                        }

                        default: {
                           switch (ch) {
                              case KEY_RIGHT:
                                 if (--RaCursorOffset < 0)
                                    RaCursorOffset = 0;
                                 break;
                              case KEY_LEFT:
                                 if (++RaCursorOffset > RaCommandIndex)
                                    RaCursorOffset = RaCommandIndex;
                                 break;
        
                              default:
                                 if (isascii(ch)) {
                                    if (RaCursorOffset == 0) 
                                       RaCommandInputStr[RaCommandIndex++] = ch;
                                    else {
                                       int z, start; 
                                       start = RaCommandIndex - RaCursorOffset;
                                       for (z = RaCommandIndex; z > start; z--)
                                          RaCommandInputStr[z] = RaCommandInputStr[z-1];

                                       RaCommandInputStr[start] = ch;
                                       RaCommandIndex++;
                                    }
                                 }
                           }
                           break;
                        }
                     }
                  }
                  break;
               }
            }
         }
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (2, "ArgusProcessCommand (0x%x, %d, %d)", parser, status, ch);
#endif

   return (retn);
}
#endif



void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

#if defined(ARGUS_CURSES)
   if (!ArgusParser->dflag)
      ArgusWindowClose();
#endif

   fprintf (stderr, "RaSqlInsert Version %s\n", version);
   fprintf (stderr, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [ra-options] [specific-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);

#if defined (ARGUSDEBUG)
   fprintf (stderr, "         -D <level>         specify debug level\n");
#endif
   fprintf (stderr, "         -M <mode>          specify modes\n");
   fprintf (stderr, "             cache          use the database table contents as cache\n");
   fprintf (stderr, "             nodrop         do not delete the table if it exists\n");
   fprintf (stderr, "         -R <directory>     recursively process argus data files in directory.\n");
   fprintf (stderr, "\n");
   fprintf (stderr, "         -r <dbUrl>         read argus data to mysql database.\n");
   fprintf (stderr, "         -w <dbUrl>         write argus data to mysql database.\n");
   fprintf (stderr, "                            Rasqlinsert will create the database and table\n");
   fprintf (stderr, "                            if they do not exist.\n");
   fprintf (stderr, "\n");
   fprintf (stderr, "               dbUrl:       mysql://[user[:pass]@]host[:port]/db/table\n");
   fprintf (stderr, "\n");
   fprintf (stderr, "         -s [-][+[]]field   specify fields to print.\n");
   fprintf (stderr, "               fields:      record\n");
   exit(1);
}


/*
   RaProcessRecord - this routine will take a non-managment record and
   process it as if it were a SBP.  This basically means, transform the
   flow descriptor to whatever model is appropriate, find the flow
   cache.  Then we carve the new record into the appropriate size for
   the SBP operation, and then proceed to merge the fragments into the
   appropriate record for this ns.

   If the ns cache is a sticky ns, it may not be in the RaTopProcess
   queue, so we need to check and put it in if necessary.

   And because we had a record, we'll indicate that the window needs
   to be updated.

   All screen operations, queue timeouts etc, are done in 
   ArgusClientTimeout, so we're done here.

*/
void RaProcessRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   switch (ns->hdr.type & 0xF0) {
      case ARGUS_EVENT:
         break;
      case ARGUS_MAR:
         RaProcessManRecord(parser, ns);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns;

            if (flow != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
            RaProcessThisRecord(parser, ns);

#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
            tns = ArgusCopyRecordStruct(ns);
            ArgusReverseRecord(tns);

            if ((flow = (void *) tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif

            RaProcessThisRecord(parser, tns);

#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif

            ArgusDeleteRecordStruct(parser, tns);

         } else {
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;

            if (flow && agg && agg->ArgusMatrixMode) {
               if (agg->mask & ((0x01LL << ARGUS_MASK_SADDR) | (0x01LL << ARGUS_MASK_DADDR))) {
                  switch (flow->hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_LAYER_3_MATRIX:
                     case ARGUS_FLOW_CLASSIC5TUPLE: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              if (flow->ip_flow.ip_src > flow->ip_flow.ip_dst) 
                                 ArgusReverseRecord(ns);
                           }
                           break; 

                           case ARGUS_TYPE_IPV6: {
                              int i;
                              for (i = 0; i < 4; i++) {
                                 if (flow->ipv6_flow.ip_src[i] < flow->ipv6_flow.ip_dst[i])
                                    break;

                                 if (flow->ipv6_flow.ip_src[i] > flow->ipv6_flow.ip_dst[i]) {
                                    ArgusReverseRecord(ns);
                                    break;
                                 }
                              }
                           }
                           break; 
                        }
                        break; 
                     }

                     default:
                        break; 
                  }

               } else 
               if (agg->mask & ((0x01LL << ARGUS_MASK_SMAC) | (0x01LL << ARGUS_MASK_DMAC))) {
                  struct ArgusMacStruct *m1 = NULL;
                  if ((m1 = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX]) != NULL) {
                     switch (m1->hdr.subtype) {
                        case ARGUS_TYPE_ETHER: {
                           struct ether_header *e1 = &m1->mac.mac_union.ether.ehdr;
                           int i;

                           for (i = 0; i < 6; i++) {
#if defined(HAVE_SOLARIS)
                              if (e1->ether_shost.ether_addr_octet[i] < e1->ether_dhost.ether_addr_octet[i])
                                 break;
                              if (e1->ether_shost.ether_addr_octet[i] > e1->ether_dhost.ether_addr_octet[i]) {
                                 ArgusReverseRecord(ns);
                                 break;
                              }
#else
                              if (e1->ether_shost[i] < e1->ether_dhost[i])
                                 break;
                              if (e1->ether_shost[i] > e1->ether_dhost[i]) {
                                 ArgusReverseRecord(ns);
                                 break;
                              }
#endif
                           }
                           break;
                        }
                        case ARGUS_TYPE_IB_LOCAL: {
/*
                           struct ArgusIBMacFlow *i1 = &m1->mac.mac_union.ib;
*/
                           break;
                        }
                     }
                  }
               }
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
            RaProcessThisRecord(parser, ns);

#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif

         }
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessRecord (0x%x, 0x%x)\n", parser, ns);
#endif
}



void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tns = NULL, *pns = NULL, *cns = NULL;
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusTimeObject *time = (void *) ns->dsrs[ARGUS_TIME_INDEX];
   struct ArgusHashStruct *hstruct = NULL;
   struct ArgusFlow *flow = NULL;
   int found = 0;

   if (time != NULL) {
      ArgusThisTime.tv_sec  = time->src.start.tv_sec;
      ArgusThisTime.tv_usec = time->src.start.tv_usec;
   }

   if (ArgusLastTime.tv_sec == 0) {
      ArgusLastTime    = ArgusThisTime;
      ArgusCurrentTime = ArgusThisTime;
   }

   if (!((ArgusLastTime.tv_sec  > ArgusThisTime.tv_sec) ||
      ((ArgusLastTime.tv_sec == ArgusThisTime.tv_sec) &&
       (ArgusLastTime.tv_usec > ArgusThisTime.tv_usec)))) {

      while (!(RaUpdateRate)) {
         struct timespec ts = {0, 25000000};
         nanosleep (&ts, NULL);
         ArgusClientTimeout ();
      }

/* ok so lets deal with realtime processing */
      if (!(parser->Sflag) && (ArgusParser->status & ARGUS_REAL_TIME_PROCESS)) {
         if ((ArgusThisTime.tv_sec  > ArgusLastTime.tv_sec) ||
            ((ArgusThisTime.tv_sec == ArgusLastTime.tv_sec) &&
             (ArgusThisTime.tv_usec > ArgusLastTime.tv_usec))) {
            int thisRate;
            int deltausec;

/* this record is some period of time after the last record, so 
lets calculate the difference, and then sleep to deal with
time that needs to lapse */

            dRealTime = *RaDiffTime(&ArgusThisTime, &ArgusLastTime);
            thisUsec  = ((dRealTime.tv_sec * 1000000) + dRealTime.tv_usec);

            dRealTime = *RaDiffTime(&parser->ArgusRealTime, &ArgusLastRealTime);
            lastUsec  = ((dRealTime.tv_sec * 1000000) + dRealTime.tv_usec);

            parser->ArgusGlobalTime = ArgusLastTime;

            while ((deltausec = (thisUsec - (lastUsec * parser->ArgusTimeMultiplier))) > 0) {
               struct timespec ts;
               char gtime[256];

               int timeIncrement;

               thisRate = (deltausec > 50000) ? 50000 : deltausec;

               ts.tv_sec  = 0;
               ts.tv_nsec = thisRate * 1000;

#if defined(ARGUSDEBUG)
               bzero(gtime, sizeof(gtime));
               ArgusPrintTime(parser, gtime, &ArgusParser->ArgusGlobalTime);
               ArgusDebug (7, "ArgusProcessThisRecord () idling for %2.6f real seconds: globaltime %s\n", 
                      (ts.tv_sec * 1.0) + ((thisRate * 1.0)/ 1000000.0), gtime);

#endif
               nanosleep (&ts, NULL);

               timeIncrement = thisRate * parser->ArgusTimeMultiplier;
               parser->ArgusGlobalTime.tv_sec  += timeIncrement / 1000000;
               parser->ArgusGlobalTime.tv_usec += timeIncrement % 1000000;
               if (parser->ArgusGlobalTime.tv_usec > 1000000) {
                  parser->ArgusGlobalTime.tv_sec++;
                  parser->ArgusGlobalTime.tv_usec -= 1000000;
               }

               dRealTime = *RaDiffTime(&parser->ArgusRealTime, &ArgusLastRealTime);
               lastUsec  = ((dRealTime.tv_sec * 1000000) + dRealTime.tv_usec);

               ArgusClientTimeout ();
            }
         }
      }

      ArgusLastRealTime = parser->ArgusRealTime;
      ArgusLastTime     = ArgusThisTime;
      ArgusCurrentTime  = ArgusThisTime;
      parser->ArgusGlobalTime  = ArgusThisTime;
   }

   RaTopStopTime = parser->ArgusRealTime;
   if (ArgusParser->RaClientUpdate.tv_sec == 0) {
      ArgusParser->RaClientUpdate.tv_sec = parser->ArgusGlobalTime.tv_sec;
      ArgusParser->RaClientUpdate.tv_usec = 0;
   }
   if (RaTopStartTime.tv_sec == 0)
      RaTopStartTime = parser->ArgusRealTime;

#if defined(ARGUSMYSQL)
   {
      char *table;

      if (RaSQLSaveTable != NULL) {
         if ((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))) {
            table = ArgusCreateSQLSaveTableName(parser, ns, RaSQLSaveTable);
            if (RaSQLCurrentTable) {
               if (strncmp(RaSQLCurrentTable, table, strlen(table))) {
                  if ((ArgusLastTime.tv_sec   > ArgusThisTime.tv_sec) || 
                     ((ArgusLastTime.tv_sec  == ArgusThisTime.tv_sec) && 
                      (ArgusLastTime.tv_usec  > ArgusThisTime.tv_usec))) {

                     free (RaSQLCurrentTable);
                     RaSQLCurrentTable = NULL;
                  }
               }
            }

            if (RaSQLCurrentTable == NULL) {
               struct ArgusQueueStruct *queue = RaTopProcess->queue;
               struct ArgusRecordStruct *argus;
               int x, z, count;

               count = queue->count;

               for (x = 0, z = count; x < z; x++) {
                  if ((argus = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL)
                     ArgusDeleteRecordStruct(ArgusParser, argus);
               }

               ArgusCreateSQLSaveTable(table);
            }
         }
      }
   }
#endif

   while (agg && !found) {
      int retn = 0, fretn = -1, lretn = -1;
      if (agg->filterstr) {
         struct nff_insn *fcode = agg->filter.bf_insns;
         fretn = ArgusFilterRecord (fcode, ns);
      }

      if (agg->labelstr) {
         struct ArgusLabelStruct *label;
         if (((label = (void *)ns->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
            if (regexec(&agg->lpreg, label->l_un.label, 0, NULL, 0))
               lretn = 0;
            else
               lretn = 1;
         } else
            lretn = 0;
      }

      retn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

      if (retn != 0) {
         if (ns->dsrs[ARGUS_FLOW_INDEX] != NULL) {

            cns = ArgusCopyRecordStruct(ns);
            flow = (struct ArgusFlow *) cns->dsrs[ARGUS_FLOW_INDEX];

            if ((agg->rap = RaFlowModelOverRides(agg, cns)) == NULL)
               agg->rap = agg->drap;

            ArgusGenerateNewFlow(agg, cns);

            if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusGenerateHashStruct error %s", strerror(errno));

            if ((pns = ArgusFindRecord(RaTopProcess->htable, hstruct)) == NULL) {
               if ((!RaSQLDBDeletes) || (!ArgusCreateTable)) {
                  struct ArgusMaskStruct *ArgusMaskDefs =  ArgusSelectMaskDefs(ns);
                  char ubuf[1024], tbuf[1024], sbuf[MAXSTRLEN], buf[MAXSTRLEN];
                  char tmpbuf[MAXSTRLEN], *ptr, *tptr;
                  int uflag, nflag = parser->nflag;
                  int retn, i, y, mind = 0;
                  MYSQL_RES *mysqlRes;

                  parser->nflag = 2;

                  bzero(ubuf, sizeof(ubuf));
                  bzero(sbuf, sizeof(MAXSTRLEN));

                  for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
                     if (parser->RaPrintAlgorithmList[i] != NULL) {
                        parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[i];

                        found = 0;
                        bzero (tmpbuf, sizeof(tmpbuf));

                        if (agg && agg->mask) {
                           for (y = 0; y < ARGUS_MAX_MASK_LIST; y++) {
                              if (agg->mask & (0x01LL << y)) {
                                 if (!strcmp(parser->RaPrintAlgorithm->field, ArgusMaskDefs[y].name)) {
                                    found++;
                                 }
                              }
                           }
                        }

                        if (found) {
                           int len = parser->RaPrintAlgorithm->length;
                           len = (len > 256) ? len : 256;

                           if (mind++ > 0)
                              sprintf (&ubuf[strlen(ubuf)], " and ");

                           uflag = ArgusParser->uflag;
                           ArgusParser->uflag++;

                           parser->RaPrintAlgorithm->print(parser, tmpbuf, cns, len);

                           ArgusParser->uflag = uflag;

                           if ((ptr = ArgusTrimString(tmpbuf)) != NULL) {
                              sprintf (tbuf, "%s=\"%s\"", parser->RaPrintAlgorithm->field, ptr);
                              tptr = &ubuf[strlen(ubuf)];
                              sprintf (tptr, "%s", tbuf);
                           }
                        }
                     }
                  }

                  sprintf (sbuf, "SELECT record FROM %s WHERE %s", RaSQLCurrentTable, ubuf);
                  parser->nflag   = nflag;

#if defined(ARGUSDEBUG)
                  ArgusDebug (1, "ArgusProcessThisRecord () sql query %s\n", sbuf); 
#endif
                  if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
                     ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));
                  else {
                     if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
                        if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                           while ((row = mysql_fetch_row(mysqlRes))) {
                              unsigned long *lengths;
                              int x;

                              lengths = mysql_fetch_lengths(mysqlRes);
                              bzero(buf, sizeof(buf));

                              for (x = 0; x < retn; x++) {
                                 bcopy (row[x], buf, (int) lengths[x]);
                                 if ((((struct ArgusRecord *)buf)->hdr.type & ARGUS_FAR) ||
                                     (((struct ArgusRecord *)buf)->hdr.type & ARGUS_NETFLOW)) {
#ifdef _LITTLE_ENDIAN
                                    ArgusNtoH((struct ArgusRecord *) buf);
#endif
                                    if ((tns = ArgusGenerateRecordStruct (ArgusParser, ArgusInput, (struct ArgusRecord *) buf)) != NULL) {
                                       if ((pns = ArgusCopyRecordStruct(tns)) != NULL) {
                                          pns->htblhdr = ArgusAddHashEntry (RaTopProcess->htable, pns, hstruct);
                                          ArgusAddToQueue (RaTopProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
                                          gettimeofday (&pns->qhdr.logtime, 0L);
                                       }
                                    }
                                 }
                              }
                           }
                        }
                        mysql_free_result(mysqlRes);
                     }
                  }
               }
            }
         }

         if ((pns) && pns->qhdr.queue) {
            int lockstat = ARGUS_LOCK;

            if (pns->qhdr.queue == RaTopProcess->queue)
               lockstat = ARGUS_NOLOCK;

            ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, lockstat);
            ArgusAddToQueue (RaTopProcess->queue, &pns->qhdr, lockstat);
            pns->status |= ARGUS_RECORD_MODIFIED;
         }
         found++;

      } else
         agg = agg->nxt;
   }

   if (agg && cns) {
      if (!found)
         if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

      RaBinProcess->nadp.stperiod = 0.0;
      RaBinProcess->nadp.dtperiod = 0.0;

      while ((tns = ArgusAlignRecord(parser, cns, &RaBinProcess->nadp)) != NULL) {
         int offset = 0;

         if (pns) {
            if (pns->bins) {
               offset = parser->Bflag / pns->bins->size;
               pns->bins->nadp.RaStartTmStruct = RaBinProcess->nadp.RaStartTmStruct;
               pns->bins->nadp.RaEndTmStruct   = RaBinProcess->nadp.RaEndTmStruct;

               if (!(ArgusInsertRecord (parser, pns->bins, tns, offset)))
                  ArgusDeleteRecordStruct(ArgusParser, tns);

               pns->bins->status |= RA_DIRTYBINS;

            } else {
               if (parser->RaCumulativeMerge)
                  ArgusMergeRecords (ArgusParser->ArgusAggregator, pns, tns);
               else {
                  int i;
                  for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
                     if (tns->dsrs[i] != NULL) {
                        if (pns->dsrs[i] != NULL)
                           ArgusFree(pns->dsrs[i]);
                        pns->dsrs[i] = tns->dsrs[i];
                        tns->dsrs[i] = NULL;
                     }
                  }
               }

               ArgusDeleteRecordStruct(ArgusParser, tns);
               pns->status |= ARGUS_RECORD_MODIFIED;
            }

            ArgusRemoveFromQueue(RaTopProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
            ArgusAddToQueue (RaTopProcess->queue, &pns->qhdr, ARGUS_NOLOCK);

         } else {
            if ((pns =  ArgusCopyRecordStruct(tns)) != NULL) { /* new record */
               if (RaBinProcess->nadp.mode == ARGUSSPLITRATE) {
                  if ((pns->bins = (struct RaBinProcessStruct *)ArgusNewRateBins(parser, pns)) == NULL)
                     ArgusLog (LOG_ERR, "ArgusProcessThisRecord: ArgusNewRateBins error %s", strerror(errno));

                  offset = parser->Bflag / pns->bins->size;

                  if (!(ArgusInsertRecord (parser, pns->bins, tns, offset))) 
                     ArgusDeleteRecordStruct(ArgusParser, tns);

                  pns->bins->status |= RA_DIRTYBINS;

               } else
                  ArgusDeleteRecordStruct(ArgusParser, tns);

               pns->status |= ARGUS_RECORD_MODIFIED;
               pns->htblhdr = ArgusAddHashEntry (RaTopProcess->htable, pns, hstruct);
               ArgusAddToQueue (RaTopProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
            }
         }

         RaWindowModified = 1;
      }

      ArgusDeleteRecordStruct(ArgusParser, cns);

   } else {
/* no key, so we're just inserting the record at the end of the table */
      char sbuf[MAXSTRLEN];
      ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, ns, sbuf, ARGUS_STATUS);
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessThisRecord () returning\n"); 
#endif
}

void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
 
#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessManRecord () returning\n"); 
#endif
}

int RaSendArgusRecord(struct ArgusRecordStruct *ns) {return 0;}

void ArgusWindowClose(void);
int ArgusWindowClosing = 0;

void
ArgusWindowClose(void)
{ 
   if (!(ArgusWindowClosing++)) {
#if defined(ARGUS_CURSES)
      if (!ArgusParser->dflag) {
         struct timeval tvbuf, *tvp = &tvbuf;
         fd_set in;
         int ch;

         if (RaCursesInit && (!(isendwin()))) {
            tvp->tv_sec = 0; tvp->tv_usec = 0;
            FD_ZERO(&in); FD_SET(0, &in);

            while (select(1, &in, 0, 0, tvp) > 0)
               if ((ch = wgetch(RaWindow)) == ERR)
                  break;

            endwin();
            printf("\n");
         }
      }
#endif
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}


#if defined(ARGUS_CURSES)
int 
RaInitCurses (struct ArgusParserStruct *parser)
{
   RaCursesInit++;

   parser->RaCursesMode = 1;

#if defined(HAVE_SETENV)
   if (setenv("ESCDELAY", "0", 1) < 0)
      sprintf (ArgusParser->RaDebugString, "setenv(ESCDELAY, 0, 1) error %s", strerror(errno));
#else
   {
      char buf[16];
      sprintf (buf, "ESCDELAY=0");
      if (putenv(buf) < 0)
         sprintf (ArgusParser->RaDebugString, "putenv(%s) error %s", buf, strerror(errno));
   }
#endif

   RaWindow = initscr();
/*
   if (has_colors() == TRUE) {
      ArgusTerminalColors++;
      start_color();
   }
*/
   cbreak();
#if defined(ARGUS_READLINE)
   keypad(stdscr, FALSE);
#else
   keypad(stdscr, TRUE);
#endif
   meta(stdscr, TRUE);
   nodelay(RaWindow, TRUE);
   noecho();
   nonl();
   intrflush(stdscr, FALSE);

   clearok(RaWindow, TRUE);
   werase(RaWindow);
   wrefresh(RaWindow);

   getmaxyx(RaWindow, RaScreenLines, RaScreenColumns);
 
   RaHeaderWindow = newwin (RaHeaderWinSize, RaScreenColumns, 0, 0);
   RaWindowLines  = RaScreenLines - (RaHeaderWinSize + 1);
   RaWindowStartLine = 0;
   RaDisplayLines = RaWindowLines - 2;

   RaAvailableWindow = newwin (RaWindowLines, RaScreenColumns, RaHeaderWinSize, 0);

   idlok (RaAvailableWindow, TRUE);
   notimeout(RaAvailableWindow, TRUE);
   nodelay(RaWindow, TRUE);
   intrflush(RaWindow, FALSE);
   refresh();

#if defined(ARGUS_READLINE)
   rl_resize_terminal();
#endif

   return (1);
}


void
RaResizeScreen(void)
{
   struct winsize size;

   if (ioctl(fileno(stdout), TIOCGWINSZ, &size) == 0) {
#if defined(__FreeBSD__) || (__NetBSD__) || (__OpenBSD__)
      resizeterm(size.ws_row, size.ws_col);
#else
#if defined(HAVE_SOLARIS)
#else
      resize_term(size.ws_row, size.ws_col);
#endif
#endif
      wrefresh(RaWindow);   /* Linux needs this */
   }

   getmaxyx(RaWindow, RaScreenLines, RaScreenColumns);

   RaScreenLines = RaScreenLines;
   RaScreenColumns = RaScreenColumns;

   RaWindowLines = RaScreenLines - (RaHeaderWinSize + 1);
/*
   if (RaDisplayLines > (RaWindowLines - 2))
      RaDisplayLines = (RaWindowLines - 2);
*/
#if !defined(HAVE_SOLARIS)
   wresize(RaWindow, RaScreenLines, RaScreenColumns);
   wresize(RaHeaderWindow, RaHeaderWinSize, RaScreenColumns);
   wresize(RaAvailableWindow, RaScreenLines - RaHeaderWinSize, RaScreenColumns);
#else
   delwin(RaHeaderWindow);
   RaHeaderWindow = newwin (RaHeaderWinSize, RaScreenColumns, 0, 0);
   idlok (RaHeaderWindow, TRUE);
   notimeout(RaHeaderWindow, TRUE);
 
   delwin(RaAvailableWindow);
   RaAvailableWindow = newwin (RaWindowLines, RaScreenColumns, RaHeaderWinSize, 0);
   idlok (RaAvailableWindow, TRUE);
   notimeout(RaAvailableWindow, TRUE);
#endif/* HAVE_SOLARIS */

   idlok (RaWindow, TRUE);
   notimeout(RaWindow, TRUE);
   nodelay(RaWindow, TRUE);
   intrflush(RaWindow, FALSE);

   RaWindow = initscr();
   wclear(RaWindow);

   ArgusParser->RaLabel = NULL;

   ArgusUpdateScreen();
   RaRefreshDisplay(ArgusParser);

   RaScreenResize = FALSE;
}


void
RaOutputModifyScreen ()
{
   int i = 0;
   werase(RaAvailableWindow);
 
   for (i = RaMinCommandLines; i < (RaMaxCommandLines + 1); i++) {
      mvwprintw (RaAvailableWindow, i, 1, RaCommandArray[i - RaMinCommandLines]);
      if (i == RaMinCommandLines)
         wstandout(RaAvailableWindow);
      wprintw (RaAvailableWindow, "%s", RaCommandValueArray[i - RaMinCommandLines]());
      if (i == RaMinCommandLines)
         wstandend(RaAvailableWindow);
   }
}

void
RaOutputHelpScreen ()
{
   extern char version[];
   werase(RaAvailableWindow);
   mvwprintw (RaAvailableWindow, 0, 1, "RaTop Version %s\n", version);
   mvwprintw (RaAvailableWindow, 1, 1, "Key Commands: c,d,D,f,F,h,m,n,N,p,P,q,r,R,s,S,t,T,u,U,v,w,z,Z,=");
   mvwprintw (RaAvailableWindow, 3, 1, "  ^D - Clear command line. Reset input (also ESC).");
   mvwprintw (RaAvailableWindow, 4, 1, "   c - Connect to remote Argus Source");
   mvwprintw (RaAvailableWindow, 5, 1, "   d - Drop connection from remote argus source");
   mvwprintw (RaAvailableWindow, 6, 1, "   D - Set debug printing level");
   mvwprintw (RaAvailableWindow, 7, 1, "   f - Specify filter expression");
   mvwprintw (RaAvailableWindow, 8, 1, "   F - Specify fields to print (use arrow keys to navigate).");
   mvwprintw (RaAvailableWindow, 9, 1, "         +[#]field - add field to optional column # or end of line");
   mvwprintw (RaAvailableWindow,10, 1, "         -field    - remove field from display");
   mvwprintw (RaAvailableWindow,11, 1, "          field    - reset fields and add to display");
   mvwprintw (RaAvailableWindow,12, 1, "             available fields are:");
   mvwprintw (RaAvailableWindow,13, 1, "               srcid, stime, ltime, dur, avgdur, trans, flgs, dir, state, seq, bins, binnum");
   mvwprintw (RaAvailableWindow,14, 1, "               mac, smac, dmac, mpls, smpls, dmpls, vlan, svlan, dvlan, svid, dvid, svpri, dvpri");
   mvwprintw (RaAvailableWindow,15, 1, "               saddr, daddr, snet, dnet, proto, sport, dport, stos, dtos, sttl, dttl, sipid, dipid");
   mvwprintw (RaAvailableWindow,16, 1, "               tcpext, tcprtt, stcpb, dtcpb, swin, dwin, srng, drng, spksz, dpksz, smaxsz, sminsz, dmaxsz, dminsz");
   mvwprintw (RaAvailableWindow,17, 1, "               suser, duser, svc, pkts, spkts, dpkts, load,sload, dload, bytes, sbytes, dbytes, rate, srate, drate");
   mvwprintw (RaAvailableWindow,18, 1, "               sloss, dloss, sintpkt, dintpkt, sjit, djit, sintpktact, dintpktact, sintpktidl, dintpktidl");
   mvwprintw (RaAvailableWindow,19, 1, "               sjitidl, djitidl, ddur, dstime, dltime, dspkts, ddpkts, dsbytes, ddbytes");
   mvwprintw (RaAvailableWindow,20, 1, "               djitact, jitidl, sjitidl, djitidl, state, ddur, dstime, dltime, dspkts, ddpkts");
   mvwprintw (RaAvailableWindow,21, 1, "   m - Specify the flow model objects.");
   mvwprintw (RaAvailableWindow,22, 1, "   n - Toggle name to number conversion(cycle through).");
   mvwprintw (RaAvailableWindow,23, 1, "   N - Specify the number of items to print.");
   mvwprintw (RaAvailableWindow,24, 1, "   %% - Show percent values.");
   mvwprintw (RaAvailableWindow,25, 1, "   p - Specify precision.");
   mvwprintw (RaAvailableWindow,26, 1, "   P - Pause the program");
   mvwprintw (RaAvailableWindow,27, 1, "   q - Quit the program.");
   mvwprintw (RaAvailableWindow,28, 1, "   r - Read argus data file(s)");
   mvwprintw (RaAvailableWindow,29, 1, "   R - Recursively open argus data files(s)");
   mvwprintw (RaAvailableWindow,30, 1, "   s - Specify sort fields.");
   mvwprintw (RaAvailableWindow,31, 1, "   t - Specify time range. same as -t command line option. ");
   mvwprintw (RaAvailableWindow,32, 1, "   T - Specify idle timeout value [60s].");
   mvwprintw (RaAvailableWindow,33, 1, "   u - Specify the window update timer, in seconds [0.1s]");
   mvwprintw (RaAvailableWindow,34, 1, "   U - Specify the playback rate, in seconds per second [1.0]");
   mvwprintw (RaAvailableWindow,35, 1, "   v - reverse the sort order");
   mvwprintw (RaAvailableWindow,36, 1, "   w - Write display to file");
   mvwprintw (RaAvailableWindow,37, 1, "   z - Toggle State field output formats");
   mvwprintw (RaAvailableWindow,38, 1, "   Z - Toggle TCP State field output");
   mvwprintw (RaAvailableWindow,39, 1, "   = - Clear Flow List");
   mvwprintw (RaAvailableWindow,40, 1, "   h - Print help screen.");
   mvwprintw (RaAvailableWindow,42, 1, "Navigation Keys (vi): g,G,j,k,i^F,^D,^B,^U");

   wnoutrefresh(RaAvailableWindow);
   doupdate();
}


#endif/* ARGUS_CURSES */


struct RaTopProcessStruct *
RaTopNewProcess(struct ArgusParserStruct *parser)
{
   struct RaTopProcessStruct *retn = NULL;
 
   if ((retn = (struct RaTopProcessStruct *) ArgusCalloc (1, sizeof(*retn))) != NULL) {
      if ((retn->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaTopNewProcess: ArgusNewQueue error %s\n", strerror(errno));

      if ((retn->htable = ArgusNewHashTable(0x100000)) == NULL)
         ArgusLog (LOG_ERR, "RaTopNewProcess: ArgusCalloc error %s\n", strerror(errno));

   } else
      ArgusLog (LOG_ERR, "RaTopNewProcess: ArgusCalloc error %s\n", strerror(errno));
 
#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaTopNewProcess(0x%x) returns 0x%x\n", parser, retn);
#endif
   return (retn);
}



char RaGetStrBuf[MAXSTRLEN];

char *
RaGetCiscoServers(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", (ArgusParser->Cflag ? "yes" : "no"));
   return(retn);
}

char *
RaGetNoOutputStatus(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", (ArgusParser->qflag ? "yes" : "no"));
   return(retn);
}

char *
RaGetUserAuth(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", ArgusParser->ustr);
   return(retn);
}

char *
RaGetUserPass(void)
{
   char *retn = RaGetStrBuf;
   int i;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", ArgusParser->pstr);
   for (i = 0; i < strlen(RaGetStrBuf); i++)
      RaGetStrBuf[i] = 'x';
   return(retn);
}

char *
RaGetOutputFile(void)
{
   char *retn = RaGetStrBuf;
   struct ArgusWfileStruct *wfile = NULL, *start;

   bzero(RaGetStrBuf, MAXSTRLEN);

   if (ArgusParser->ArgusWfileList != NULL) {
      if ((wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList)) != NULL) {
         start = wfile;
         do {
            sprintf(&RaGetStrBuf[strlen(RaGetStrBuf)], "%s ", wfile->filename);
            ArgusPopFrontList(ArgusParser->ArgusWfileList, ARGUS_LOCK);
            ArgusPushBackList(ArgusParser->ArgusWfileList, (struct ArgusListRecord *)wfile, ARGUS_LOCK);
            wfile = (struct ArgusWfileStruct *)ArgusFrontList(ArgusParser->ArgusWfileList);
         } while (wfile != start);
      }
      sprintf(RaGetStrBuf, "%s", RaGetStrBuf);
   }
   return(retn);
}

char *
RaGetExceptionOutputFile(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", ArgusParser->exceptfile);
   return(retn);
}

char *
RaGetTimeRange(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", ArgusParser->timearg);
   return(retn);
}

char *
RaGetRunTime(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%d", ArgusParser->Tflag);
   return(retn);
}

char *
RaGetFieldDelimiter(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   if (ArgusParser->RaFieldDelimiter == '\0')
      sprintf(RaGetStrBuf, "'\\0'");
   else
      sprintf(RaGetStrBuf, "'%c'", ArgusParser->RaFieldDelimiter);
   return(retn);
}

char *
RaGetTimeFormat(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", ArgusParser->RaTimeFormat);
   return(retn);
}

char *
RaGetPrecision(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%d", ArgusParser->pflag);
   return(retn);
}

char *
RaGetTimeSeries(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", (ArgusParser->Hstr ? "yes" : "no"));
   return(retn);
}

char *
RaGetValidateStatus(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", (ArgusParser->Vflag ? "yes" : "no"));
   return(retn);
}

char *
RaGetNumber(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%d", ArgusParser->eNflag);
   return(retn);
}

char *
RaGetDebugLevel(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%d", ArgusParser->debugflag);
   return(retn);
}

char *
RaGetUserDataEncode(void)
{
   char *retn = RaGetStrBuf, *str = NULL;

   bzero(RaGetStrBuf, MAXSTRLEN);
   switch (ArgusParser->eflag) {
      case ARGUS_ENCODE_ASCII:
         str = "ascii"; break;
      case ARGUS_ENCODE_32:
         str = "encode32"; break;
      case ARGUS_ENCODE_64:
         str = "encode64"; break;
   }

   sprintf(RaGetStrBuf, "%s", str);
   return(retn);
}


char *
RaSplitFilename (struct ArgusAdjustStruct *nadp)
{
   char *retn = NULL, tmpbuf[MAXSTRLEN];
   char *filename = nadp->filename;
   int len, i = 1, carry = 0;

   if (filename != NULL) {
      len = strlen(filename);

      for (i = 0; i < nadp->slen; i++)
         if (filename[len - (i + 1)] == 'z')
            carry++;

      if ((carry == (nadp->slen - 1)) && (filename[len - nadp->slen] == 'y')) {
         bzero (tmpbuf, MAXSTRLEN);
         strncpy(tmpbuf, filename, MAXSTRLEN);
         tmpbuf[strlen(tmpbuf) - nadp->slen] = 'z';
         for (i = 0; i < nadp->slen; i++)
            strcat(tmpbuf, "a");
         nadp->slen++;

      } else {
         for (i = 0, carry = 0; i < nadp->slen; i++) {
            if (filename[len - (i + 1)] == 'z') {
               filename[len - (i + 1)] = 'a';
            } else {
               filename[len - (i + 1)]++;
               break;
            }
         }
         strncpy (tmpbuf, filename, MAXSTRLEN);
      }

      if (nadp->filename)
         free(nadp->filename);

      nadp->filename = strdup(tmpbuf);
      retn = nadp->filename;
   }


#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaSplitFilename (0x%x) returning %s\n", nadp, retn); 
#endif

   return (retn);
}

int
RaProcessSplitOptions(struct ArgusParserStruct *parser, char *str, int len, struct ArgusRecordStruct *ns)
{
   char resultbuf[MAXSTRLEN], tmpbuf[MAXSTRLEN];
   char *ptr = NULL, *tptr = str;
   int retn = 0, i, x;

   bzero (resultbuf, len);

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

#if defined(ARGUS_CURSES)
#if defined(ARGUS_READLINE)
int
argus_getch_function(FILE *file)
{
   int retn = wgetch(RaWindow);
   if (retn  != ERR) {
      return retn;
   } else
      return -1;
}


int
argus_readline_timeout(void)
{
   struct ArgusQueueStruct *queue = RaTopProcess->queue;
   int retn = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "argus_readline_timeout()");
#endif

   if (RaWindowModified) {
      int i;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock);
#endif
      RaTopSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);
      if (ArgusParser->ns) {
         ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
         ArgusParser->ns = NULL;
      }
      for (i = 0; i < queue->count; i++) {
         struct ArgusRecordStruct *ns;
         if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
            break;
         if (ArgusParser->ns)
            ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
         else
            ArgusParser->ns = ArgusCopyRecordStruct (ns);
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif

      switch (RaInputStatus) {
         case RAGETTINGh:
            break;
         default:
            argus_redisplay_function();
            break;
      }

      RaWindowModified  = 0;
      RaWindowImmediate = FALSE;
   }

   return (retn);
}


int ArgusReadlinePoint = 0;
void
argus_redisplay_function()
{
   int offset = 0, plen, len, sw = RaScreenColumns - 1;
   char RaOutputBuffer[MAXSTRLEN];

   if (RaInputStatus == RAGETTINGh) {
      RaWindowStatus = 1;
      werase(RaAvailableWindow);
      RaInputStatus = RAGOTslash;
      RaInputString = RANEWCOMMANDSTR;
      RaCommandInputStr[0] = '\0';
      RaWindowModified++;
      rl_done = 1;
   }

   if (RaInputStatus == RAGETTINGcolon)
      RaInputStatus = argus_process_command (ArgusParser, RaInputStatus);

   sprintf (RaOutputBuffer, "%s", RaInputString);
   plen = strlen(RaOutputBuffer);
   len = strlen(rl_line_buffer) + 1;

   if ((rl_point + 1) > (sw - plen)) {
      offset = (rl_point + 1) - (sw - plen);
      RaOutputBuffer[plen - 1] = '<';
      sprintf (&RaOutputBuffer[plen], "%s", &rl_line_buffer[offset]);
   } else {
      sprintf (&RaOutputBuffer[plen], "%s", rl_line_buffer);
   }

   if (strlen(RaOutputBuffer) > sw)
      RaOutputBuffer[sw] = '>';

#ifdef ARGUSDEBUG
   ArgusDebug (4, "argus_redisplay_function: sw %d plen %d rl_point %d offset %d", sw, plen, rl_point, offset);
#endif

   RaRefreshDisplay(ArgusParser);

   mvwaddnstr (RaWindow, RaScreenLines - 2, 0, RaOutputBuffer, sw + 1);
   wclrtoeol(RaWindow);
   if (offset > 0)
      wmove(RaWindow, RaScreenLines - 2, plen + (rl_point - offset));
   else
      wmove(RaWindow, RaScreenLines - 2, plen + rl_point);

   ArgusUpdateScreen();
   wnoutrefresh(RaWindow);
   doupdate();
}

void
argus_getsearch_string(int dir)
{
   int linenum = RaWindowCursorY;
   int cursx = RaWindowCursorX, cursy = RaWindowCursorY + RaWindowStartLine;
   struct ArgusQueueStruct *queue = RaTopProcess->queue;
   char *line;

   if (!(argus_history_is_enabled()))
      argus_enable_history();

   ArgusSearchDirection = dir;

   RaInputStatus = RAGETTINGslash;
   RaInputString = (dir == ARGUS_FORWARD) ? "/" : "?";
   ArgusSearchDirection = dir;
   bzero(RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;

   rl_redisplay_function = argus_redisplay_function;
   ArgusReadlinePoint = 0;

   if ((line = readline("")) != NULL) {
      if (strlen(line) > 0) {
         strcpy (RaCommandInputStr, line);
         if (*line && argus_history_is_enabled()) {
            add_history (line);
         }
         free(line);
         sprintf(RaLastSearch, "%s", RaCommandInputStr);
      } else {
         if (strlen(RaLastSearch) > 0) 
            sprintf(RaCommandInputStr, "%s", RaLastSearch);
      }

      if ((linenum = RaSearchDisplay(ArgusParser, queue, ArgusSearchDirection, 
               &cursx, &cursy, RaCommandInputStr)) < 0) {
         if (ArgusSearchDirection == ARGUS_FORWARD) {
            sprintf (ArgusParser->RaDebugString, "search hit BOTTOM, continuing at TOP");
            cursx = 0; cursy = 0;
         } else {
            sprintf (ArgusParser->RaDebugString, "search hit TOP, continuing at BOTTOM");
            cursx = RaScreenColumns; cursy = RaSortItems;
         }
         linenum = RaSearchDisplay(ArgusParser, queue, ArgusSearchDirection,
               &cursx, &cursy, RaCommandInputStr);
      }

      if (linenum >= 0) {
         if ((linenum < RaWindowStartLine) || ((linenum > RaWindowStartLine + RaDisplayLines))) {
            int startline = ((cursy - 1)/ RaDisplayLines) * RaDisplayLines;
            startline = (RaSortItems > startline) ? startline : RaSortItems - RaDisplayLines;
            startline = (startline > 0) ? startline : 0;
            RaWindowStartLine = startline;

            if ((RaWindowCursorY = cursy % RaDisplayLines) == 0)
               RaWindowCursorY = RaDisplayLines;

         } else
            RaWindowCursorY = cursy - RaWindowStartLine;

         RaInputStatus = RAGOTslash;

         RaWindowCursorX = cursx;
         ArgusUpdateScreen();
      } else {
         sprintf (ArgusParser->RaDebugString, "Pattern not found: %s", RaCommandInputStr);
         RaInputStatus = RAGOTslash;
         RaInputString = RANEWCOMMANDSTR;
         bzero(RaCommandInputStr, MAXSTRLEN);
         RaCommandIndex = 0;
      }

      RaInputStatus = RAGOTslash;
      RaInputString = (dir == ARGUS_FORWARD) ? "/" : "?";
   }
}


void
argus_command_string(void)
{
   char *line;

   argus_disable_history();

   RaInputStatus = RAGETTINGcolon;
   RaInputString = ":";
   bzero(RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;

   ArgusReadlinePoint = 0;

   if ((line = readline("")) != NULL) {
      if (strlen(line) > 0) {
         strcpy (RaCommandInputStr, line);
         free(line);
         sprintf(RaLastCommand, "%s", RaCommandInputStr);
      } else {
         if (strlen(RaLastCommand) > 0) 
            sprintf(RaCommandInputStr, "%s", RaLastCommand);
      }
   }

   if (*RaCommandInputStr == 'q') {
      bzero (RaCommandInputStr, MAXSTRLEN);
      ArgusUpdateScreen();
      RaParseComplete(SIGINT);
   }

   if (strlen(RaCommandInputStr)) {
      switch(RaInputStatus) {
         case RAGETTINGh: {
            RaWindowStatus = 1;
            RaInputStatus = RAGOTcolon;
            wclear(RaWindow);
            ArgusUpdateScreen();
            RaRefreshDisplay(ArgusParser);
            break;
         }

         case RAGETTINGN: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            if (ptr != RaCommandInputStr) {
               RaDisplayLines = ((value < (RaScreenLines - (RaHeaderWinSize + 1)) - 1) ?
                                  value : (RaScreenLines - (RaHeaderWinSize + 1)) - 1);
               ArgusUpdateScreen();
            }

            break;
         }

         case RAGETTINGS: {
            if (!(ArgusAddHostList (ArgusParser, RaCommandInputStr, (ArgusParser->Cflag ? ARGUS_CISCO_DATA_SOURCE : ARGUS_DATA_SOURCE)))) {
               ArgusLog (LOG_ALERT, "%s%s host not found", RaInputString, RaCommandInputStr);
            } else {
               ArgusParser->Sflag = 1;
               ArgusParser->RaParseDone = 0;
            }
            break;
         }

         case RAGETTINGa: {
            if (!(strncasecmp(RaCommandInputStr, "Totals", 6))) {
               RaScreenResize = TRUE;
               ArgusPrintTotals++;
               RaHeaderWinSize++;
               ArgusUpdateScreen();
            }
         }
         break;

#if defined(ARGUSMYSQL)
         case RAGETTINGB: {
            RaSQLSaveTable = strdup(RaCommandInputStr);
            ArgusCreateSQLSaveTable(RaSQLSaveTable);
         }
         break;
#endif
         case RAGETTINGd: {
            struct ArgusInput *input;
            char strbuf[MAXSTRLEN];

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (strbuf, " %s:%d", input->hostname, input->portnum);
                  if ((strstr (RaCommandInputStr, strbuf))) {
                     ArgusRemoveFromQueue (ArgusParser->ArgusActiveHosts, &input->qhdr, ARGUS_LOCK);
                     ArgusCloseInput(ArgusParser, input);
                     break;
                  }
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
            } else {
#if defined(ARGUSMYSQL)
               if (RaMySQL != NULL) {
                  sprintf (strbuf, "%s", RaDatabase);
                  if (RaHost)
                     sprintf (&strbuf[strlen(strbuf)], "@%s", RaHost);
                  if ((strstr (RaCommandInputStr, strbuf))) {
                     mysql_close(&mysql);
                     RaMySQL = NULL;
                     sprintf (ArgusParser->RaDBString, " ");
                  }
               }
#endif
            }
         }
         break;

         case RAGETTINGD: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            if (ptr != RaCommandInputStr)
               ArgusParser->debugflag = value;
            break;
         }

         case RAGETTINGc: {
            break;
         }

         case RAGETTINGf: {
            struct nff_program lfilter;
            char *ptr, *str = NULL;
            int ind = ARGUS_REMOTE_FILTER;
            int i, retn;

            bzero ((char *) &lfilter, sizeof (lfilter));
            ptr = RaCommandInputStr;
            while (isspace((int)*ptr)) ptr++;

            if ((str = strstr (ptr, "local")) != NULL) {
               ptr = strdup(&str[strlen("local ")]);
               ind = ARGUS_LOCAL_FILTER;
            } else 
            if ((str = strstr (ptr, "display")) != NULL) {
               ptr = strdup(&str[strlen("display ")]);
               ind = ARGUS_DISPLAY_FILTER;
            } else 
            if ((str = strstr (ptr, "remote")) != NULL) {
               ptr = strdup(&str[strlen("remote ")]);
               ind = ARGUS_REMOTE_FILTER;
            } else 
            if ((str = strstr (ptr, "none")) != NULL) {
               ind = RaFilterIndex;
            }

            if ((retn = ArgusFilterCompile (&lfilter, ptr, 1)) < 0)
               sprintf (ArgusParser->RaDebugString, "%s%s syntax error", RAGETTINGfSTR, RaCommandInputStr);

            else {
               sprintf (ArgusParser->RaDebugString, "%s%s filter accepted", RAGETTINGfSTR, RaCommandInputStr);
               str = ptr;
               while (isspace((int)*str)) str++;
               
               switch (ind) {
                  case ARGUS_LOCAL_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusLocalFilter !=  NULL) {
                        free(ArgusParser->ArgusLocalFilter);
                        ArgusParser->ArgusLocalFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusLocalFilter = ptr;
                     else
                        free(ptr);
                     break;

                  case ARGUS_DISPLAY_FILTER:
                     if (ArgusParser->ArgusDisplayCode.bf_insns != NULL)
                        free (ArgusParser->ArgusDisplayCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusDisplayCode, sizeof(lfilter));
                     bcopy((char *)&lfilter, (char *)&ArgusSorter->filter, sizeof(lfilter));

                     if (ArgusParser->ArgusDisplayFilter !=  NULL) {
                        free(ArgusParser->ArgusDisplayFilter);
                        ArgusParser->ArgusDisplayFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusDisplayFilter = ptr;
                     else
                        free(ptr);
                     break;

                  case ARGUS_REMOTE_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);
                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusRemoteFilter !=  NULL) {
                        free(ArgusParser->ArgusRemoteFilter);
                        ArgusParser->ArgusRemoteFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusRemoteFilter = ptr;
                     else
                        free(ptr);
                     break;
               }

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
               RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);

               if (RaSortItems) {
                  if (ArgusParser->ns) {
                     ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                     ArgusParser->ns = NULL;
                  }
                  for (i = 0; i < RaSortItems; i++) {
                     struct ArgusRecordStruct *ns;
                     if ((ns = (struct ArgusRecordStruct *)RaTopProcess->queue->array[i]) == NULL)
                        break;
                     if (ArgusParser->ns)
                        ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
                     else
                        ArgusParser->ns = ArgusCopyRecordStruct (ns);
                  }
               }
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
               RaWindowStatus = 1;
               wclear(RaAvailableWindow);
               ArgusUpdateScreen();
               RaRefreshDisplay(ArgusParser);
            }
            break;
         }
                      
         case RAGETTINGm: {
            struct ArgusRecordStruct *ns = NULL;
            char strbuf[MAXSTRLEN], *tok = NULL, *ptr;
            struct ArgusModeStruct *mode = NULL, *modelist = NULL, *list; 
            struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;
            int i;                                  

            ArgusParser->RaMonMode = 0;

            if (strcmp(agg->modeStr, RaCommandInputStr)) {
               strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

               if ((mode = ArgusParser->ArgusMaskList) != NULL)
                  ArgusDeleteMaskList(ArgusParser);

               agg->mask = 0;
               agg->saddrlen = 0;
               agg->daddrlen = 0;

               if ((ptr = strbuf) != NULL) {
                  while ((tok = strtok (ptr, " \t")) != NULL) {
                     if ((mode = (struct ArgusModeStruct *) ArgusCalloc (1, sizeof(struct ArgusModeStruct))) != NULL) {
                        if ((list = modelist) != NULL) {
                           while (list->nxt)
                              list = list->nxt;
                           list->nxt = mode;
                        } else
                           modelist = mode;
                        mode->mode = strdup(tok);
                     }
                     ptr = NULL;
                  }
               } else {
                  if ((modelist = ArgusParser->ArgusMaskList) == NULL)
                     agg->mask  = ( ARGUS_MASK_SRCID_INDEX | ARGUS_MASK_PROTO_INDEX |
                                    ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_SPORT_INDEX |
                                    ARGUS_MASK_DADDR_INDEX | ARGUS_MASK_DPORT_INDEX );
               }

               ArgusInitAggregatorStructs(agg);

               if ((mode = modelist) != NULL) {
                  while (mode) {
                     char *ptr = NULL, **endptr = NULL;
                     int value = 0;

                     if ((ptr = strchr(mode->mode, '/')) != NULL) {
                        *ptr++ = '\0';
                        if ((value = strtol(ptr, endptr, 10)) == 0)
                           if (*endptr == ptr)
                              usage();
                     }
                     if (!(strncasecmp (mode->mode, "none", 4))) {
                        agg->mask  = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "mac", 3))) {
                        ArgusParser->RaMonMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SMAC);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "addr", 4))) {
                        ArgusParser->RaMonMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "matrix", 6))) {
                        agg->ArgusMatrixMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        agg->mask |= (0x01LL << ARGUS_MASK_DADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else {
                        struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;

                        for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                           if (!(strncasecmp (mode->mode, ArgusMaskDefs[i].name, ArgusMaskDefs[i].slen))) {
                              agg->mask |= (0x01LL << i);
                              switch (i) {
                                 case ARGUS_MASK_SADDR:
                                    if (value > 0)
                                       agg->saddrlen = value;
                                    break;
                                 case ARGUS_MASK_DADDR:
                                    if (value > 0)
                                       agg->daddrlen = value;
                                    break;

                                 case ARGUS_MASK_SMPLS:
                                 case ARGUS_MASK_DMPLS: {
                                    int x, RaNewIndex = 0;
                                    char *ptr;

                                    if ((ptr = strchr(mode->mode, '[')) != NULL) {
                                       char *cptr = NULL;
                                       int sind = -1, dind = -1;
                                       *ptr++ = '\0';
                                       while (*ptr != ']') {
                                          if (isdigit((int)*ptr)) {
                                             dind = strtol(ptr, (char **)&cptr, 10);
                                             if (cptr == ptr)
                                                usage ();
            
                                             if (sind < 0)
                                                sind = dind;

                                             for (x = sind; x <= dind; x++)
                                                RaNewIndex |= 0x01 << x;

                                             ptr = cptr;
                                             if (*ptr != ']')
                                                ptr++;
                                             if (*cptr != '-')
                                                sind = -1;
                                          } else
                                             usage ();
                                       }
                                       ArgusIpV4MaskDefs[i].index = RaNewIndex;
                                       ArgusIpV6MaskDefs[i].index = RaNewIndex;
                                       ArgusEtherMaskDefs[i].index = RaNewIndex;
                                    }
                                    break;
                                 }
                              }
                              break;
                           }
                        }
                     }
                     mode = mode->nxt;
                  }
               }

               ArgusParser->ArgusMaskList = modelist;

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_LOCK)) != NULL)
                  RaMySQLDeleteRecords(ArgusParser, ns);

               ArgusEmptyHashTable(RaTopProcess->htable);
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->ns = NULL;
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
               werase(RaWindow);
               ArgusUpdateScreen();
            }

            break;
         }

         case RAGETTINGM: {
            struct ArgusModeStruct *mode = NULL;
            char strbuf[MAXSTRLEN], *str = strbuf, *tok = NULL;
            char *tzptr;
            int retn = 0;

            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if ((tzptr = strstr(strbuf, "TZ=")) != NULL) {
               if (ArgusParser->RaTimeZone)
                  free (ArgusParser->RaTimeZone);
               ArgusParser->RaTimeZone = strdup(tzptr);
               tzptr = getenv("TZ");
#if defined(HAVE_SETENV)
               if ((retn = setenv("TZ", (ArgusParser->RaTimeZone + 3), 1)) < 0)
                  sprintf (ArgusParser->RaDebugString, "setenv(TZ, %s, 1) error %s", 
                     ArgusParser->RaTimeZone + 3, strerror(errno));
#else
               if ((retn = putenv(ArgusParser->RaTimeZone)) < 0)
                  sprintf (ArgusParser->RaDebugString, "setenv(TZ, %s, 1) error %s", 
                     ArgusParser->RaTimeZone + 3, strerror(errno));
#endif
               if (retn == 0) {
                  tzset();
                  sprintf (ArgusParser->RaDebugString, "Timezone changed from %s to %s", 
                             tzptr, getenv("TZ"));
               }

               ArgusUpdateScreen();
               break;
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               ArgusDeleteModeList(ArgusParser);
               ArgusParser->RaCumulativeMerge = 1;
            }

            if (strlen(strbuf) > 0) {
               while ((tok = strtok(str, " \t\n")) != NULL) {
                  if (!(strncasecmp (tok, "none", 4)))
                     ArgusDeleteModeList(ArgusParser);
                  else if (!(strncasecmp (tok, "default", 7))) {
                     ArgusDeleteModeList(ArgusParser);
                  } else
                     ArgusAddModeList (ArgusParser, tok);
                  str = NULL;
               }
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               struct ArgusAdjustStruct *nadp = NULL;
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
                     int size = -1;
                     nadp = &RaBinProcess->nadp;

                     nadp = &RaBinProcess->nadp;

                     switch (ind) {
                        case ARGUSSPLITRATE:  {   /* "%d:%d[yMwdhms]" */
                           struct ArgusModeStruct *tmode = NULL; 
                           nadp->mode = ind;
                           if ((tmode = mode->nxt) != NULL) {
                              mptr = tmode->mode;
                              if (isdigit((int)*tmode->mode)) {
                                 char *ptr = NULL;
                                 nadp->len = strtol(tmode->mode, (char **)&ptr, 10);
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
                                          size = nadp->value * 31556926;
                                          break;
                                       case 'M':
                                          nadp->qual = ARGUSSPLITMONTH; 
                                          size = nadp->value * 2629744;
                                          break;
                                       case 'w':
                                          nadp->qual = ARGUSSPLITWEEK;  
                                          size = nadp->value * 604800;
                                          break;
                                       case 'd':
                                          nadp->qual = ARGUSSPLITDAY;   
                                          size = nadp->value * 86400;
                                          break;
                                       case 'h':
                                          nadp->qual = ARGUSSPLITHOUR;  
                                          size = nadp->value * 3600;
                                          break;
                                       case 'm':
                                          nadp->qual = ARGUSSPLITMINUTE;
                                          size = nadp->value * 60;
                                          break;
                                        default:
                                          nadp->qual = ARGUSSPLITSECOND;
                                          size = nadp->value;
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
                                 just a bit bigger than (nadp->len * size) */

                              ArgusParser->timeout.tv_sec  = (nadp->len * size);
                              ArgusParser->timeout.tv_usec = 0;
                           }

                           ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                           ArgusSorter->ArgusSortAlgorithms[1] = NULL;
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
                           ArgusSorter->ArgusSortAlgorithms[0] = NULL;
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
                     if (!(strncasecmp (mode->mode, "nomerge", 7))) {
                        ArgusParser->RaCumulativeMerge = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "merge", 5))) {
                        ArgusParser->RaCumulativeMerge = 1;
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
                           if (ptr != endptr) {
                              RaUpdateRate = value;
                           }
                        }

                     }
                  }

                  mode = mode->nxt;
               }
            }

            break;
         }

         case RAGETTINGp: {
            int value = 0;
            char *endptr = NULL;

            value = strtod(RaCommandInputStr, &endptr);

            if (RaCommandInputStr != endptr) {
               ArgusParser->pflag = value;
               sprintf (ArgusParser->RaDebugString, "%s %s precision accepted", RAGETTINGpSTR, RaCommandInputStr);
            } else
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);

            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGR: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  RaProcessRecursiveFiles (ptr);
                  str = NULL;
               }
            }
            break;
         }

         case RAGETTINGr: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            glob_t globbuf;

            bzero (strbuf, MAXSTRLEN);
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               struct ArgusRecordStruct *ns = NULL;

               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  glob (ptr, 0, NULL, &globbuf);
                  if (globbuf.gl_pathc > 0) {
                     int i;
                     for (i = 0; i < globbuf.gl_pathc; i++)
                        ArgusAddFileList (ArgusParser, globbuf.gl_pathv[i], ARGUS_DATA_SOURCE, -1, -1);
                  } else 
                     sprintf (ArgusParser->RaDebugString, "%s no files found for %s", RAGETTINGrSTR, ptr);
                  str = NULL;
               }
               ArgusParser->RaTasksToDo = 1;
               ArgusParser->Sflag = 0;
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_LOCK)) != NULL)
                  RaMySQLDeleteRecords(ArgusParser, ns);

               ArgusEmptyHashTable(RaTopProcess->htable);

               if (ArgusParser->ns != NULL) {
                  ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                  ArgusParser->ns = NULL;
               }

               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->status &= ~ARGUS_FILE_LIST_PROCESSED;
               ArgusLastTime.tv_sec  = 0;
               ArgusLastTime.tv_usec = 0;
            }
            break;
         }

         case RAGETTINGs: {
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int (*srtalg[ARGUS_MAX_SORT_ALG])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
            int i, x, ind = 0;
            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero(srtalg, sizeof(srtalg));
            while ((tok = strtok(ptr, " ")) != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                  if (!strncmp (ArgusSortKeyWords[x], tok, strlen(ArgusSortKeyWords[x]))) {
                     srtalg[ind++] = ArgusSortAlgorithmTable[x];
                     break;
                  }
               }
               if (x == ARGUS_MAX_SORT_ALG) {
                  bzero(srtalg, sizeof(srtalg));
                  ArgusLog (LOG_ALERT, "sort keyword %s not valid", tok);
                  break;
               }
               ptr = NULL;
            }

            if (srtalg[0] != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++)
                  ArgusSorter->ArgusSortAlgorithms[x] = srtalg[x];
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
            RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < RaTopProcess->queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)RaTopProcess->queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns)
                  ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGT: {
            double sec, usec, value;
            char *ptr = NULL;

            value = strtod(RaCommandInputStr, (char **)&ptr);
            if (ptr != RaCommandInputStr) {
               usec = modf(value, &sec);
               ArgusParser->timeout.tv_sec  = sec;
               ArgusParser->timeout.tv_usec = usec;
            }
            break;
         }

         case RAGETTINGt: {
            if (ArgusParser->timearg) {
               free (ArgusParser->timearg);
               ArgusParser->timearg = NULL;
            }

            if (RaCommandInputStr)
               if (strlen(RaCommandInputStr))
                  ArgusParser->timearg = strdup(RaCommandInputStr);

            ArgusCheckTimeFormat (ArgusParser->RaTmStruct, ArgusParser->timearg);
            break;
         }

         case RAGETTINGu: {
            double value = 0.0, ivalue, fvalue;
            char *endptr = NULL;
       
            value = strtod(RaCommandInputStr, &endptr);
       
            if (RaCommandInputStr != endptr) {
               fvalue = modf(value, &ivalue);
       
               RaTopUpdateInterval.tv_sec  = (int) ivalue;
               RaTopUpdateInterval.tv_usec = (int) (fvalue * 1000000.0);
       
               sprintf (ArgusParser->RaDebugString, "%s %s interval accepted", RAGETTINGuSTR, RaCommandInputStr);
               RaTopUpdateTime = ArgusParser->ArgusRealTime;
       
            } else
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);

            break;
         }


         case RAGETTINGU: {
            double value = 0.0;
            char *endptr = NULL;
       
            value = strtod(RaCommandInputStr, &endptr);
       
            if (RaCommandInputStr != endptr) {
               RaUpdateRate = value;
               sprintf (ArgusParser->RaDebugString, "%s %s accepted", RAGETTINGUSTR, RaCommandInputStr);
       
            } else
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGUSTR, RaCommandInputStr);

            break;
         }

         
         case RAGETTINGw: {
            struct ArgusListStruct *wlist = ArgusParser->ArgusWfileList;
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusRecord *argusrec = NULL;
            struct ArgusRecordStruct *ns;
            static char sbuf[0x10000];
            int i;

            if (RaSortItems > 0) {
               ArgusParser->ArgusWfileList = NULL;
               setArgusWfile (ArgusParser, RaCommandInputStr, NULL);
               wfile = (struct ArgusWfileStruct *) ArgusParser->ArgusWfileList->start;

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
               for (i = 0; i < RaSortItems; i++) {
                  int pass = 1;

                  if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[i]) == NULL)
                     break;

                  if (wfile->filterstr) {
                     struct nff_insn *wfcode = wfile->filter.bf_insns;
                     pass = ArgusFilterRecord (wfcode, ns);
                  }

                  if (pass != 0) {
                     if ((argusrec = ArgusGenerateRecord (ns, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        ArgusWriteNewLogfile (ArgusParser, ns->input, wfile, argusrec);

                     }
                  }
               }
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
               fflush(wfile->fd);
               fclose(wfile->fd);
               clearArgusWfile(ArgusParser);
               ArgusParser->ArgusWfileList = wlist;
            }

            break;   
         }

         case RAGETTINGF: {
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int x;
            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero ((char *)ArgusParser->RaSOptionStrings, sizeof(ArgusParser->RaSOptionStrings));
            ArgusParser->RaSOptionIndex = 0;
            ArgusPrintRank = 0;
            while ((tok = strtok(ptr, " ")) != NULL) {
               if ((strstr (tok, "rank"))) {
                  if (*tok == '-')
                     ArgusPrintRank = 0;
                  else
                     ArgusPrintRank++;
               } else
                  if (ArgusParser->RaSOptionIndex <  ARGUS_MAX_S_OPTIONS)
                     ArgusParser->RaSOptionStrings[ArgusParser->RaSOptionIndex++] = tok;
               ptr = NULL;
            }

            if (ArgusParser->RaSOptionIndex > 0) {
               ArgusProcessSOptions(ArgusParser);
               for (x = 0; x < ArgusParser->RaSOptionIndex; x++) 
                  if (ArgusParser->RaSOptionStrings[x] != NULL) 
                     ArgusParser->RaSOptionStrings[x] = NULL;
               ArgusParser->RaSOptionIndex = 0;
            }
            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGcolon: {
            char *endptr = NULL;
            int linenum, startline;

            linenum = (int)strtol(RaCommandInputStr, &endptr, 10);
            if (RaCommandInputStr == endptr) {
               switch (*RaCommandInputStr) {
                  case 'q': {
                     bzero (RaCommandInputStr, MAXSTRLEN);
                     ArgusUpdateScreen();
                     RaParseComplete(SIGINT);
                     break;
                  }
               }
            } else {
               if ((linenum >= RaWindowStartLine) && (linenum <= (RaWindowStartLine + RaDisplayLines)))
                  RaWindowCursorY = linenum - RaWindowStartLine;
               else {
                  startline = ((linenum - 1)/ RaDisplayLines) * RaDisplayLines;
                  startline = (RaSortItems > startline) ? startline : RaSortItems - RaDisplayLines;
                  startline = (startline > 0) ? startline : 0;
                  RaWindowStartLine = startline;
                  if ((RaWindowCursorY = linenum % RaDisplayLines) == 0)
                     RaWindowCursorY = RaDisplayLines;
               }
               RaCursorOffset = 0;
               RaWindowCursorX = 0;
               ArgusUpdateScreen();
            }
            break;
         }
      }
   }

   RaInputStatus = RAGOTcolon;
   RaInputString = RANEWCOMMANDSTR;
   bzero(RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;

   argus_enable_history();
}


int
argus_process_command (struct ArgusParserStruct *parser, int status)
{
   char promptbuf[256], *prompt = promptbuf;
   int retn = status;

   if (strlen(rl_line_buffer) == 1) {

      switch (*rl_line_buffer) {
          case 'a': {
             retn = RAGETTINGa;
             RaInputString = RAGETTINGaSTR;
             break;
          }

#if defined(ARGUSMYSQL)
          case 'B':
             RaInputStatus = RAGETTINGB;
             RaInputString = RAGETTINGBSTR;
             break;
#endif
          case 'c': {
#if defined(ARGUSMYSQL)
             if (RaMySQL == NULL) {
/*
                char strbuf[MAXSTRLEN];
                RaInputStatus = RAGETTINGc;
                RaInputString = RAGETTINGcSTR;
                sprintf (strbuf, "NTAIS:");

                if (ArgusParser->dbstr != NULL)
                   sprintf (&strbuf[strlen(strbuf)], "%s", ArgusParser->dbstr);

                sprintf (RaCommandInputStr, "%s", strbuf);
                RaCommandIndex = strlen(RaCommandInputStr);
*/
             }
#endif
             break;
          }

          case 'd': {
             struct ArgusInput *input;
             retn = RAGETTINGd;

             RaInputString = RAGETTINGdSTR;

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ", input->hostname, input->portnum);
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);

            } else {
#if defined(ARGUSMYSQL)
               if (RaMySQL) {
                  sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", RaDatabase);
                  if (RaHost)
                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "@%s", RaHost);
                  RaCommandIndex = strlen(RaCommandInputStr);
               }
#endif
            }
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }
                   
          case 'D': {
             retn = RAGETTINGD;
             RaInputString = RAGETTINGDSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->debugflag);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'f': 
             retn = RAGETTINGf;
             RaInputString = RAGETTINGfSTR;
             RaFilterIndex = 3;
             if (ArgusParser->ArgusRemoteFilter) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "remote %s ", ArgusParser->ArgusRemoteFilter);
                RaCommandIndex = strlen(RaCommandInputStr); 
                RaFilterIndex = ARGUS_REMOTE_FILTER;
             } else
             if (ArgusParser->ArgusLocalFilter) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "local %s ", ArgusParser->ArgusLocalFilter);
                RaCommandIndex = strlen(RaCommandInputStr); 
                RaFilterIndex = ARGUS_LOCAL_FILTER;
             } else
             if (ArgusParser->ArgusDisplayFilter) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "display %s ", ArgusParser->ArgusDisplayFilter);
                RaCommandIndex = strlen(RaCommandInputStr); 
                RaFilterIndex = ARGUS_DISPLAY_FILTER;
             }
             break;

         case 'm': {
            struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;
            struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
            int i;

            retn = RAGETTINGm;
            RaInputString = RAGETTINGmSTR;
            if (agg->modeStr != NULL) {
               sprintf (RaCommandInputStr, "%s", agg->modeStr);
            } else {
               for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                  if (agg->mask & (0x01LL << i)) {
                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusMaskDefs[i].name);

                     switch (i) {
                        case ARGUS_MASK_SADDR:
                           if (agg->saddrlen > 0)
                              sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->saddrlen);
                           break;
                        case ARGUS_MASK_DADDR:
                           if (agg->daddrlen > 0)
                              sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->daddrlen);
                           break;
                     }

                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " ");
                  }
               }

               agg->modeStr = strdup(RaCommandInputStr);
            }
             RaCommandIndex = strlen(RaCommandInputStr);
             break;
          }

          case 'M': {
             struct ArgusModeStruct *mode;
             retn = RAGETTINGM;
             RaInputString = RAGETTINGMSTR;
    
             if ((mode = ArgusParser->ArgusModeList) != NULL) {
                while (mode) {
                   sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", mode->mode);
                   mode = mode->nxt;
                }
             }
             RaCommandIndex = strlen(RaCommandInputStr);
             break;
          }

          case 'N':
             retn = RAGETTINGN;
             RaInputString = RAGETTINGNSTR;
             break;

          case 'p': {
             retn = RAGETTINGp;
             RaInputString = RAGETTINGpSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->pflag);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'P': {
             double rate  = RaUpdateRate;
             double pause = ArgusParser->Pauseflag;

             ArgusParser->Pauseflag = (pause > 0.0) ? 0.0 : rate;
             RaUpdateRate = (rate > 0.0) ? 0.0 : pause;

             if (ArgusParser->Pauseflag)
                RaInputString = "Paused";
             else
                RaInputString = "";
             break;
          }

          case 't':
             retn = RAGETTINGt;
             RaInputString = RAGETTINGtSTR;
             if (ArgusParser->timearg) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusParser->timearg);
                RaCommandIndex = strlen(RaCommandInputStr); 
             }
             break;

          case 'T':
             retn = RAGETTINGT;
             RaInputString = RAGETTINGTSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.%6d",
                   (int)ArgusParser->timeout.tv_sec, (int)ArgusParser->timeout.tv_usec);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;

          case 'R': {
             struct ArgusInput *input = ArgusParser->ArgusInputFileList;
             retn = RAGETTINGR;
             RaInputString = RAGETTINGRSTR;
             while (input) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", input->filename);
                RaCommandIndex = strlen(RaCommandInputStr); 
                input = (void *) input->qhdr.nxt;
             }
             break;
          }

          case 'r': {
             struct ArgusInput *input = ArgusParser->ArgusInputFileList;
             retn = RAGETTINGr;
             RaInputString = RAGETTINGrSTR;
             while (input) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", input->filename);
                RaCommandIndex = strlen(RaCommandInputStr); 
                input = (void *) input->qhdr.nxt;
             }
             break;
          }

          case 'S': {
             struct ArgusInput *input;
             retn = RAGETTINGS;
             RaInputString = RAGETTINGSSTR;

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ", input->hostname, input->portnum);
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);

               RaCommandIndex = strlen(RaCommandInputStr); 
            }
            break;
         }

          case 's': {
             int x, y;
             retn = RAGETTINGs;
             RaInputString = RAGETTINGsSTR;
             for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                if (ArgusSorter->ArgusSortAlgorithms[x]) {
                   for (y = 0; y < ARGUS_MAX_SORT_ALG; y++) {
                      if (ArgusSorter->ArgusSortAlgorithms[x] == ArgusSortAlgorithmTable[y]) {
                         sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", 
                               ArgusSortKeyWords[y]);
                         break;
                      }
                   }
                }
             }
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'u':
             retn = RAGETTINGu;
             RaInputString = RAGETTINGuSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.", (int) RaTopUpdateInterval.tv_sec);
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%06d",(int) RaTopUpdateInterval.tv_usec);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;

          case 'U':
             retn = RAGETTINGU;
             RaInputString = RAGETTINGUSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%2.2f", RaUpdateRate);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;

          case 'w':
             retn = RAGETTINGw;
             RaInputString = RAGETTINGwSTR;
             break;

          case 'F': {
             int x, y;
             retn = RAGETTINGF;
             RaInputString = RAGETTINGFSTR;

             if (ArgusPrintRank)
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "rank:%d ", ArgusRankSize);

             for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                if (parser->RaPrintAlgorithmList[x] != NULL) {
                   for (y = 0; y < MAX_PRINT_ALG_TYPES; y++) {
                      if ((void *) parser->RaPrintAlgorithmList[x]->print == (void *) RaPrintAlgorithmTable[y].print) {
                         sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ",
                            RaPrintAlgorithmTable[y].field, RaPrintAlgorithmTable[y].length);
                         break;
                      }
                   }
                } else
                   break;
             }
             RaCommandIndex = strlen(RaCommandInputStr);
             break;
          }

          case 'Q':
             retn = RAGETTINGq;
             RaInputString = RAGETTINGqSTR;
             break;

          case 'h':
             retn = RAGETTINGh;
             RaInputString = RAGETTINGhSTR;
             RaWindowStatus = 0;
             RaOutputHelpScreen();
             break;

          case 'n':
             if (++ArgusParser->nflag > 3) {
                ArgusParser->nflag = 0;
             }
             rl_done = 1;
             break;

          case 'v': 
             if (ArgusParser->vflag) {
                ArgusParser->vflag = 0;
                ArgusReverseSortDir = 0;
             } else {
                ArgusParser->vflag = 1;
                ArgusReverseSortDir++;
             }

#if defined(ARGUS_THREADS)
             pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
             RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);

#if defined(ARGUS_THREADS)
             pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
             rl_done = 1;
             break;

          case '=':  {
             struct ArgusRecordStruct *ns = NULL;

             werase(RaWindow);
             ArgusUpdateScreen();

             while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_LOCK)) != NULL)
                RaMySQLDeleteRecords(ArgusParser, ns);

             ArgusEmptyHashTable(RaTopProcess->htable);

             if (ArgusParser->ns != NULL) {
                ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                ArgusParser->ns = NULL;
             }

             ArgusParser->RaClientUpdate.tv_sec = 0;
             ArgusParser->ArgusTotalRecords = 0;
             RaTopStartTime.tv_sec = 0;
             RaTopStartTime.tv_usec = 0;
             RaTopStopTime.tv_sec = 0;
             RaTopStopTime.tv_usec = 0;
             rl_done = 1;
             break;
          }

          case 'z':  
             if (++ArgusParser->zflag > 1) {
                ArgusParser->zflag = 0;
             }
             rl_done = 1;
             break;

          case 'Z':  
             switch (ArgusParser->Zflag) {
                case '\0': ArgusParser->Zflag = 'b'; break;
                case  'b': ArgusParser->Zflag = 's'; break;
                case  's': ArgusParser->Zflag = 'd'; break;
                case  'd': ArgusParser->Zflag = '\0'; break;
             }
             rl_done = 1;
             break;

          default:
             break;
      }

      if (retn != status) {
         sprintf (prompt, ":%s ", RaInputString);

         rl_set_prompt(prompt);
         rl_save_prompt();
         rl_replace_line(RaCommandInputStr, 1);
         rl_point = strlen(rl_line_buffer);
      }

   } else {
   }

   return (retn);
}


char ratop_historybuf[MAXSTRLEN];
char *ratop_history = NULL;

int argus_history_enabled = 1;

void
argus_recall_history(void)
{
   if (ratop_history != NULL)
      read_history(ratop_history);
}

void
argus_save_history(void)
{
   if (ratop_history == NULL) {
      char *home;

      if ((home = getenv("HOME")) != NULL) {
         sprintf (ratop_historybuf, "%s/.ratop_history", home);
         ratop_history = ratop_historybuf;
      }
   }

   if (ratop_history != NULL)
      write_history(ratop_history);
}

void
argus_enable_history(void)
{
   argus_recall_history();
   argus_history_enabled = 1;
}


void
argus_disable_history(void)
{
   argus_save_history();
   clear_history();
   argus_history_enabled = 0;
}

int
argus_history_is_enabled(void)
{
   return (argus_history_enabled);
}
#endif
#endif


#if defined(ARGUSMYSQL)

void
RaSQLQueryTable (char *table)
{
   char buf[0x10000], sbuf[0x10000];
   MYSQL_RES *mysqlRes;
   struct timeval now;
   int retn, x;

   if ((ArgusInput = (struct ArgusInput *) ArgusCalloc (1, sizeof(struct ArgusInput))) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

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

   sprintf (buf, "SELECT record from %s", table);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "SQL Query %s\n", buf);
#endif
   if ((retn = mysql_real_query(&mysql, buf, strlen(buf))) != 0)
      ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));
   else {
      if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;

               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));
 
               for (x = 0; x < retn; x++) {
                  bcopy (row[x], sbuf, (int) lengths[x]);

                  if (((struct ArgusRecord *)sbuf)->hdr.type & ARGUS_MAR) {
                     bcopy ((char *) &sbuf, (char *)&ArgusInput->ArgusInitCon, sizeof (struct ArgusRecord));
                  } else 
                     ArgusHandleDatum (ArgusParser, ArgusInput, (struct ArgusRecord *)&sbuf, &ArgusParser->ArgusFilterCode);
               }
            }
         }

         mysql_free_result(mysqlRes);
      }
   }
}

void
RaSQLQueryMcastTables (void)
{
   char buf[0x10000], sbuf[0x10000];
   MYSQL_RES *mysqlRes;
   int retn, x, i;

   for (i = 0; i < RA_MAXMCASTSQLQUERY; i++) {
      sprintf (buf, RaMcastTableQueryString[i], RaDatabase);

#ifdef ARGUSDEBUG
      ArgusDebug (1, "SQL Query %s\n", buf);
#endif
      if ((retn = mysql_real_query(&mysql, buf, strlen(buf))) != 0)
         ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));
      else {
         if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               while ((row = mysql_fetch_row(mysqlRes))) {
                  unsigned long *lengths;

                  lengths = mysql_fetch_lengths(mysqlRes);
                  bzero(sbuf, sizeof(sbuf));
    
                  for (x = 0; x < retn; x++) {
                     bcopy (row[x], sbuf, (int) lengths[x]);

                     if (((struct ArgusRecord *)sbuf)->hdr.type & ARGUS_MAR) {
                        bcopy ((char *) &sbuf, (char *)&ArgusInput->ArgusInitCon,
                           sizeof (struct ArgusRecord));
                     } else 
                        ArgusHandleDatum (ArgusParser, ArgusInput, (struct ArgusRecord *)&sbuf,
                              &ArgusParser->ArgusFilterCode);
                  }
               }
            }

            mysql_free_result(mysqlRes);
         }
      }
   }
}

void
RaSQLQueryProbes ()
{
   struct RaMySQLProbeTable *sqry = NULL;
   char buf[2048], sbuf[2048];
   MYSQL_RES *mysqlRes;
   char *endptr;
   int retn, x;

   sprintf (buf, "%s", RaTableQueryString[0]);
#ifdef ARGUSDEBUG
   ArgusDebug (1, "SQL Query %s\n", buf);
#endif
   if ((retn = mysql_real_query(&mysql, buf, strlen(buf))) != 0)
      ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));

   else {
      if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
    
               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));

               if ((sqry = (void *) ArgusCalloc (1, sizeof(*sqry))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

               for (x = 0; x < retn; x++) {
                  snprintf(sbuf, 2048, "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");
                  switch (x) {
                     case RAMYSQL_PROBETABLE_PROBE:
                        sqry->probe = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_PROBETABLE_NAME:
                        sqry->name = strdup(sbuf);
                        break;
                  }
               }
               ArgusAddToQueue (ArgusProbeQueue, &sqry->qhdr, ARGUS_LOCK);
            }
         }
         mysql_free_result(mysqlRes);
      }
   }
}

void
RaSQLQuerySecondsTable (unsigned int start, unsigned int stop)
{
   struct RaMySQLSecondsTable *sqry = NULL;
   char buf[2048], sbuf[2048];
   MYSQL_RES *mysqlRes;
   char *endptr, *str;
   int retn, x;


   if (RaRoleString) {
      str = "SELECT * from %s_Seconds WHERE second >= %u and second <= %u",
      sprintf (buf, str, RaRoleString, start, stop);
   } else {
      str = "SELECT * from Seconds WHERE second >= %u and second <= %u",
      sprintf (buf, str, start, stop);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "SQL Query %s\n", buf);
#endif

   if ((retn = mysql_real_query(&mysql, buf, strlen(buf))) != 0)
      ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));

   else {
      if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
    
               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));

               if ((sqry = (void *) ArgusCalloc (1, sizeof(*sqry))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

               for (x = 0; x < retn; x++) {
                  int y = x;
                  snprintf(sbuf, 2048, "%.*s ", (int) lengths[x], row[x] ? row[x] : "NULL");
                  if (!(RaRoleString)) 
                     y++;
                  
                  switch (y) {
                     case RAMYSQL_SECONDTABLE_PROBE:
                        sqry->probe = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_SECOND:
                        sqry->second = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_FILEINDEX:
                        sqry->fileindex = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_OSTART:
                        sqry->ostart = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_OSTOP:
                        sqry->ostop = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;
                  }
               }

               ArgusAddToQueue (ArgusModelerQueue, &sqry->qhdr, ARGUS_LOCK);
            }
         }

         mysql_free_result(mysqlRes);
      }
   }
}


/*
   Mysql URL that we will respond to is:
      mysql://[username[:password]@]hostname[:port]/database/tablename
*/


void
RaMySQLInit ()
{
   int retn = 0, x;
   char *sptr = NULL, *ptr;
   char userbuf[1024], sbuf[1024];
   MYSQL_RES *mysqlRes;

   bzero((char *)RaTableExistsNames,  sizeof(RaTableExistsNames));
   bzero((char *)RaTableCreateNames,  sizeof(RaTableCreateNames));
   bzero((char *)RaTableCreateString, sizeof(RaTableCreateString));
   bzero((char *)RaTableDeleteString, sizeof(RaTableDeleteString));

   if ((RaUser == NULL) && (ArgusParser->dbustr != NULL)) {
      bzero(userbuf, sizeof(userbuf));
      strncpy (userbuf, ArgusParser->dbustr, sizeof(userbuf));
      if ((sptr = strchr (userbuf, ':')) != NULL) {
         *sptr++ = '\0';
         RaPass = strdup(sptr);
      }
      RaUser = strdup(userbuf);
   }

   if ((RaPass == NULL) && (ArgusParser->dbpstr != NULL))
      RaPass = ArgusParser->dbpstr;

   if (RaDatabase == NULL) {
      if (ArgusParser->writeDbstr != NULL)
         RaDatabase = strdup(ArgusParser->writeDbstr);

      else if (ArgusParser->readDbstr != NULL)
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
 
   if ((ptr = strchr (RaDatabase, '/')) != NULL) {
      *ptr++ = '\0';
      RaTable = ptr;

      if (ArgusParser->writeDbstr != NULL)
         RaSQLSaveTable = strdup(RaTable);
   }

   if (!(ArgusParser->status & ARGUS_REAL_TIME_PROCESS))
      ArgusLastTime = ArgusParser->ArgusRealTime;
 
   if ((mysql_init(&mysql)) == NULL)
      ArgusLog(LOG_ERR, "mysql_init error %s");

   if (!mysql_thread_safe())
      ArgusLog(LOG_INFO, "mysql not thread-safe");

   mysql_options(&mysql, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);

   if ((mysql_real_connect(&mysql, RaHost, RaUser, RaPass, NULL, RaPort, NULL, 0)) == NULL)
      ArgusLog(LOG_ERR, "mysql_connect error %s", mysql_error(&mysql));

   RaMySQL = &mysql;

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "SHOW VARIABLES LIKE 'bulk_insert_buffer_size'");

   if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(&mysql));

   if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");

           ArgusSQLBulkBufferSize = (int)strtol(sbuf, (char **)NULL, 10);
         }
      }
      mysql_free_result(mysqlRes);
   }

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "SHOW VARIABLES LIKE 'max_allowed_packet'");

   if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(&mysql));

   if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");
            
           ArgusSQLMaxPacketSize = (int)strtol(sbuf, (char **)NULL, 10);
         }
      }
      mysql_free_result(mysqlRes);
   }

   ArgusSQLBulkInsertSize = (ArgusSQLMaxPacketSize < ArgusSQLBulkBufferSize) ? ArgusSQLMaxPacketSize : ArgusSQLBulkBufferSize;

   if ((ArgusSQLBulkBuffer = calloc(1, ArgusSQLBulkInsertSize)) == NULL)
      ArgusLog(LOG_WARNING, "ArgusMySQLInit: cannot alloc bulk buffer size %d\n", ArgusSQLBulkInsertSize);

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "CREATE DATABASE IF NOT EXISTS %s", RaDatabase);

   if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)  
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(&mysql));

   sprintf (sbuf, "USE %s", RaDatabase);

   if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(&mysql));

   if ((mysqlRes = mysql_list_tables(&mysql, NULL)) != NULL) {
      char sbuf[MAXSTRLEN];

      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         int thisIndex = 0;

         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            bzero(sbuf, sizeof(sbuf));
               for (x = 0; x < retn; x++)
               sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

            RaTableExistsNames[thisIndex++] = strdup (sbuf);
         }

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "mysql_num_fields() returned zero.\n");
#endif
      }
      mysql_free_result(mysqlRes);
   }

   if (ArgusParser->writeDbstr != NULL) {
      char *ptr;
      sprintf (ArgusParser->RaDBString, "-w %s", ArgusParser->writeDbstr);
      if ((ptr = strrchr(ArgusParser->writeDbstr, '/')) != NULL)
         *ptr = '\0';

   } else 
   if (ArgusParser->readDbstr != NULL) {
      char *ptr;
      sprintf (ArgusParser->RaDBString, "-r %s", ArgusParser->readDbstr);
      if ((ptr = strrchr(ArgusParser->readDbstr, '/')) != NULL)
         *ptr = '\0';
   } else  {
      sprintf (ArgusParser->RaDBString, "db %s", RaDatabase);

      if (RaHost)
         sprintf (&ArgusParser->RaDBString[strlen(ArgusParser->RaDBString)], "@%s", RaHost);

      sprintf (&ArgusParser->RaDBString[strlen(ArgusParser->RaDBString)], " user %s", RaUser);
   }

   if ((ArgusParser->ArgusInputFileList != NULL)  ||
        (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0))) {

      if (RaSQLSaveTable != NULL) {
         if (!((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))))
            if (ArgusCreateSQLSaveTable(RaSQLSaveTable))
               ArgusLog(LOG_ERR, "mysql create %s returned error", RaSQLSaveTable);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}


/*
    So first look to see if the table already exists.
    If so and we're suppose to delete, then delete it.
    Then look to see if the name is in our list of default
    RaTableCreateNames[] to see if we need to remove it
    from that list, if we didn't catch the table in the
    other list.  At the end of this routine cindex is pointing 
    at the right place.
*/

extern int RaDaysInAMonth[12];

time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;

char *
ArgusCreateSQLSaveTableName (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, char *table)
{
   char *retn = NULL;
   struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;

   if (strchr(table, '%') || strchr(table, '$')) {
      int size = nadp->size / 1000000;
      long long start;
      time_t tableSecs;
      struct tm tmval;

      if (ns != NULL) 
         start = ArgusFetchStartuSecTime(ns);
      else 
         start = parser->ArgusRealTime.tv_sec * 1000000LL + parser->ArgusRealTime.tv_usec;
      
      tableSecs = start / 1000000;

      if (!(ArgusTableStartSecs) || !((tableSecs >= ArgusTableStartSecs) && (tableSecs < ArgusTableEndSecs))) {
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

         if (strftime(ArgusSQLSaveTableNameBuf, MAXSTRLEN, table, &tmval) <= 0)
            ArgusLog (LOG_ERR, "RaSendArgusRecord () ArgusCalloc %s\n", strerror(errno));

         RaProcessSplitOptions(ArgusParser, ArgusSQLSaveTableNameBuf, MAXSTRLEN, ns);
/* 
         if (strcmp(wfile->filename, ArgusSQLSaveTableNameBuf))
            ArgusInitNewFilename(ArgusParser, wfile, ArgusSQLSaveTableNameBuf);
*/
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
      }
/*
      if (tableSecs > ArgusSaveTableSeconds) {
         if (strftime(tmpbuf, 1024, table, localtime_r(&tSecs, &tmval)) <= 0)
            ArgusLog (LOG_ERR, "RaSendArgusRecord () ArgusCalloc %s\n", strerror(errno));

         if (ArgusSaveTableSeconds < tableSecs)
            ArgusSaveTableSeconds = tableSecs;

         RaProcessSplitOptions(parser, tmpbuf, 1024, ns);
      }
*/
      retn = ArgusSQLSaveTableNameBuf;

   } else {
      bcopy(ArgusSQLSaveTableNameBuf, table, strlen(table));
      retn = ArgusSQLSaveTableNameBuf;
   }

   return (retn);
}


int
ArgusCreateSQLSaveTable(char *table)
{
   int retn = 0, cindex = 0, ind = 0, i, x, exists = 0;
   struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
   char stable[256], sbuf[MAXSTRLEN], kbuf[MAXSTRLEN];
   MYSQL_RES *mysqlRes;

   sprintf (stable, "%s", table);

   for (i = 0; i < RA_MAXTABLES; i++) {
      if (RaTableExistsNames[i] != NULL) {
         free (RaTableExistsNames[i]);
         RaTableExistsNames[i] = NULL;
      } else
         break;
   }

   if ((mysqlRes = mysql_list_tables(&mysql, NULL)) != NULL) {
      char sbuf[MAXSTRLEN];

      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         int thisIndex = 0;

         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            bzero(sbuf, sizeof(sbuf));
               for (x = 0; x < retn; x++)
               sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

            RaTableExistsNames[thisIndex++] = strdup (sbuf);
         }

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "mysql_num_fields() returned zero.\n");
#endif
      }

      mysql_free_result(mysqlRes);
   }


   for (i = 0; i < RA_MAXTABLES && !exists; i++) {
      if (RaTableExistsNames[i] != NULL) {
         if (!strcmp(RaTableExistsNames[i], stable))
            exists++;
      } else
         break;
   }

   if (!exists) {
      RaTableCreateNames[cindex] = strdup(stable);

      sprintf (sbuf, "CREATE table %s (", RaTableCreateNames[cindex]);
      ind = 0;

      for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
         if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
            ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[i];

            for (x = 0; x < ARGUS_MAX_PRINT_ALG; x++) {
               if (!strcmp(ArgusParser->RaPrintAlgorithm->field, RaPrintAlgorithmTable[x].field)) {
                  if (ind++ > 0)
                     sprintf (&sbuf[strlen(sbuf)], ",");

                  sprintf (&sbuf[strlen(sbuf)], "%s %s", RaPrintAlgorithmTable[x].field, RaPrintAlgorithmTable[x].dbformat);
                  break;
               }
            }
         }
      }

      if ((ArgusParser->ArgusAggregator != NULL) || ArgusAutoId) {
         struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

         long long mask = 0;
         int status = 0;

         while (agg != NULL) {
            mask |= agg->mask;
            status |= agg->status;
            agg = agg->nxt;
         }

         if (mask || ArgusAutoId) {
            ind = 0;
            sprintf (kbuf, "primary key (");

            if (ArgusAutoId) {
               sprintf (&kbuf[strlen(kbuf)], "autoid");
               ind++;
            }

            for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
               int found; 
               if (mask & (0x01LL << i)) {
                  for (found = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                     if (ArgusParser->RaPrintAlgorithmList[x] != NULL) {
                        ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[x];
                        if (!strcmp(ArgusParser->RaPrintAlgorithm->field, ArgusMaskDefs[i].name)) {
                           found = 1;
                           break;
                        }
                     }
                  }

                  if (!found)
                     ArgusLog(LOG_ERR, "key field '%s' not in schema (-s option)",  ArgusMaskDefs[i].name);

                  for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                     if (!(strcasecmp (ArgusMaskDefs[i].name, RaPrintAlgorithmTable[x].field))) {
                        if (ind++ > 0)
                           sprintf (&kbuf[strlen(kbuf)], ",");

                        sprintf (&kbuf[strlen(kbuf)], "%s", RaPrintAlgorithmTable[x].field);
                        break;
                     }
                  }
               }
            }
         }
      }

/*
      if (ind > 0)
         sprintf (&sbuf[strlen(sbuf)], ", %s)", kbuf);
*/

      if (ArgusSOptionRecord)
         sprintf (&sbuf[strlen(sbuf)], ", record blob");

      sprintf (&sbuf[strlen(sbuf)], ") TYPE=MyISAM");
      RaTableCreateString[cindex] = strdup(sbuf);

      cindex++;

      for (i = 0; i < cindex; i++) {
         char *str = NULL;
         if (RaTableCreateNames[i] != NULL) {
            if ((str = RaTableCreateString[i]) != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "generating table %s\n", str);
#endif
               if ((retn = mysql_real_query(&mysql, str, strlen(str))) != 0)
                  ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(&mysql));

               ArgusCreateTable = 1;
               RaSQLCurrentTable = strdup(table);
            }
         }
      }

   } else {
      if (RaSQLCurrentTable == NULL)
         RaSQLCurrentTable = strdup(table);
      retn = 0;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCreateSQLSaveTable (%s) returning", table, retn);
#endif
   return (retn);
}


void
RaMySQLDeleteRecords(struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   char sbuf[MAXSTRLEN];

#if defined(ARGUSMYSQL)
   if (RaSQLUpdateDB && RaSQLSaveTable) {
      if (ns->htblhdr != NULL) {
         ArgusRemoveHashEntry(&ns->htblhdr);
         ns->htblhdr = NULL;
      }

      if (ns->hinthdr != NULL) {
         ArgusRemoveHashEntry(&ns->hinthdr);
         ns->hinthdr = NULL;
      }

      if (RaSQLDBDeletes)
         if (ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, ns, sbuf, ARGUS_STOP) == NULL)
            ArgusLog(LOG_ERR, "RaMySQLDeleteRecords: ArgusScheduleSQLQuery error %s", strerror(errno));
   }
#endif

   ArgusDeleteRecordStruct (parser, ns);

#ifdef ARGUSDEBUG
      ArgusDebug (4, "RaMySQLDeleteRecords (0x%x, 0x%x) done", parser, ns);
#endif
}

char *
ArgusTrimString (char *str)
{
   char *retn = NULL;
   while (isspace((int)*str)) str++;
   retn = str;

   str = &str[strlen(str) - 1];

   while ((*str != '\0') && (isspace((int)*str)))
      *str-- = '\0';

   return (retn);
}

char *
ArgusScheduleSQLQuery (struct ArgusParserStruct *parser, struct ArgusAggregatorStruct *agg, struct ArgusRecordStruct *ns, char *sbuf, int state)
{
   char *retn = sbuf;
   char tbuf[1024], fbuf[1024], ubuf[1024], *ptr, *tptr;
   char tmpbuf[MAXSTRLEN], rbuf[MAXSTRLEN], mbuf[MAXSTRLEN], dbuf[MAXSTRLEN];
   struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;
   struct ArgusSQLQueryStruct *sqry = NULL;
   struct ArgusRecord *argus = NULL;

   int i, y, len, ind = 0, mind = 0, iind = 0;
   char vbuf[1024], ibuf[1024];
   int  nflag, found, uflag;

   nflag = parser->nflag;
   parser->nflag = 2;

   bzero(vbuf, sizeof(vbuf));
   bzero(fbuf, sizeof(fbuf));
   bzero(ubuf, sizeof(ubuf));
   bzero(tbuf, sizeof(tbuf));
   bzero(ibuf, sizeof(ibuf));
   bzero(sbuf, sizeof(MAXSTRLEN));

   for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
      if (parser->RaPrintAlgorithmList[i] != NULL) {
         parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[i];

         if (strncmp(parser->RaPrintAlgorithm->field, "autoid", 6)) {
            int len = parser->RaPrintAlgorithm->length;
            len = (len > 256) ? len : 256;

            found = 0;
            bzero (tmpbuf, sizeof(tmpbuf));

            if (agg && agg->mask) {
               for (y = 0; y < ARGUS_MAX_MASK_LIST; y++) {
                  if (agg->mask & (0x01LL << y)) {
                     if (!strcmp(parser->RaPrintAlgorithm->field, ArgusMaskDefs[y].name)) {
                        found++;
                     }
                  }
               }
            }

            if (ind++ > 0) {
               sprintf (&fbuf[strlen(fbuf)], ",");
               sprintf (&vbuf[strlen(vbuf)], ",");
            }

            if (found) {
               if (mind++ > 0)
                  sprintf (&ubuf[strlen(ubuf)], " and ");
            } else {
               if (iind++ > 0)
                  sprintf (&ibuf[strlen(ibuf)], ",");
            }

            uflag = ArgusParser->uflag;
            ArgusParser->uflag++;

            parser->RaPrintAlgorithm->print(parser, tmpbuf, ns, len);

            ArgusParser->uflag = uflag;

            if ((ptr = ArgusTrimString(tmpbuf)) != NULL) {
               sprintf (tbuf, "\"%s\"", ptr);
               tptr = &fbuf[strlen(fbuf)];
               sprintf (tptr, "%s", tbuf);

               sprintf (&vbuf[strlen(vbuf)], "%s", parser->RaPrintAlgorithm->field);
               sprintf (tbuf, "%s=\"%s\"", parser->RaPrintAlgorithm->field, ptr);

               if (found) {
                  tptr = &ubuf[strlen(ubuf)];
                  sprintf (tptr, "%s", tbuf);
               } else {
                  tptr = &ibuf[strlen(ibuf)];
                  sprintf (tptr, "%s", tbuf);
               }
            }
         }
      }
   }

   parser->nflag   = nflag;

   if (state != ARGUS_STOP) {
      if (ArgusSOptionRecord) {
         if ((argus = ArgusGenerateRecord (ns, 0L, rbuf)) == NULL)
            ArgusLog(LOG_ERR, "ArgusScheduleSQLQuery: ArgusGenerateRecord error %s", strerror(errno));
#ifdef _LITTLE_ENDIAN
         ArgusHtoN(argus);
#endif

         if ((len = mysql_real_escape_string(&mysql, mbuf, (char *)argus, ntohs(argus->hdr.len) * 4)) <= 0)
            ArgusLog(LOG_ERR, "mysql_real_escape_string error %s", mysql_error(&mysql));
      }

      if ((ns->qhdr.logtime.tv_sec > 0) && !(ns->status & ARGUS_RECORD_CLEARED)) {
         if (ArgusSOptionRecord) {
            if (strlen(ibuf)) {
               sprintf (sbuf, "UPDATE %s SET %s,record=\"%s\" WHERE %s", RaSQLCurrentTable, ibuf, mbuf, ubuf);
               sprintf (dbuf, "UPDATE %s SET %s,record=\"...\" WHERE %s", RaSQLCurrentTable, ibuf, ubuf);
            } else {
               sprintf (sbuf, "UPDATE %s SET record=\"%s\" WHERE %s", RaSQLCurrentTable, mbuf, ubuf);
               sprintf (dbuf, "UPDATE %s SET record=\"...\" WHERE %s", RaSQLCurrentTable, ubuf);
            }
         } else {
            sprintf (sbuf, "UPDATE %s SET %s WHERE %s", RaSQLCurrentTable, ibuf, ubuf);
            sprintf (dbuf, "%s", sbuf);
         }

      } else {
         if (ArgusSOptionRecord) {
            sprintf (sbuf, "INSERT INTO %s (%s,record) VALUES (%s,\"", RaSQLCurrentTable, vbuf, fbuf);
            bcopy(mbuf, &sbuf[strlen(sbuf)], len + 1);
            sprintf (&sbuf[strlen(sbuf)], "\")");

            sprintf (dbuf, "INSERT INTO %s (%s,record) VALUES (%s,...)", RaSQLCurrentTable, vbuf, fbuf);

         } else {
            sprintf (sbuf, "INSERT INTO %s (%s) VALUES (%s)", RaSQLCurrentTable, vbuf, fbuf);
            sprintf (dbuf, "%s", sbuf);
         }

#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusScheduleSQLQuery (0x%x, 0x%x, 0x%x, %s, %d) done\n", parser, agg, ns, dbuf, state);
#endif
      }

      ns->status &= ~ARGUS_RECORD_CLEARED;

   } else {
      sprintf (sbuf, "DELETE FROM %s WHERE %s", RaSQLCurrentTable, ubuf);
      sprintf (dbuf, "%s", sbuf);
#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusScheduleSQLQuery (0x%x, 0x%x, 0x%x, %s, %d) done\n", parser, agg, ns, dbuf, state);
#endif
   }

   ns->qhdr.logtime = ArgusParser->ArgusRealTime;

   if ((sqry = (void *) ArgusCalloc(1, sizeof(*sqry))) == NULL)
      ArgusLog(LOG_ERR, "ArgusScheduleSQLQuery: ArgusCalloc error %s", strerror(errno));

   sqry->tbl  = strdup(RaSQLCurrentTable);
   sqry->sptr = strdup(retn);
   sqry->dptr = strdup(dbuf);

   ArgusPushBackList (ArgusSQLQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
   return (retn);
}


#endif
