/*
 * Argus Software
 * Copyright (c) 2000-2009 QoSient, LLC
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
 * rastream - time based stream processor. 
 *    this routine will take in an argus stream and align it to
 *    to a time array, and hold it for a hold period, and then
 *    output the bin contents as an argus stream, splitting into
 *    an output strategy like rasplit().  when a file is done,
 *    rastream() closes the file, and then forks whatever
 *    program is specified on the commandline.
 *
 *    this is the primary stream block processor for Argus.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * 
 * $Id: //depot/argus/clients/clients/rastream.c#32 $
 * $DateTime: 2009/07/22 18:40:35 $
 * $Change: 1767 $
 */

#if defined(CYGWIN)
#define USE_IPV6
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <unistd.h>
#include <stdlib.h>

#include <math.h>

#include <compat.h>
#include <sys/wait.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <rabins.h>
#include <rasplit.h>
#include <argus_sort.h>
#include <argus_cluster.h>

#include <signal.h>
#include <ctype.h>


int RaRealTime = 0;
float RaUpdateRate = 1.0;

struct timeval ArgusLastRealTime = {0, 0};
struct timeval ArgusLastTime     = {0, 0};
struct timeval ArgusThisTime     = {0, 0};
struct timeval dLastTime         = {0, 0};
struct timeval dRealTime         = {0, 0};
struct timeval dThisTime         = {0, 0};
struct timeval dTime             = {0, 0};

long long thisUsec = 0;

#define ARGUS_SCRIPT_TIMEOUT            30

struct ArgusScriptStruct {
   struct ArgusListObjectStruct *nxt;
   struct ArgusWfileStruct *file;
   char *script, *filename, *cmd;
   char *args[8];
   struct timeval startime;
   int timeout;
   pid_t pid;
};


int ArgusRunScript (struct ArgusParserStruct *, struct ArgusWfileStruct *);

struct RaBinProcessStruct *RaBinProcess = NULL;
struct RaBinProcessStruct *RaStreamBins = NULL;

struct ArgusHashTable ArgusFileTable;

struct ArgusListStruct *ArgusFileList = NULL;
struct ArgusListStruct *ArgusScriptList = NULL;

struct ArgusScriptStruct *ArgusCurrentScript = NULL;

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

struct ArgusWfileStruct *ArgusThisFilename(struct ArgusParserStruct *, struct ArgusWfileStruct *, struct ArgusRecordStruct *);
struct ArgusWfileStruct *ArgusFindFilename(struct ArgusParserStruct *, struct ArgusWfileStruct *, char *);
struct ArgusHashStruct  *ArgusGenerateFileHash(struct ArgusParserStruct *, char *);
struct ArgusWfileStruct *ArgusAddFilename(struct ArgusParserStruct *, struct ArgusWfileStruct *, char *);
int ArgusRemoveFilename(struct ArgusParserStruct *, struct ArgusWfileStruct *, char *);

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusWfileStruct *wfile = NULL;
   struct ArgusAdjustStruct *nadp;
   struct ArgusModeStruct *mode = NULL;
   char outputfile[MAXSTRLEN];
   int i = 0, ind = 0, count = 0;
   long long size = 1;

   parser->RaWriteOut = 0;
   bzero(outputfile, sizeof(outputfile));

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "rtime", 5)) ||
               (!(strncasecmp (mode->mode, "realtime", 8)))) {
               char *ptr = NULL;
               RaRealTime++;
               if ((ptr = strchr(mode->mode, ':')) != NULL) {
                  double value = 0.0;
                  char *endptr = NULL;
                  ptr++;
                  value = strtod(ptr, &endptr);
                  if (ptr != endptr) {
                     RaUpdateRate = value;
                  }  
               }
            } else
            if (!(strncasecmp (mode->mode, "ind", 3)))
               ArgusProcessFileIndependantly = 1;
            mode = mode->nxt;
         }
      }

      if ((ArgusFileList = ArgusNewList()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewList error %s\n", strerror(errno));

      bzero(&ArgusFileTable, sizeof(ArgusFileTable));

      ArgusFileTable.size  = 1024;
      if ((ArgusFileTable.array = (struct ArgusHashTableHdr **)
                  ArgusCalloc (1024, sizeof (struct ArgusHashTableHdr))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s\n", strerror(errno));
      
      if ((RaBinProcess = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*RaBinProcess))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));
      
#if defined(ARGUS_THREADS)
      pthread_mutex_init(&RaBinProcess->lock, NULL);
#endif

      nadp = &RaBinProcess->nadp;

      if (parser->vflag)
         ArgusReverseSortDir++;

      nadp->mode   = -1;
      nadp->modify =  1;
      nadp->slen   =  2;

      if (parser->aflag)
         nadp->slen = parser->aflag;

      parser->RaCumulativeMerge = 1;

      if ((ArgusSorter = ArgusNewSorter()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));
      
      ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortSrcId;
      ArgusSorter->ArgusSortAlgorithms[1] = ArgusSortStartTime;
      
      
      parser->RaClientTimeout.tv_sec  = 0;
      parser->RaClientTimeout.tv_usec = 274895;
      parser->RaInitialized++;
      
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

               fclose (stdin);
               fclose (stdout);
               fclose (stderr);
            }
         }
      }

      if (ArgusParser->ArgusWfileList && (ArgusParser->ArgusWfileList->start != NULL)) {
         count = ArgusParser->ArgusWfileList->count;
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) ArgusPopFrontList(parser->ArgusWfileList, ARGUS_NOLOCK)) != NULL) {
               if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                  strncpy (outputfile, wfile->filename, MAXSTRLEN);
                  count++;
                  break;
               } else
                  ArgusPushBackList(ArgusParser->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_NOLOCK);
            }
         }
      } else {
         bzero (outputfile, MAXSTRLEN);
         *outputfile = 'x';
      }

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (isdigit((int) *mode->mode)) {
               ind = 0;
            } else {
               if (!(strncasecmp (mode->mode, "rtime", 5)) ||
                  (!(strncasecmp (mode->mode, "realtime", 8)))) {
                  char *ptr = NULL;
                  RaRealTime++;
                  if ((ptr = strchr(mode->mode, ':')) != NULL) {
                     double value = 0.0;
                     char *endptr = NULL;
                     ptr++;
                     value = strtod(ptr, &endptr);
                     if (ptr != endptr) {
                        RaUpdateRate = value;
                     }
                  }
               } else
               if (!(strncasecmp (mode->mode, "nomerge", 4)))
                  parser->RaCumulativeMerge = 0;
               else
               if (!(strncasecmp (mode->mode, "rmon", 4)))
                  parser->RaMonMode++;
               else
               if (!(strncasecmp (mode->mode, "norep", 5)))
                  parser->RaAgMode++;
               else {
                  for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
                     if (!(strncasecmp (mode->mode, RaSplitModes[i], 3))) {
                        ind = i;
                        switch (ind) {
                           case ARGUSSPLITTIME:
                           case ARGUSSPLITSIZE:
                           case ARGUSSPLITCOUNT:
                              if ((mode = mode->nxt) == NULL)
                                 usage();
                              break;
                        }
                     }
                  }
               }
            }

            if (ind < 0)
               usage();

            switch (ind) {
               case ARGUSSPLITTIME:
                  nadp->mode   = ind;
                  nadp->modify =  1;
                  if (isdigit((int)*mode->mode)) {
                     char *ptr = NULL;
                     nadp->value = strtod(mode->mode, (char **)&ptr);
                     if (ptr == mode->mode)
                        usage();
                     else {
                        time_t tsec = ArgusParser->ArgusRealTime.tv_sec;

                        switch (*ptr) {
                           case 'y':
                              nadp->qual = ARGUSSPLITYEAR;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              nadp->RaStartTmStruct.tm_hour = 0;
                              nadp->RaStartTmStruct.tm_mday = 1;
                              nadp->RaStartTmStruct.tm_mon = 0;
                              nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*24.0*7.0*52.0*1000000LL;
                              break;

                           case 'M':
                              nadp->qual = ARGUSSPLITMONTH;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              nadp->RaStartTmStruct.tm_hour = 0;
                              nadp->RaStartTmStruct.tm_mday = 1;
                              nadp->RaStartTmStruct.tm_mon = 0;
                              nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

                              nadp->size = nadp->value*3600.0*24.0*7.0*4.0*1000000LL;
                              break;

                           case 'w':
                              nadp->qual = ARGUSSPLITWEEK;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              nadp->RaStartTmStruct.tm_hour = 0;
                              nadp->RaStartTmStruct.tm_mday = 1;
                              nadp->RaStartTmStruct.tm_mon = 0;
                              nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

                              nadp->size = nadp->value*3600.0*24.0*7.0*1000000LL;
                              break;

                           case 'd':
                              nadp->qual = ARGUSSPLITDAY;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              nadp->RaStartTmStruct.tm_hour = 0;
                              nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

                              nadp->size = nadp->value*3600.0*24.0*1000000LL;
                              break;

                           case 'h':
                              nadp->qual = ARGUSSPLITHOUR;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*1000000LL;
                              break;

                           case 'm': {
                              nadp->qual = ARGUSSPLITMINUTE;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*60.0*1000000LL;
                              break;
                           }

                            default:
                           case 's': {
                              long long val = tsec / nadp->value;
                              nadp->qual = ARGUSSPLITSECOND;
                              tsec = val * nadp->value;

                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->start.tv_sec = tsec;
                              nadp->size = nadp->value * 1000000LL;
                              break;
                           }
                        }
                     }
                  }
                  RaBinProcess->rtime.tv_sec = nadp->start.tv_sec;

                  if (RaRealTime)
                     nadp->start.tv_sec = 0;

                  ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                  break;


               case ARGUSSPLITSIZE:
               case ARGUSSPLITCOUNT:
                  nadp->mode = ind;
                  nadp->count = 1;

                  if (mode != NULL) {
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

               case ARGUSSPLITFLOW: {
                  nadp->mode = ind;
                  if ((mode = mode->nxt) != NULL) {
                     nadp->filterstr = strdup(mode->mode);

                     if (ArgusFilterCompile (&nadp->filter, nadp->filterstr, ArgusParser->Oflag) < 0)
                        ArgusLog (LOG_ERR, "flow filter parse error");

                     if (ArgusParser->bflag) {
                        nff_dump(&nadp->filter, ArgusParser->bflag);
                        exit (0);
                     }
                  }
                  break;
               }

               case ARGUSSPLITPATTERN:
                  break;

               case ARGUSSPLITNOMODIFY:
                  nadp->modify = 0;
            }

            mode = mode->nxt;
         }
      }

      RaBinProcess->size  = nadp->size;
      if (!(nadp->value))
         nadp->value = 1;

      if (nadp->mode < 0) {
         nadp->value = 1;
         nadp->count = 1;
      }

      if (ArgusParser->Bflag == 0)
         ArgusParser->Bflag = 3;

/*
   At this point RaBinProcess has the timing specifications for the files.
   We need this structure to specify the filenames and to
   align the data to the time barriers set up by the files.

   However, we need a structure to hold the bins so we can
   process records based on the delay buffer hold time.

*/
      RaBinProcess->size  = nadp->size;
      RaBinProcess->rtime.tv_sec = ArgusParser->ArgusRealTime.tv_sec;

      if (ArgusParser->startime_t && ArgusParser->lasttime_t) {
         nadp->count = ((ArgusParser->lasttime_t - ArgusParser->startime_t)/size) + 1;
      } else {
         int cnt = ((parser->Bflag * 1000000LL) / nadp->size);
         nadp->count = ((size > cnt) ? size : cnt);
         nadp->count += 2;
      }

      /*
         If content substitution, either time or any field, is used,
         size and count modes will not work properly.  If using
         the default count, set the value so that we generate only
         one filename.

         If no substitution, then we need to add "aa" suffix to the
         output file for count and size modes.
      */
 
      if ((strchr(outputfile, '%')) || (strchr(outputfile, '$'))) {
         switch (nadp->mode) {
            case ARGUSSPLITCOUNT:
               nadp->count = -1;
               break;

            case ARGUSSPLITSIZE:
            case ARGUSSPLITFLOW:
               for (i = 0; i < nadp->slen; i++) 
#if defined(HAVE_STRLCAT)
                  strlcat(outputfile, "a", MAXSTRLEN - strlen(outputfile));
#else
                  strcat(outputfile, "a");
#endif
               break;
         }

      } else {
         switch (nadp->mode) {
            case ARGUSSPLITSIZE:
            case ARGUSSPLITCOUNT:
            case ARGUSSPLITFLOW:
               for (i = 0; i < nadp->slen; i++) 
#if defined(HAVE_STRLCAT)
                  strlcat(outputfile, "a", MAXSTRLEN - strlen(outputfile));
#else
                  strcat(outputfile, "a");
#endif
               break;
         }
      }

      if (!(strchr(outputfile, '%'))) {
         switch (nadp->mode) {
            case ARGUSSPLITTIME:
            /* if strftime() labels are not in use, need to add suffix */
               if (outputfile[strlen(outputfile) - 1] != '.')
#if defined(HAVE_STRLCAT)
                  strlcat(outputfile, ".", MAXSTRLEN - strlen(outputfile));
#else
                  strcat(outputfile, ".");
#endif
#if defined(HAVE_STRLCAT)
                  strlcat(outputfile, "%Y.%m.%d.%H.%M.%S", MAXSTRLEN - strlen(outputfile));
#else
                  strcat(outputfile, "%Y.%m.%d.%H.%M.%S");
#endif
              break;
         }
      }

      nadp->filename = strdup(outputfile);
      setArgusWfile (parser, outputfile, NULL);

      size = 1000000LL;

      if ((RaStreamBins = RaNewBinProcess(parser, size)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

      RaStreamBins->size        =  size;
      RaStreamBins->nadp.size   =  RaStreamBins->size;
      RaStreamBins->nadp.value  =  1;
      RaStreamBins->nadp.count  =  ArgusParser->Bflag ? ArgusParser->Bflag : 5;

      RaStreamBins->nadp.mode   = -1;
      RaStreamBins->nadp.modify =  0;
      RaStreamBins->nadp.slen   =  2;

      RaStreamBins->nadp.start.tv_sec  = 0;
      RaStreamBins->nadp.start.tv_usec = 0;
      bzero(&RaStreamBins->nadp.RaStartTmStruct, sizeof(struct tm));

      parser->RaClientTimeout.tv_sec  = 0;
      parser->RaClientTimeout.tv_usec = 330000;

      parser->RaInitialized++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientInit()\n");
#endif
}


void RaArgusInputComplete (struct ArgusInput *input) { return; }


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
#endif
         switch (sig) {
            case SIGHUP:
            case SIGINT:
            case SIGTERM:
            case SIGQUIT: {
               struct ArgusWfileStruct *wfile = NULL;

               if (ArgusParser->ArgusWfileList != NULL) {
                  struct ArgusListObjectStruct *lobj = NULL;
                  int i, count = ArgusParser->ArgusWfileList->count;

                  if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
                     for (i = 0; i < count; i++) {
                        if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                           if (wfile->fd != NULL) {
#ifdef ARGUSDEBUG
                              ArgusDebug (2, "RaParseComplete: closing %s\n", wfile->filename);
#endif
                              fflush (wfile->fd);
                              fclose (wfile->fd);
                              wfile->fd = NULL;
                           }
                        }
                        lobj = lobj->nxt;
                     }
                  }
               }
               exit(0);
               break;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaParseComplete(%d)\n", sig);
#endif
}

struct ArgusTime RaFileTimeout = {0, 0};

void
ArgusClientTimeout ()
{
   struct ArgusRecordStruct *ns = NULL, *argus = NULL;
   struct RaBinProcessStruct *rbps = RaStreamBins;
   struct RaBinStruct *bin = NULL;
   int i, count;

   if (RaRealTime) {  /* establish value for time comparison */
      gettimeofday(&ArgusParser->ArgusRealTime, 0);
      ArgusAdjustGlobalTime(ArgusParser, &ArgusParser->ArgusRealTime);

      if (ArgusLastTime.tv_sec != 0) {
         if (ArgusLastRealTime.tv_sec > 0) {
            dRealTime = *RaDiffTime(&ArgusParser->ArgusRealTime, &ArgusLastRealTime);
            thisUsec = ((dRealTime.tv_sec * 1000000) + dRealTime.tv_usec) * RaUpdateRate;
            dRealTime.tv_sec  = thisUsec / 1000000;
            dRealTime.tv_usec = thisUsec % 1000000;

            ArgusLastTime.tv_sec  += dRealTime.tv_sec;
            ArgusLastTime.tv_usec += dRealTime.tv_usec;

            if (ArgusLastTime.tv_usec > 1000000) {
               ArgusLastTime.tv_sec++;
               ArgusLastTime.tv_usec -= 1000000;
            }
         }

         ArgusLastRealTime = ArgusParser->ArgusRealTime;
      }
   }

   if (ArgusScriptList) {
      struct ArgusScriptStruct *script = NULL;
      int retn = 0, status;

      if ((script = ArgusCurrentScript) != NULL) {
         if (script->pid > 0) {
            if ((retn = waitpid(script->pid, &status, WNOHANG)) == script->pid) {
#ifdef ARGUSDEBUG
               ArgusDebug (1, "ArgusClientTimeout(): waitpid(%d) returned for %d", script->pid, retn);
#endif
               if (WIFEXITED(status)) {
#ifdef ARGUSDEBUG
                  ArgusDebug (1, "ArgusTask(%d): task %s completed", script->pid, script->cmd);
#endif
               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (1, "ArgusTask(%d): task %s completed with problems", script->pid, script->cmd);
#endif
               }

               if (script->filename)
                  free(script->filename);
               if (script->script)
                  free(script->script);
               if (script->cmd)
                  free(script->cmd);
               ArgusFree(script);
               ArgusCurrentScript = NULL;
            } else {
               if (retn == -1) {
                  switch (errno) {
                     case ECHILD: {
                        if (script->filename)
                           free(script->filename);
                        if (script->script)
                           free(script->script);
                        if (script->cmd)
                           free(script->cmd);
                        ArgusFree(script);
                        ArgusCurrentScript = NULL;
                        break;
                     }
                  }
               }
            }
         }
      }

      if (ArgusCurrentScript == NULL) {
         if ((script = (struct ArgusScriptStruct *) ArgusFrontList(ArgusScriptList)) != NULL) {
            ArgusPopFrontList(ArgusScriptList, ARGUS_LOCK); 

            if ((script->pid = fork()) < 0)
               ArgusLog (LOG_ERR, "ArgusRunScript (%s) fork() error %s\n", script->cmd, strerror(errno));

            if (script->pid > 0) {
               ArgusCurrentScript = script;
            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (1, "ArgusRunScript calling %s", script->cmd);
#endif
               exit(execv(script->script, script->args));
            }
         }
      }
   }

   if ((ArgusParser->Bflag > 0) && rbps->rtime.tv_sec) {
      struct timeval *diffTime;
      long long dtime;
               
      diffTime = RaDiffTime(&ArgusParser->ArgusRealTime, &rbps->rtime);
      dtime = (diffTime->tv_sec * 1000000LL) + diffTime->tv_usec;

      if (dtime >= ((ArgusParser->Bflag * 1000000LL) + rbps->size)) {
         long long rtime = (rbps->rtime.tv_sec * 1000000LL) + rbps->rtime.tv_usec;

         count = (rbps->end - rbps->start)/rbps->size;

         if (rbps->array != NULL) {
            if ((bin = rbps->array[rbps->index]) != NULL) {
               struct ArgusAggregatorStruct *agg = bin->agg;
               while (agg) {
                  if (agg->queue->count) {
                     int cnt = 0;

#ifdef ARGUSDEBUG
                     ArgusDebug (1, "ArgusClientTimeout() RaStreamBins: Bflag %d rtime %d start %d end %d size %d items %d\n",
                        ArgusParser->Bflag, RaStreamBins->rtime.tv_sec, RaStreamBins->startpt.tv_sec, RaStreamBins->endpt.tv_sec,
                        RaStreamBins->size, agg->queue->count);
#endif
                     ArgusSortQueue(ArgusSorter, agg->queue);
                     argus = ArgusCopyRecordStruct((struct ArgusRecordStruct *) agg->queue->array[0]);

                     cnt = agg->queue->count;

                     for (i = 1; i < cnt; i++)
                        ArgusMergeRecords (agg, argus, (struct ArgusRecordStruct *)agg->queue->array[i]);

                     ArgusParser->ns = argus;

                     for (i = 0; i < cnt; i++)
                        RaProcessThisRecord (ArgusParser, (struct ArgusRecordStruct *) agg->queue->array[i]);

                     ArgusDeleteRecordStruct(ArgusParser, ArgusParser->ns);
                     ArgusParser->ns = NULL;
                  }

                  agg = agg->nxt;
               }

               RaDeleteBin(ArgusParser, bin);
               rbps->array[rbps->index] = NULL;

            } else {
               if (RaStreamBins->nadp.zero && ((i >= RaStreamBins->index) && (((i - RaStreamBins->index) * RaStreamBins->size) < RaStreamBins->scalesecs))) {
                  long long tval = RaBinProcess->start + (RaBinProcess->size * RaBinProcess->index);
                  
                  ns = ArgusGenerateRecordStruct(NULL, NULL, NULL);

                  ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.start.tv_sec  = tval / 1000000;
                  ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.start.tv_usec = tval % 1000000;
            
                  tval += RaBinProcess->size;
                  ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.end.tv_sec    = tval / 1000000;;
                  ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.end.tv_usec   = tval % 1000000;

                  RaSendArgusRecord (ns);

                  ArgusDeleteRecordStruct(ArgusParser, ns);
#ifdef ARGUSDEBUG
                  ArgusDebug (5, "ArgusClientTimeout() RaBinProcess: creating zero record\n");
#endif
               }
            }

            for (i = 0; i < count; i++)
               rbps->array[i] = rbps->array[(i + 1)];

            rbps->start += rbps->size;
            rbps->end   += rbps->size;

            rbps->array[count] = NULL;
            rbps->startpt.tv_sec += rbps->size;
         }

         rtime += rbps->size;
         rbps->rtime.tv_sec  = rtime / 1000000;
         rbps->rtime.tv_usec = rtime % 1000000;
      }
   }

   if (rbps->rtime.tv_sec == 0) {
//    long long rtime = (ArgusParser->ArgusRealTime.tv_sec * 1000000LL) / rbps->size;
      rbps->rtime.tv_sec = ArgusParser->ArgusRealTime.tv_sec;
   }

/*
   Need to process the file list here to close and run the scripts against it.
*/

   if (ArgusParser->ArgusRealTime.tv_sec > RaFileTimeout.tv_sec) {
      if ((count = ArgusFileList->count) != 0) {
         for (i = 0; i < count; i++) {
            struct ArgusWfileStruct *wfile = (void *)ArgusPopFrontList(ArgusFileList, ARGUS_LOCK);

            if ((wfile->endSecs) && (wfile->endSecs < ArgusParser->ArgusRealTime.tv_sec)) {
               ArgusRunScript(ArgusParser, wfile);
               ArgusRemoveFilename(ArgusParser, wfile, wfile->filename);
               if (wfile->fd != NULL)
                  fclose (wfile->fd);
               if (wfile->filename)
                  free(wfile->filename);
               ArgusFree(wfile);

            } else
               ArgusPushBackList(ArgusFileList, (struct ArgusListRecord *)wfile, ARGUS_LOCK);
         }
      }

      RaFileTimeout.tv_sec = ArgusParser->ArgusRealTime.tv_sec;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientTimeout()\n");
#endif
}

void parse_arg (int argc, char**argv) {}

void
usage ()
{
   extern char version[];

   fprintf (stderr, "Rasplit Version %s\n", version);
   fprintf (stderr, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -b                 dump packet-matching code.\n");
   fprintf (stderr, "         -C <[host]:port>   specify remote Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stderr, "         -D <level>         specify debug level\n");
#endif
   fprintf (stderr, "         -E <file>          write records that are rejected by the filter\n");
   fprintf (stderr, "                            into <file>\n");
   fprintf (stderr, "         -F <conffile>      read configuration from <conffile>.\n");
   fprintf (stderr, "         -h                 print help.\n");

   fprintf (stderr, "         -M <mode>          supported modes of operation:\n");
   fprintf (stderr, "            time n[smhdwmy]\n");
   fprintf (stderr, "           count n[kmb]\n");
   fprintf (stderr, "            size n[kmb]\n");
   fprintf (stderr, "            nomodify\n");

   fprintf (stderr, "         -r <file>          read argus data <file>. '-' denotes stdin.\n");
   fprintf (stderr, "         -S <host[:port]>   specify remote argus <host> and optional port\n");
   fprintf (stderr, "                            number.\n");
   fprintf (stderr, "         -t <timerange>     specify <timerange> for reading records.\n");
   fprintf (stderr, "                   format:  timeSpecification[-timeSpecification]\n");
   fprintf (stderr, "                            timeSpecification: [[[yyyy/]mm/]dd.]hh[:mm[:ss]]\n");
   fprintf (stderr, "                                                 [yyyy/]mm/dd\n");
   fprintf (stderr, "                                                 -%%d{yMdhms}\n");
   fprintf (stderr, "         -T <secs>          attach to remote server for T seconds.\n");
#ifdef ARGUS_SASL
   fprintf (stderr, "         -U <user/auth>     specify <user/auth> authentication information.\n");
#endif
   fprintf (stderr, "         -w <file>          write output to <file>. '-' denotes stdout.\n");
   exit(1);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tns = NULL;
   int retn = 0, offset = 0;
   double stime, itime, ftime;

   if ((stime = ArgusFetchStartTime(ns)) > 0.0) {
      ftime = modf(stime, &itime);
      ArgusThisTime.tv_sec  = itime;
      ArgusThisTime.tv_usec = ftime * 1000000;

      if (RaRealTime) {
         if (ArgusLastTime.tv_sec == 0)
            ArgusLastTime = ArgusThisTime;

         if (!((ArgusLastTime.tv_sec  > ArgusThisTime.tv_sec) ||
            ((ArgusLastTime.tv_sec == ArgusThisTime.tv_sec) &&
             (ArgusLastTime.tv_usec > ArgusThisTime.tv_usec)))) {

            while ((ArgusThisTime.tv_sec  > ArgusLastTime.tv_sec) ||
                  ((ArgusThisTime.tv_sec == ArgusLastTime.tv_sec) &&
                   (ArgusThisTime.tv_usec > ArgusLastTime.tv_usec))) {
               struct timespec ts = {0, 0};
               int thisRate;

               dThisTime = *RaDiffTime(&ArgusThisTime, &ArgusLastTime);
               thisRate = ((dThisTime.tv_sec * 1000000) + dThisTime.tv_usec)/RaUpdateRate;
               thisRate = (thisRate > 100000) ? 100000 : thisRate;

               ts.tv_nsec =  thisRate * 1000;
               nanosleep (&ts, NULL);

               ArgusClientTimeout ();

               gettimeofday(&parser->ArgusRealTime, 0);

               if (ArgusLastRealTime.tv_sec > 0) {
                  dRealTime = *RaDiffTime(&parser->ArgusRealTime, &ArgusLastRealTime);
                  thisUsec = ((dRealTime.tv_sec * 1000000) + dRealTime.tv_usec) * RaUpdateRate;
                  dRealTime.tv_sec  = thisUsec / 1000000;
                  dRealTime.tv_usec = thisUsec % 1000000;

                  ArgusLastTime.tv_sec  += dRealTime.tv_sec;
                  ArgusLastTime.tv_usec += dRealTime.tv_usec;
                  if (ArgusLastTime.tv_usec > 1000000) {
                     ArgusLastTime.tv_sec++;
                     ArgusLastTime.tv_usec -= 1000000;
                  }
               }
               ArgusLastRealTime = parser->ArgusRealTime;
            }
         }
      } else
         ArgusLastTime = parser->ArgusRealTime;
   }

   offset = (ArgusParser->Bflag + (RaBinProcess->nadp.size - 1))/RaBinProcess->nadp.size;
   RaBinProcess->nadp.stperiod = 0.0;
   RaBinProcess->nadp.dtperiod = 0.0;

   switch (RaBinProcess->nadp.mode) {
      case ARGUSSPLITTIME: {
         switch (ns->hdr.type & 0xF0) {
            case ARGUS_MAR: 
            case ARGUS_EVENT: {
               if ((retn = ArgusCheckTime (parser, ns)) != 0) {
                  tns = ArgusCopyRecordStruct(ns);
                  if (!(ArgusInsertRecord(parser, RaBinProcess, tns, offset)))
                     ArgusDeleteRecordStruct(parser, tns);
               }
               break;
            }

            case ARGUS_NETFLOW: 
            case ARGUS_FAR: {
               while ((tns = ArgusAlignRecord(parser, ns, &RaBinProcess->nadp)) != NULL) {
                  if ((retn = ArgusCheckTime (parser, tns)) != 0) {
                     struct ArgusMetricStruct *metric = (void *)tns->dsrs[ARGUS_METRIC_INDEX];

                     if ((metric != NULL) && ((metric->src.pkts + metric->dst.pkts) > 0)) {
                        if (!(ArgusInsertRecord(parser, RaStreamBins, tns, offset)))
                           ArgusDeleteRecordStruct(parser, tns);
                     } else
                        ArgusDeleteRecordStruct(parser, tns);
                  }
               }
               break;
            }
         }
      }
   }
 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessRecord (0x%x) done\n", ns); 
#endif
}


void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   RaSendArgusRecord (ns);
   ArgusDeleteRecordStruct (parser, ns);
}


struct ArgusHashStruct ArgusFileHash;
unsigned int ArgusFileHashBuf[(MAXSTRLEN + 1)/4];

struct ArgusHashStruct *
ArgusGenerateFileHash(struct ArgusParserStruct *parser, char *filename)
{
   struct ArgusHashStruct *retn = NULL;

   if (filename != NULL) {
      u_short *sptr = NULL;
      int i, len, s = sizeof(*sptr);

      retn = &ArgusFileHash;
      retn->len  = s * ((strlen(filename) + (s - 1))/s);
      retn->len  = (retn->len >= MAXSTRLEN) ? (MAXSTRLEN - 1) : retn->len;
      retn->buf  = ArgusFileHashBuf;
      bzero(ArgusFileHashBuf, retn->len + 1);
      bcopy(filename, ArgusFileHashBuf, retn->len);

      retn->hash = 0;
      sptr = (unsigned short *)&retn->buf[0];
      for (i = 0, len = retn->len / s; i < len; i++)
         retn->hash += *sptr++;
   }

   return (retn);
}

struct ArgusWfileStruct *
ArgusFindFilename(struct ArgusParserStruct *parser, struct ArgusWfileStruct *wfile, char *filename)
{
   struct ArgusWfileStruct *retn = NULL;
   struct ArgusHashStruct *hash = ArgusGenerateFileHash(parser, filename);
   struct ArgusHashTableHdr *tblhdr = NULL;

   if (hash != NULL)
      if ((tblhdr = ArgusFindHashEntry (&ArgusFileTable, hash)) != NULL)
         retn = (struct ArgusWfileStruct *) tblhdr->object;
   
#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusFindFilename (0x%x, 0x%x, %s) return 0x%x", parser, wfile, filename, retn);
#endif
   return(retn);
}

struct ArgusWfileStruct *
ArgusAddFilename(struct ArgusParserStruct *parser, struct ArgusWfileStruct *wfile, char *filename)
{
   struct ArgusWfileStruct *retn = NULL;
   struct ArgusHashStruct *hash = ArgusGenerateFileHash(parser, filename);

   if (hash != NULL)
      if ((wfile->htblhdr = ArgusAddHashEntry (&ArgusFileTable, (void *)wfile, hash)) != NULL) {
         ArgusPushFrontList(ArgusFileList, (struct ArgusListRecord *)wfile, ARGUS_LOCK);
         retn = wfile;
      }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusAddFilename (0x%x, 0x%x, %s) return 0x%x", parser, wfile, filename, retn);
#endif
   return(retn);
}

int
ArgusRemoveFilename(struct ArgusParserStruct *parser, struct ArgusWfileStruct *wfile, char *filename)
{
   int retn = 0, count, i;

   if (wfile != NULL) {
      if (wfile->htblhdr != NULL)
         ArgusRemoveHashEntry (&wfile->htblhdr);

      if ((count = ArgusFileList->count) != 0) {
         for (i = 0; (i < count) && (retn == 0); i++) {
            struct ArgusListRecord *lrec = ArgusPopFrontList(ArgusFileList, ARGUS_LOCK);
            if (lrec == (void *) wfile) {
               retn = 1;
            } else
               ArgusPushBackList(ArgusFileList, lrec, ARGUS_LOCK);
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusAddFilename (0x%x, 0x%x, %s) return 0x%x", parser, wfile, filename, retn);
#endif
   return(retn);
}



struct ArgusWfileStruct *
ArgusThisFilename(struct ArgusParserStruct *parser, struct ArgusWfileStruct *wfile, struct ArgusRecordStruct *ns)
{
   struct ArgusWfileStruct *retn = NULL;
   char ptrbuf[MAXSTRLEN], *tptr = ptrbuf, tmpbuf[MAXSTRLEN];
   time_t startSecs, endSecs, fileSecs;
   struct ArgusAdjustStruct *nadp;
   int newfilename = 0;

   nadp = &RaBinProcess->nadp;
   snprintf (tptr, MAXSTRLEN, "%s", wfile->filename);

   switch (nadp->mode) {
      default:
      case ARGUSSPLITTIME: {
         long long dusecs, stime = ArgusFetchStartuSecTime(ns);

         dusecs = (stime - nadp->startuSecs) / nadp->size;
         dusecs *= nadp->size;
         dusecs = (nadp->startuSecs + dusecs);
         startSecs = dusecs / 1000000;
         localtime_r(&startSecs, &nadp->RaStartTmStruct);

         endSecs = (dusecs + nadp->size) / 1000000;
         localtime_r(&endSecs, &nadp->RaEndTmStruct);

         fileSecs = startSecs;

         if (strftime(tmpbuf, MAXSTRLEN, tptr, localtime(&fileSecs)) <= 0)
            ArgusLog (LOG_ERR, "ArgusCheckCurrentWfilestatus () strftime %s", strerror(errno));

         RaProcessSplitOptions(parser, tmpbuf, MAXSTRLEN, ns);
         break;
      }

      case ARGUSSPLITCOUNT: {
         int value = nadp->value;

         if ((value > 1) && (!(nadp->count % value)))
            newfilename++;

         if (nadp->count > 0)
            nadp->count++;
         break;
      }

      case ARGUSSPLITSIZE:
         if ((nadp->value > 0) && (stat (tptr, &wfile->statbuf) == 0))
            if ((wfile->statbuf.st_size + (ns->hdr.len * 4)) > nadp->value)
               newfilename++;
         break;
   }

   switch (nadp->mode) {
      default:
      case ARGUSSPLITTIME: {
         if ((retn = ArgusFindFilename(parser, wfile, tmpbuf)) == NULL) {
            if ((retn = (struct ArgusWfileStruct *)ArgusCalloc(1, sizeof(*retn))) == NULL)
               ArgusLog (LOG_ERR, "ArgusCheckCurrentWfileStatus: ArgusCalloc error %s", strerror(errno));

            retn = ArgusAddFilename(parser, retn, tmpbuf);
            retn->filename = strdup(tmpbuf);
            retn->startSecs = startSecs;
            retn->endSecs   = endSecs + parser->Bflag + 1;
         }
         break;
      }

      case ARGUSSPLITCOUNT:
      case ARGUSSPLITSIZE: {
         if (newfilename) {
            char *tptr = NULL, *pptr = NULL;
            char *filename = NULL;

            if (wfile->filename != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (3, "ArgusThisFilename (0x%x, 0x%x, 0x%x) file done %s", parser, wfile, ns, wfile->filename);
#endif
               if (wfile->htblhdr != NULL)
                  ArgusRemoveHashEntry (&wfile->htblhdr);

               if (wfile->fd != NULL) {
                  fclose (wfile->fd);
                  wfile->fd = NULL;
               }

               ArgusFree(wfile);
            }

            if ((retn = (struct ArgusWfileStruct *)ArgusCalloc(1, sizeof(*retn))) == NULL)
               ArgusLog (LOG_ERR, "ArgusCheckCurrentWfileStatus: ArgusCalloc error %s", strerror(errno));

            if ((filename = RaSplitFilename(nadp)) == NULL)
               ArgusLog(LOG_ERR, "RaProcessRecord filename beyond space");

            retn->filename = strdup(filename);

// got new filename, need to check the
// path to be sure that all the directories exist

            strncpy (tmpbuf, retn->filename, MAXSTRLEN);
            if ((tptr = strrchr(tmpbuf, (int) '/')) != NULL) {
               *tptr = '\0';
               pptr = tptr;

               while ((pptr != NULL) && ((stat(tmpbuf, &retn->statbuf)) < 0)) {
                  switch (errno) {
                     case ENOENT:
                        if ((pptr = strrchr(tmpbuf, (int) '/')) != NULL) {
                           if (pptr != tmpbuf) {
                              *pptr = '\0';
                           } else {
                              pptr = NULL;
                           }
                        }
                        break;

                     default:
                        ArgusLog (LOG_ERR, "stat: %s %s\n", tmpbuf, strerror(errno));
                  }
               }

               while (&tmpbuf[strlen(tmpbuf)] <= tptr) {
                  if ((mkdir(tmpbuf, 0777)) < 0) {
                     if (errno != EEXIST)
                        ArgusLog (LOG_ERR, "mkdir: %s %s\n", tmpbuf, strerror(errno));
                  }
                  tmpbuf[strlen(tmpbuf)] = '/';
               }
               *tptr = '/';
            }
         }
         break;
      }
   }


#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusThisFilename (0x%x, 0x%x, 0x%x) return 0x%x", parser, wfile, ns, retn);
#endif

   return (retn);
}


int
ArgusRunScript (struct ArgusParserStruct *parser, struct ArgusWfileStruct *file)
{
   struct ArgusScriptStruct *script = NULL;
   int retn = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusRunScript(0x%x, %x) filename %s", parser, file, file->filename);
#endif

   if (file && parser->ArgusFlowModelFile) {
      char sbuf[1024];
      int i;

      if (ArgusScriptList == NULL)
         if ((ArgusScriptList = ArgusNewList()) == NULL)
            ArgusLog (LOG_ERR, "ArgusRunScript (%s) ArgusNewList() error %s\n", file->filename, strerror(errno));

      if ((script = (struct ArgusScriptStruct *) ArgusCalloc (1, sizeof(*script))) == NULL)
         ArgusLog (LOG_ERR, "ArgusRunScript (%s) ArgusCalloc() error %s\n", file->filename, strerror(errno));

      script->file = file;
      script->filename = strdup(file->filename);
      script->script = strdup(parser->ArgusFlowModelFile);
      script->startime = parser->ArgusRealTime;
      script->timeout = ARGUS_SCRIPT_TIMEOUT;

      bzero(script->args, sizeof(script->args));
      bzero(sbuf, sizeof(sbuf));

      script->args[0] = script->script;         
      script->args[1] = "-r";         
      script->args[2] = script->filename;

      for (i = 0; i < 4; i++) {
         if (script->args[i] != NULL) {
            int slen = strlen(sbuf);
            snprintf (&sbuf[slen], 1024 - slen, " %s", script->args[i]);
         }
      }

      script->cmd = strdup(sbuf);
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusRunScript(0x%x, 0x%x) scheduling %s", parser, file, script->cmd);
#endif
      ArgusPushBackList(ArgusScriptList, (struct ArgusListRecord *) script, ARGUS_LOCK);

   } else
      retn = 1;

#ifdef ARGUSDEBUG
   if (script)
      ArgusDebug (1, "ArgusRunScript(0x%x, %x) returning %s", parser, file, script->cmd);
   else
      ArgusDebug (1, "ArgusRunScript(0x%x, %x) no script", parser, file);
#endif

   return (retn);
}


int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   int retn = 1;

   if (argus->status & ARGUS_RECORD_WRITTEN)
      return (retn);
 
   if (ArgusParser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL, *tfile = NULL;
      int i, count = ArgusParser->ArgusWfileList->count;
      struct ArgusListObjectStruct *lobj = NULL;

      if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int pass = 1;
               if (wfile->filterstr) {
                  struct nff_insn *wfcode = wfile->filter.bf_insns;
                  pass = ArgusFilterRecord (wfcode, argus);
               }

               if (pass != 0) {
                  if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;
                     char buf[2048];
                     if ((argusrec = ArgusGenerateRecord (argus, 0L, buf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        if ((tfile = ArgusThisFilename(ArgusParser, wfile, argus)) != NULL)
                           ArgusWriteNewLogfile (ArgusParser, argus->input, tfile, argusrec);
                     }
                  }
               }
            }
            lobj = lobj->nxt;
         }
      }
   }

   argus->status |= ARGUS_RECORD_WRITTEN;
   return (retn);
}


void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}


char *
RaSplitFilename (struct ArgusAdjustStruct *nadp)
{
   char *retn = NULL, tmpbuf[MAXSTRLEN];
   char *filename = nadp->filename;
   int len, i = 1;

   if (filename != NULL) {
      len = strlen(filename);

      for (i = 0; i < nadp->slen; i++) {
         if (filename[len - (i + 1)] == 'z') {
            filename[len - (i + 1)] = 'a';
         } else {
            filename[len - (i + 1)]++;
            break;
         }
      }

      if (filename[len - nadp->slen] == 'z') {
         snprintf(tmpbuf, MAXSTRLEN, "%sa", filename);

         if (nadp->filename)
            free(nadp->filename);

         nadp->filename = strdup(tmpbuf);
      }

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
   char *ptr = NULL, *cptr = NULL, *tptr = str;
   int retn = 0, i, x, slen = 0;

   bzero(resultbuf, MAXSTRLEN);
   bzero(tmpbuf, MAXSTRLEN);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      slen = strlen(resultbuf);
      snprintf (&resultbuf[slen], MAXSTRLEN - slen, "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);

            while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
               tmpbuf[strlen(tmpbuf) - 1] = '\0';

            while (isspace((int)tmpbuf[i])) i++;
            slen = strlen(resultbuf);
            snprintf (&resultbuf[slen], MAXSTRLEN - slen, "%s", &tmpbuf[i]);

            ptr += strlen(RaPrintAlgorithmTable[x].field);
            cptr = &resultbuf[strlen(resultbuf)];

            while (*ptr && (*ptr != '$')) {
               *cptr++ = *ptr++;
            }
            *cptr = '\0';
            break;
         }
      }

      tptr = ptr;
      retn++;
   }

   if (retn) {
      int len = strlen(resultbuf);
      bcopy (resultbuf, str, strlen(resultbuf));
      str[len] = '\0';
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "RaProcessSplitOptions(%s, %d, 0x%x): returns %d", str, len, ns, retn);
#endif

   return (retn);
}


struct RaBinProcessStruct *
RaNewBinProcess (struct ArgusParserStruct *parser, int size)
{
   struct RaBinProcessStruct *retn = NULL;
   struct ArgusAdjustStruct *tnadp;

   parser->ArgusReverse = 0;

   if ((retn = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "RaNewBinProcess: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&retn->lock, NULL);
#endif

   tnadp = &retn->nadp;
   bcopy((char *)&RaBinProcess->nadp, (char *)tnadp, sizeof(*tnadp));

   tnadp->mode    = -1;
   tnadp->modify  =  1;
   tnadp->slen    =  2;
   tnadp->count   = 1;
   tnadp->value   = 1;

   return (retn);
}

