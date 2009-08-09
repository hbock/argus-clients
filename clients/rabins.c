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
 * rabins - time based bin processor. 
 *    this routine will take in an argus stream and align it to
 *    to a time array, and hold it for a hold period, and then
 *    output the bin countents as an argus stream.
 *
 *    this is the basis for all stream block processors.
 *    used by ragraph() to structure the data into graphing
 *    regions.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/clients/clients/rabins.c#44 $
 * $DateTime: 2009/07/31 11:50:38 $
 * $Change: 1775 $
 */

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>

#include <math.h>

#include <compat.h>

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


struct timeval dLastTime = {0, 0};
struct timeval dRealTime = {0, 0};
struct timeval dThisTime = {0, 0};
struct timeval dTime     = {0, 0};

long long thisUsec = 0;

struct RaBinProcessStruct *RaBinProcess = NULL;

int ArgusRmonMode = 0;



void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusAdjustStruct *nadp;
   struct ArgusModeStruct *mode = NULL;
   char outputfile[MAXSTRLEN];
   int i = 0, ind = 0, size = 1;
   time_t tsec = ArgusParser->ArgusRealTime.tv_sec;

   parser->RaWriteOut = 0;
   *outputfile = '\0';

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if ((RaBinProcess = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*RaBinProcess))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
      pthread_mutex_init(&RaBinProcess->lock, NULL);
#endif

      RaBinProcess->scalesecs = 0;

      nadp = &RaBinProcess->nadp;
      bzero((char *)nadp, sizeof(*nadp));

      nadp->mode      = -1;
      nadp->modify    =  1;
      nadp->slen      =  2;

      if (parser->aflag)
         nadp->slen = parser->aflag;

      if (parser->vflag)
         ArgusReverseSortDir++;

      parser->RaCumulativeMerge = 1;

      if ((ArgusSorter = ArgusNewSorter()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));
 
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
                  nadp->mode = ind;
                  if (isdigit((int)*mode->mode)) {
                     char *ptr = NULL;
                     nadp->value = strtod(mode->mode, (char **)&ptr);
                     if (ptr == mode->mode)
                        usage();
                     else {

                        switch (*ptr) {
                           case 'y':
                              nadp->qual = ARGUSSPLITYEAR;  
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              nadp->RaStartTmStruct.tm_hour = 0;
                              nadp->RaStartTmStruct.tm_mday = 1;
                              nadp->RaStartTmStruct.tm_mon = 0;
//                            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
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
//                            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
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
//                            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*24.0*7.0*1000000LL;
                              break;

                           case 'd':
                              nadp->qual = ARGUSSPLITDAY;   
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              nadp->RaStartTmStruct.tm_hour = 0;
//                            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*24.0*1000000LL;
                              break;

                           case 'h':
                              nadp->qual = ARGUSSPLITHOUR;  
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
//                            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*1000000LL;
                              break;

                           case 'm': {
                              nadp->qual = ARGUSSPLITMINUTE;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
//                            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*60.0*1000000LL;
                              break;
                           }

                            default: 
                           case 's': {
                              long long val = tsec / nadp->value;
                              nadp->qual = ARGUSSPLITSECOND;
                              tsec = val * nadp->value;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
//                            nadp->start.tv_sec = tsec;
                              nadp->size = nadp->value * 1000000LL;
                              break;
                           }
                        }
                     }
                  }

                  RaBinProcess->rtime.tv_sec = tsec;

                  if (RaRealTime) 
                     nadp->start.tv_sec = 0;

                  ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                  break;

               case ARGUSSPLITSIZE:
               case ARGUSSPLITCOUNT:
                  nadp->mode = ind;
                  nadp->count = 1;

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
                  ArgusSorter->ArgusSortAlgorithms[0] = NULL;
                  break;

               case ARGUSSPLITNOMODIFY:
                  nadp->modify = 0;
                  break;

               case ARGUSSPLITSOFT:
               case ARGUSSPLITHARD:
                  nadp->hard++;
                  break;

               case ARGUSSPLITZERO:
                  nadp->zero++;
                  break;
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

      /* if content substitution, either time or any field, is used,
         size and count modes will not work properly.  If using
         the default count, set the value so that we generate only
         one filename.

         if no substitution, then we need to add "aa" suffix to the
         output file for count and size modes.
      */

      if (parser->ArgusWfileList != NULL) {
         struct ArgusWfileStruct *wfile = NULL;

         if ((wfile = (struct ArgusWfileStruct *)ArgusPopFrontList(parser->ArgusWfileList, ARGUS_NOLOCK)) != NULL) {
            if (strcmp(wfile->filename, "-")) {
               strncpy (outputfile, wfile->filename, MAXSTRLEN);
               if ((strchr(outputfile, '%')) || (strchr(outputfile, '$'))) {
                  switch (nadp->mode) {
                     case ARGUSSPLITCOUNT:
                        nadp->count = -1;
                        break;

                     case ARGUSSPLITSIZE:
                        for (i = 0; i < nadp->slen; i++) {
#if defined(HAVE_STRLCAT)
                           strlcat(outputfile, "a", MAXSTRLEN - strlen(outputfile));
#else
                           strcat(outputfile, "a");
#endif
                        }
                        break;
                  }

               } else {
                  switch (nadp->mode) {
                     case ARGUSSPLITSIZE:
                     case ARGUSSPLITCOUNT:
                        for (i = 0; i < nadp->slen; i++) {
#if defined(HAVE_STRLCAT)
                           strlcat(outputfile, "a", MAXSTRLEN - strlen(outputfile));
#else
                           strcat(outputfile, "a");
#endif
                        }
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
            } else
               setArgusWfile (parser, "-", NULL);
         }
      }

      parser->RaClientTimeout.tv_sec  = 0;
      parser->RaClientTimeout.tv_usec = 100000;
      parser->RaInitialized++;


      if (ArgusParser->startime_t && ArgusParser->lasttime_t) {
         nadp->count = ((ArgusParser->lasttime_t - ArgusParser->startime_t)/size) + 1;
      } else {
         int cnt = (parser->Bflag * 1000000) / nadp->size;
         nadp->count = ((size > cnt) ? size : cnt);
         if (parser->Bflag) {
            nadp->count += 2;
         } else {
            nadp->count += 10000;
         }
      }

      if (parser->Gflag) {
         parser->uflag++;
         parser->RaFieldDelimiter = ',';
      }

      for (i = 0; parser->RaPrintAlgorithmList[i] != NULL; i++) {
         if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintProto) {
            parser->RaPrintMode |= RA_PRINTPROTO;
            break;
         }
         if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcPort) {
            break;
         }
         if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintDstPort) {
            break;
         }
         if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSourceID) {
            parser->RaPrintMode |= RA_PRINTSRCID;
            break;
         }
      }

      if (parser->ArgusFlowModelFile) {
         if ((parser->ArgusAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");

      } else
         if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if (RaBinProcess->size == 0)
         usage ();
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientInit()\n");
#endif
}


void RaArgusInputComplete (struct ArgusInput *input) { return; }

void
RaParseComplete (int sig)
{
   int startsecs = 0, endsecs = 0, i;
   
   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {
         if (RaBinProcess != NULL) {
            struct RaBinStruct *bin = NULL;
            struct ArgusRecordStruct *ns = NULL;

            if ((ArgusParser->ArgusWfileList == NULL) && (ArgusParser->Gflag)) {
               if (ArgusParser->startime_t && ArgusParser->lasttime_t) {
                  startsecs = ArgusParser->startime_t;
                  endsecs   = ArgusParser->lasttime_t;
               } else {
                  for (i = 0; i < (RaBinProcess->max + 1); i++) {
                     if ((bin = RaBinProcess->array[i]) != NULL) {
                        if (startsecs == 0)
                           startsecs = bin->stime.tv_sec;
                        endsecs = bin->stime.tv_sec;
                     }
                  }
               }

               if (ArgusParser->Hstr != NULL) {

               } else {
                  char stimebuf[128], dtimebuf[128], etimebuf[128];
                  int bins;

                  RaBinProcess->endpt.tv_sec   = endsecs;

                  if (!(ArgusParser->tflag)) {
                     RaBinProcess->startpt.tv_sec = startsecs;
                     RaBinProcess->scalesecs      = (endsecs - startsecs) + (RaBinProcess->size / 1000000);
                  } else {
                     RaBinProcess->startpt.tv_sec = ArgusParser->startime_t;
                     RaBinProcess->scalesecs      = ArgusParser->lasttime_t - ArgusParser->startime_t;
                  }

                  if ((ArgusParser->RaEndTime.tv_sec >  RaBinProcess->endpt.tv_sec) ||
                     ((ArgusParser->RaEndTime.tv_sec == RaBinProcess->endpt.tv_sec) &&
                      (ArgusParser->RaEndTime.tv_usec > RaBinProcess->endpt.tv_usec)))
                     ArgusParser->RaEndTime = RaBinProcess->endpt;

                  ArgusPrintTime(ArgusParser, stimebuf, &RaBinProcess->startpt);
                  ArgusPrintTime(ArgusParser, dtimebuf, &RaBinProcess->endpt);
                  ArgusPrintTime(ArgusParser, etimebuf, &ArgusParser->RaEndTime);

                  stimebuf[strlen(stimebuf) - 1] = '\0';
                  dtimebuf[strlen(dtimebuf) - 1] = '\0';
                  etimebuf[strlen(etimebuf) - 1] = '\0';

                  printf ("StartTime=%s\n", stimebuf);
                  printf ("StopTime=%s\n",  dtimebuf);
                  printf ("LastTime=%s\n",  etimebuf);
                  printf ("Seconds=%d\n", RaBinProcess->scalesecs);
                  printf ("BinSize=%1.*f\n", ArgusParser->pflag, (RaBinProcess->size * 1.0)/1000000);
                  bins = ((RaBinProcess->scalesecs + (RaBinProcess->size/1000000 - 1))/(RaBinProcess->size / 1000000));
                  printf ("Bins=%d\n", bins);
               }
            }

            for (i = RaBinProcess->index; i < (RaBinProcess->max + 1); i++) {
               if ((bin = RaBinProcess->array[i]) != NULL) {
                  struct ArgusAggregatorStruct *agg = bin->agg;
                  while (agg) {
                     ArgusSortQueue(ArgusSorter, agg->queue);
                     while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(agg->queue, ARGUS_NOLOCK)) != NULL) {
                        RaSendArgusRecord (ns);
                        ArgusDeleteRecordStruct(ArgusParser, ns);
                     }
                     agg = agg->nxt;
                  }

               } else {
                  if (RaBinProcess->nadp.zero && ((i >= RaBinProcess->index) && 
                          ((((i - RaBinProcess->index) * 1.0) * RaBinProcess->size) < (RaBinProcess->scalesecs * 1000000LL)))) {
                     long long tval = RaBinProcess->start + (RaBinProcess->size * (i - RaBinProcess->index));

                     ns = ArgusGenerateRecordStruct(NULL, NULL, NULL);

                     ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.start.tv_sec  = tval / 1000000;
                     ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.start.tv_usec = tval % 1000000;

                     tval += RaBinProcess->size;
                     ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.end.tv_sec    = tval / 1000000;;
                     ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.end.tv_usec   = tval % 1000000;

                     RaSendArgusRecord (ns);
                  }
               }
            }
         }

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


void
ArgusClientTimeout ()
{
   struct ArgusRecordStruct *ns = NULL, *argus = NULL;
   struct RaBinProcessStruct *rbps = RaBinProcess;
   struct RaBinStruct *bin = NULL;
   int i = 0, count, nflag = 0;

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

                     ArgusSortQueue(ArgusSorter, agg->queue);
                     argus = ArgusCopyRecordStruct((struct ArgusRecordStruct *) agg->queue->array[0]);

                     if (nflag == 0)
                        cnt = agg->queue->count;
                     else
                        cnt = nflag > agg->queue->count ? agg->queue->count : nflag;

                     for (i = 1; i < cnt; i++)
                        ArgusMergeRecords (agg, argus, (struct ArgusRecordStruct *)agg->queue->array[i]);

                     ArgusParser->ns = argus;

                     for (i = 0; i < cnt; i++)
                        RaSendArgusRecord ((struct ArgusRecordStruct *) agg->queue->array[i]);

                     ArgusDeleteRecordStruct(ArgusParser, ArgusParser->ns);

                     while((argus = (struct ArgusRecordStruct *)ArgusPopQueue(agg->queue, ARGUS_LOCK)) != NULL)
                        ArgusDeleteRecordStruct(ArgusParser, argus);
                  }

                  agg = agg->nxt;
               }

               RaDeleteBin(ArgusParser, bin);
               rbps->array[rbps->index] = NULL;

            } else {
               if (RaBinProcess->nadp.zero) {
                  long long tval = RaBinProcess->start + (RaBinProcess->size * RaBinProcess->index);

                  ns = ArgusGenerateRecordStruct(NULL, NULL, NULL);

                  ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.start.tv_sec  = tval / 1000000;
                  ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.start.tv_usec = tval % 1000000;

                  tval += RaBinProcess->size;
                  ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.end.tv_sec    = tval / 1000000;;
                  ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.end.tv_usec   = tval % 1000000;

                  RaSendArgusRecord (ns);
/*
                  ArgusDeleteRecordStruct(ArgusParser, ns);
*/
#ifdef ARGUSDEBUG
                  ArgusDebug (2, "ArgusClientTimeout() RaBinProcess: creating zero record\n");
#endif
               }
            }

            for (i = 0; i < count; i++)
               rbps->array[i] = rbps->array[(i + 1)];
    
            rbps->start += rbps->size;
            rbps->end   += rbps->size;

            rbps->array[count] = NULL;
            rbps->startpt.tv_sec  += rbps->size;

            if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
               struct ArgusWfileStruct *wfile = NULL;
               struct ArgusListObjectStruct *lobj = NULL;
               int i, count = ArgusParser->ArgusWfileList->count;

               if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
                  for (i = 0; i < count; i++) {
                     if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                        if (wfile->fd != NULL)
                           fflush(wfile->fd);
                     }
                     lobj = lobj->nxt;
                  }
               }
            }
         }

#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusClientTimeout() RaBinProcess: Bflag %f rtime %lld start %lld end %lld size %lld arraylen %d count %d index %d\n",
            ArgusParser->Bflag, rtime, RaBinProcess->start, RaBinProcess->end,
            RaBinProcess->size, RaBinProcess->arraylen, RaBinProcess->count, RaBinProcess->index);
#endif
         rtime += rbps->size;
         rbps->rtime.tv_sec  = rtime / 1000000;
         rbps->rtime.tv_usec = rtime % 1000000;
      }
   }

   if ((rbps->size > 0) && (rbps->rtime.tv_sec == 0)) {
      long long rtime = (ArgusParser->ArgusRealTime.tv_sec * 1000000LL) / rbps->size;
      rbps->rtime.tv_sec = (rtime + 1) * rbps->size;
   }
}

void parse_arg (int argc, char**argv) {}

void
usage ()
{
   extern char version[];

   fprintf (stderr, "Rabins Version %s\n", version);

   fprintf (stderr, "usage: %s -M splitmode [splitmode options] [raoptions]\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -M <mode>         supported modes of operation:\n");
   fprintf (stderr, "             time n[smhdwmy] split output into time series bins\n");
   fprintf (stderr, "             nomodify        don't modify input records\n");
   fprintf (stderr, "             zero            generate zero records for gaps\n\n");

   fprintf (stderr, "         -m <mode>          supported aggregation objects:\n");
   fprintf (stderr, "             none             no flow key\n");
   fprintf (stderr, "             saddr            include the source address\n");
   fprintf (stderr, "             daddr            include the destination address\n");
   fprintf (stderr, "             proto            include the destination proto\n");
   fprintf (stderr, "             sport            include the source port\n");
   fprintf (stderr, "             dport            include the destination port\n");
   fprintf (stderr, "             srcid            include the source identifier\n\n");

#if defined (ARGUSDEBUG)
   fprintf (stderr, "         -D <level>         specify debug level\n");
#endif
   exit(1);
}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT:
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusTimeObject *time = (void *)ns->dsrs[ARGUS_TIME_INDEX];

         if (time == NULL)
            return;

         ArgusThisTime.tv_sec  = time->src.start.tv_sec;
         ArgusThisTime.tv_usec = time->src.start.tv_usec;

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

         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(ns);
            struct ArgusFlow *flow;

            if ((flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);

            ArgusReverseRecord(tns);

            if ((flow = (struct ArgusFlow *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }
    
            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else {
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;

            if (agg && agg->ArgusMatrixMode) {
               if (agg->mask & ((0x01LL << ARGUS_MASK_SADDR) | (0x01LL << ARGUS_MASK_DADDR))) {
                  struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];

                  if (flow != NULL) {
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
                     }
                  }
               }
            }
            RaProcessThisRecord(parser, ns);
         }
      }
   }
}

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   extern struct RaBinProcessStruct *RaBinProcess;
   struct ArgusRecordStruct *tns = NULL;
   int retn = 0, fretn = -1, lretn = -1;
   extern int ArgusTimeRangeStrategy;
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   int found = 0, offset, tstrat;

   while (agg && !found) {
      if (ArgusParser->tflag) {
         tstrat = ArgusTimeRangeStrategy;
         ArgusTimeRangeStrategy = 1;
      }

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
         offset = (ArgusParser->Bflag * 1000000)/RaBinProcess->nadp.size;
         RaBinProcess->nadp.stperiod = 0.0;
         RaBinProcess->nadp.dtperiod = 0.0;

         while ((tns = ArgusAlignRecord(parser, ns, &RaBinProcess->nadp)) != NULL) {
            if ((retn = ArgusCheckTime (parser, tns)) != 0) {
               struct ArgusMetricStruct *metric = (void *)tns->dsrs[ARGUS_METRIC_INDEX];

               if ((metric != NULL) && ((metric->src.pkts + metric->dst.pkts) > 0)) {
                  if (!(retn = ArgusInsertRecord(parser, RaBinProcess, tns, offset)))
                     ArgusDeleteRecordStruct(parser, tns);
               } else 
                  ArgusDeleteRecordStruct(parser, tns);
            } else
               ArgusDeleteRecordStruct(parser, tns);
         }
         found++;
      }
      agg = agg->nxt;
   }

   if (ArgusParser->tflag)
      ArgusTimeRangeStrategy = tstrat;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessThisRecord (0x%x) done\n", ns); 
#endif
}


int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   int retn = 1;
   char buf[0x10000];

   if (argus->status & ARGUS_RECORD_WRITTEN)
      return (retn);

   if (!(retn = ArgusCheckTime (ArgusParser, argus)))
      return (retn);

   if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = ArgusParser->ArgusWfileList->count;

      if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int retn = 1;
               if (wfile->filterstr) {
                  struct nff_insn *wfcode = wfile->filter.bf_insns;
                  retn = ArgusFilterRecord (wfcode, argus);
               }

               if (retn != 0) {
                  if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;
                     char buf[2048];

                     if ((argusrec = ArgusGenerateRecord (argus, 0L, buf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        ArgusWriteNewLogfile (ArgusParser, argus->input, wfile, argusrec);
                     }
                  }
               }
            }
            lobj = lobj->nxt;
         }
      }

   } else {
      if (!ArgusParser->qflag) {
         if (ArgusParser->Lflag) {
            if (ArgusParser->RaLabel == NULL)
               ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, argus);

            if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag)) {
               if (ArgusParser->Gflag) {
                  printf ("Columns=%s\n", ArgusParser->RaLabel);
               } else
                  printf ("%s", ArgusParser->RaLabel);
            }

            if (ArgusParser->Lflag < 0)
               ArgusParser->Lflag = 0;

            if (ArgusParser->Gflag) {
               switch (ArgusParser->RaPrintMode) {
                  case RA_PRINTSRCID:
                     printf ("Probes=\n");
                     break;

                  case RA_PRINTPROTO: {
                     printf ("Protos=\n");
                     break;
                  }

                  default: {
                     printf ("Objects=\n");
                     break;
                  }
               }
            }
            printf ("\n");
         }

         *(int *)&buf = 0;
         ArgusPrintRecord(ArgusParser, buf, argus, MAXSTRLEN);
         fprintf (stdout, "%s\n", buf);
         fflush(stdout);
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
   int len, i = 1, carry = 0;

   if (filename != NULL) {
      len = strlen(filename);

      for (i = 0; i < nadp->slen; i++)
         if (filename[len - (i + 1)] == 'z')
            carry++;

      if ((carry == (nadp->slen - 1)) && (filename[len - nadp->slen] == 'y')) {
         strncpy(tmpbuf, filename, MAXSTRLEN);
         tmpbuf[strlen(tmpbuf) - nadp->slen] = 'z';
         for (i = 0; i < nadp->slen; i++) {
#if defined(HAVE_STRLCAT)
            strlcat(tmpbuf, "a", MAXSTRLEN - strlen(tmpbuf));
#else
            strcat(tmpbuf, "a");
#endif
         }
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
   int retn = 0, i, x, slen = 0;

   bzero (resultbuf, len);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      slen = strlen(resultbuf);
      snprintf (&resultbuf[slen], MAXSTRLEN - slen, "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            bzero (tmpbuf, MAXSTRLEN);
            RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);

            while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
               tmpbuf[strlen(tmpbuf) - 1] = '\0';

            while (isspace((int)tmpbuf[i])) i++;
            slen = strlen(resultbuf);
            snprintf (&resultbuf[slen], MAXSTRLEN - slen, "%s", &tmpbuf[i]);

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

