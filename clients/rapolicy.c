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
 * 
 * $Id: //depot/argus/clients/clients/rapolicy.c#14 $
 * $DateTime: 2009/05/15 12:40:06 $
 * $Change: 1732 $
 */

/*
 * rapolicy.c  - match input argus records against
 *    a Cisco access control policy.
 *       
 * written by Carter Bullard
 * QoSient, LLC
 *       
 */


#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>

#include <compat.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <rapolicy.h>

struct RaPolicyPolicyStruct *policy = NULL;
struct RaPolicyPolicyStruct *RaGlobalPolicy = NULL;


int RaReadPolicy (struct ArgusParserStruct *, struct RaPolicyPolicyStruct **);
struct RaPolicyPolicyStruct *RaParsePolicy (struct ArgusParserStruct *, char *buf);
int RaCheckPolicy (struct ArgusRecordStruct *, struct RaPolicyPolicyStruct *);
int RaMeetsPolicyCriteria (struct ArgusRecordStruct *, struct RaPolicyPolicyStruct *);
int RaDoNotification (struct ArgusRecordStruct *, struct RaPolicyPolicyStruct *);


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   parser->RaWriteOut = 1;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      parser->RaInitialized++;
      parser->RaWriteOut = 0;
      if (parser->ArgusFlowModelFile != NULL)
         RaReadPolicy (parser, &policy);
   }
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
}


void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

   fprintf (stderr, "Rapolicy Version %s\n", version);
   fprintf (stderr, "usage: %s -f policy [ra-options]\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -f policy file.\n");
   exit(1);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   int process= 0;

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (flow) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {  
                  switch (flow->hdr.argus_dsrvl8.qual) {
                     case ARGUS_TYPE_IPV4:
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_TCP:
                           case IPPROTO_UDP: {
                              process++;
                              break;
                           }
                        }
                        break;
    
                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_TCP:
                           case IPPROTO_UDP: {
                              process++;
                              break;
                           }
                        }
                        break;
                     }
                  } 
                  break;  
               }
            }
    
            if (process)
               if (RaCheckPolicy (argus, policy))
                  RaSendArgusRecord (argus);
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessRecord () returning\n"); 
#endif
}

int
RaSendArgusRecord(struct ArgusRecordStruct *ns)
{
   char buf[0x10000];
   int retn = 1;

   if (ns->status & ARGUS_RECORD_WRITTEN)
      return (retn);
 
   if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = ArgusParser->ArgusWfileList->count;

      if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int pass = 1;
               if (wfile->filterstr) {
                     struct nff_insn *wfcode = wfile->filter.bf_insns;
                     pass = ArgusFilterRecord (wfcode, ns);
               }

               if (pass != 0) {
                  if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;
                     char buf[2048];
                     if ((argusrec = ArgusGenerateRecord (ns, 0L, buf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        ArgusWriteNewLogfile (ArgusParser, ns->input, wfile, argusrec);
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
               ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, ns);
 
            if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag))
               printf ("%s\n", ArgusParser->RaLabel);
 
            if (ArgusParser->Lflag < 0)
               ArgusParser->Lflag = 0;
         }

         *(int *)&buf = 0;
         ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);
         fprintf (stdout, "%s\n", buf);
         fflush(stdout);
      }
   }

   ns->status |= ARGUS_RECORD_WRITTEN;
   return (retn);
}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

int RaInitialState = 0;
int RaParseError = 0;

char *RaParseErrorStr [POLICYERRORNUM] = {
   "access-list identifier not found",
   "policy id number not found",
   "permit/deny indication not found",
   "protocol indentifier not found",
   "no source address defined",
   "no source address mask defined",
   "wrong source port operator",
   "wrong source port specification"
   "no destination address defined",
   "no destination address mask defined",
   "wrong destination port operator",
   "wrong destination port specification",
   "access violation notification not found",
};


int
RaReadPolicy (struct ArgusParserStruct *parser, struct RaPolicyPolicyStruct **policy)
{
   int retn = 1, linenum = 0;
   struct RaPolicyPolicyStruct *pol, *policyLast = NULL;
   char *file = parser->ArgusFlowModelFile;
   char buffer [1024];
   FILE *fd;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         while (fgets (buffer, 1024, fd)) {
            linenum++;
            if ((*buffer != '#') && (*buffer != '\n') && (*buffer != '!')) {
               if ((pol = RaParsePolicy (parser, buffer)) != NULL) {
                  if (policyLast)  {
                     policyLast->nxt = pol;
                     pol->prv = policyLast;
                     policyLast = pol;
                  } else
                     *policy = policyLast = pol;
               } else
                  ArgusLog (LOG_ERR, "RaReadPolicy: line %d: %s\n", linenum, RaParseErrorStr [RaParseError]);
            }
         }
         fclose (fd);

      } else {
         retn = 0;
         ArgusLog (LOG_ERR, "RaReadPolicy: fopen %s %s\n", file,  strerror(errno));
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (2, "RaReadPolicy (0x%x, %s) returning %d\n", policy, file, retn);
#endif

   return (retn);
}

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>

struct RaPolicyPolicyStruct *
RaParsePolicy (struct ArgusParserStruct *parser, char *buf)
{
   struct RaPolicyPolicyStruct *retn = NULL, tpolicy;
   int error = -1, state = RaInitialState;
   char *ptr, *str = strdup(buf);
   char *word = NULL;

   bzero ((char *)&tpolicy, sizeof(tpolicy));
   tpolicy.type = -1;

   ptr = str;

   if (RaGlobalPolicy == NULL) {
      if ((word = strtok(ptr, " \t\n")) == NULL)
         return(retn);

      if (!(strncasecmp (word, "remark", 6)))
         return(retn);

      if (!(strncasecmp (word, "no", 2)))
         return(retn);

      free(str);
      str = strdup(buf);
      ptr = str;
   }

   while (((word = strtok(ptr, " \t\n")) != NULL) && (error == -1)) {
      if (!(strncasecmp (word, "remark", 6))) {
         state = POLICYREMARK;
         break;
      }

      switch (state) {
         case POLICYSTRING:
            if (strstr (str, "source-route")) {
               tpolicy.type = RA_SRCROUTED;
               state = POLICYCOMPLETE;
               break;
            }
            if (!(strncmp (word, POLICY_STRING, sizeof(POLICY_STRING)))) {
               tpolicy.type = RA_ACCESSLIST;
               state = POLICYID;
            } else
               error = POLICYERR_NOACL;
            break;

         case POLICYID:
            if (!(strncmp (word, "extended", 8)))
               break;

            tpolicy.policyID = word;
            state = POLICYACTION;
            break;

         case POLICYACTION: 
            if (!(strcmp (word, "permit")))
               tpolicy.flags |= RA_PERMIT;
            else if (!(strcmp (word, "deny")))
               tpolicy.flags |= RA_DENY;
            else
               error = POLICYERR_NOACTION;

            tpolicy.type = RA_ACCESSLIST;
            state = POLICYPROTO;
            break;
   
         case POLICYPROTO: 
            if (!(strcmp(word, "any"))) {
               tpolicy.proto  = 0;
               tpolicy.flags |= RA_PROTO_SET;
            } else
            if (isdigit((int)*word)) {
               tpolicy.proto = atoi(word);
               tpolicy.flags |= RA_PROTO_SET;
            } else {
               struct protoent *proto;
               if ((proto = getprotobyname(word)) != NULL) {
                  tpolicy.proto = proto->p_proto;
                  tpolicy.flags |= RA_PROTO_SET;

               } else 
                  error=POLICYERR_NOPROTO;
            }
            state = POLICYSRC;
            break;

         case POLICYSRC: {
            if (!(strcmp(word, "any"))) {
               tpolicy.src.addr = ntohl(inet_addr("0.0.0.0"));
               tpolicy.src.mask = ntohl(inet_addr("255.255.255.255"));
               state = POLICYSRCPORT;
               break;
            }

            if (!(strcmp(word, "host"))) {
               if ((word = strtok(NULL, " \t\n")) != NULL) {
                  tpolicy.src.addr = ntohl(inet_addr(word));
                  tpolicy.src.mask = ntohl(inet_addr("0.0.0.0"));
                  state = POLICYSRCPORT;
               } else {
                  error=POLICYERR_NOSRCADR;
                  break;
               }

            } else {
               tpolicy.src.addr = ntohl(inet_addr(word));
               if ((word = strtok(NULL, " \t\n")) != NULL) {
                  tpolicy.src.mask = ntohl(inet_addr(word));
                  state = POLICYSRCPORT;
               } else {
                  error=POLICYERR_NOSRCADR;
                  break;
               }
            }

            break;
         }

#if !defined(INADDR_NONE)
#define INADDR_NONE	((unsigned long) -1)
#endif
         case POLICYSRCPORT: {
            if ((!(strcmp(word, "any"))) || !(strcmp(word, "host")) || (inet_addr(word) != INADDR_NONE)) {
               state = POLICYDST;
            } else {
               /* now get next words, check for port name/number */
               if (!(strncmp(word, "eq", 2)))
                  tpolicy.src_action = RA_EQ;
               else if (!(strncmp (word, "lt", 2)))
                  tpolicy.src_action = RA_LT;
               else if (!(strncmp (word, "gt", 2)))
                  tpolicy.src_action = RA_GT;
               else if (!(strncmp (word, "neq", 3)))
                  tpolicy.src_action = RA_NEQ;
               else if (!(strncmp (word, "est", 3)))
                  tpolicy.src_action = RA_EST;
               else if (!(strncmp (word, "range", 5)))
                  tpolicy.src_action = RA_RANGE;
    
               if (tpolicy.src_action == 0)
                  tpolicy.src_action = RA_EQ;
               else
                  word = strtok(NULL, " \t\n");
    
               if (isdigit((int)*word)) {
                  if (!(tpolicy.src_port_low = (arg_uint16) atoi (word)))
                     error = POLICYERR_DPORT;
               } else {
                  int port, proto;

                  switch (proto = (int)tpolicy.proto) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP:
                        if (!(argus_nametoport(word, &port, &proto)))
                           error = POLICYERR_DPORT;
                        else
                           tpolicy.src_port_low = port;
                        break;

                     case IPPROTO_ICMP:
                        break;
                  }
               }

               if (tpolicy.src_action == RA_RANGE) {
                  word = strtok(NULL, " \t\n");
                  if (word == NULL) {
                     error = POLICYERR_DPORT;
                     break;
                  }
    
                  if (isdigit((int)*word)) {
                     if (!(tpolicy.src_port_hi = (arg_uint16) atoi (word)))
                        error = POLICYERR_DPORT;
                  } else {
                     int port, proto = (int)tpolicy.proto;
                     if (!(argus_nametoport(word, &port, &proto)))
                        error = POLICYERR_DPORT;
                     else
                        tpolicy.src_port_hi = port;
                  }
               }
               state = POLICYDST;
               break;
            }
         }

         case POLICYDST: {
            if (!(strcmp(word, "any"))) {
               tpolicy.dst.addr = ntohl(inet_addr("0.0.0.0"));
               tpolicy.dst.mask = ntohl(inet_addr("255.255.255.255"));
               state = POLICYDSTPORT;
               break;
            }

            if (!(strcmp(word, "host"))) {
               if ((word = strtok(NULL, " \t\n")) != NULL) {
                  tpolicy.dst.addr = ntohl(inet_addr(word));
                  tpolicy.dst.mask = ntohl(inet_addr("0.0.0.0"));
                  state = POLICYDSTPORT;
               } else {
                  error=POLICYERR_NODSTADR;
                  break;
               }

            } else {
               tpolicy.dst.addr = ntohl(inet_addr(word));
               if ((word = strtok(NULL, " \t\n")) != NULL) {
                  tpolicy.dst.mask = ntohl(inet_addr(word));
                  state = POLICYDSTPORT;
               } else {
                  error=POLICYERR_NODSTADR;
                  break;
               }
            }
            break;
         }

         case POLICYDSTPORT: {
            /* now get next words, check for port name/number */
            if (!(strncmp(word, "eq", 2)))
               tpolicy.dst_action = RA_EQ;
            else if (!(strncmp (word, "lt", 2)))
               tpolicy.dst_action = RA_LT;
            else if (!(strncmp (word, "gt", 2)))
               tpolicy.dst_action = RA_GT;
            else if (!(strncmp (word, "neq", 3)))
               tpolicy.dst_action = RA_NEQ;
            else if (!(strncmp (word, "range", 5)))
               tpolicy.dst_action = RA_RANGE;
            else if (!(strncmp (word, "est", 3))) {
               tpolicy.dst_action = RA_EST;
            }
 
            if (tpolicy.dst_action == 0)
               tpolicy.dst_action = RA_EQ;
            else {
               if ((word = strtok(NULL, " \t\n")) != NULL) {
                  if (isdigit((int)*word)) {
                     if (!(tpolicy.dst_port_low = (arg_uint16) atoi (word)))
                        error = POLICYERR_DPORT;
                  } else {
                     int port, proto;

                     switch (proto = (int)tpolicy.proto) {
                        case IPPROTO_TCP:
                        case IPPROTO_UDP:
                           if (!(argus_nametoport(word, &port, &proto)))
                              error = POLICYERR_DPORT;
                           else
                              tpolicy.dst_port_low = port;
                           break;

                        case IPPROTO_ICMP:
                           if (isdigit((int)*word)) {
                                 tpolicy.dst_port_low = atoi(word);
                           } else {
                              if (!(strncmp(word, "host-unreachable", 15)))
                                 tpolicy.dst_port_low = ICMP_UNREACH_HOST;
                              else if (!(strncmp(word, "echo-reply", 10)))
                                 tpolicy.dst_port_low = ICMP_ECHOREPLY;
                              else if (!(strncmp(word, "unreachable", 11)))
                                 tpolicy.dst_port_low = ICMP_UNREACH;
                              else if (!(strncmp(word, "echo", 4)))
                                 tpolicy.dst_port_low = ICMP_ECHO;
                              else if (!(strncmp(word, "time-exceeded", 13)))
                                 tpolicy.dst_port_low = ICMP_TIMXCEED;
                           }
                           break;
                     }
                  }

                  if (tpolicy.dst_action == RA_RANGE) {
                     word = strtok(NULL, " \t\n");
                     if (word == NULL) {
                        error = POLICYERR_DPORT;
                        break;
                     }
       
                     if (isdigit((int)*word)) {
                        if (!(tpolicy.dst_port_hi = (arg_uint16) atoi (word)))
                           error = POLICYERR_DPORT;
                     } else {
                        int port, proto = (int)tpolicy.proto;
                        if (!(argus_nametoport(word, &port, &proto)))
                           error = POLICYERR_DPORT;
                        else
                           tpolicy.dst_port_hi = port;
                     }
                  }
                  state = POLICYNOTIFICATION;
                  break;
               }
            }
         }
   
         case POLICYNOTIFICATION: 
            state = POLICYCOMPLETE;
            break;
      }

      if ((state == POLICYSTRING) && (error == POLICYERR_NOACL)) {
         if ((!(strcmp (word, "permit"))) || (!(strcmp (word, "deny"))))
            state = POLICYACTION;
         else {
            tpolicy.type   = RA_ACCESSLIST;
            tpolicy.flags |= RA_PERMIT;
            state = POLICYPROTO;
         }
         error = -1;
         free(str);
         str = strdup(buf);
         ptr = str;
      } else
         ptr = NULL;
   }

   if (error != -1) {
      RaParseError = error;
   } else {
      if (state != POLICYREMARK) {
         if ((retn = (struct RaPolicyPolicyStruct *) ArgusCalloc (1, sizeof (*retn))) != NULL) {
            bcopy ((char *)&tpolicy, (char *)retn, sizeof(*retn));
            retn->str = strdup(buf);

            switch (state) {
               case POLICYSTRING:
               case POLICYID:
               case POLICYACTION:
                  RaGlobalPolicy = retn;
                  RaInitialState = POLICYACTION;
                  retn = NULL;
                  break;

               case POLICYPROTO:
               case POLICYSRC:
               case POLICYSRCPORT:
               case POLICYDST:
               case POLICYDSTPORT:
               case POLICYNOTIFICATION:
               case POLICYCOMPLETE:
                  break;
            }
         }
      }
   }

   free (str);
   return (retn);
}


int
RaCheckPolicy (struct ArgusRecordStruct *argus, struct RaPolicyPolicyStruct *policy)
{
   int retn = 0, policymatch = 0;

   if (policy) {
      while (policy) {
         if ((retn = RaMeetsPolicyCriteria (argus, policy))) {
            retn = RaDoNotification (argus, policy);
            policymatch = 1;
            break;
         }
         policy = policy->nxt;
      }
   }
   return (retn);
}


int
RaMeetsPolicyCriteria (struct ArgusRecordStruct *argus, struct RaPolicyPolicyStruct *policy)
{
   int retn = 0, i = 0;
   struct ArgusFlow *flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX];

   if (flow != NULL) {
      u_char proto = flow->ip_flow.ip_p;

      arg_uint32 saddr = 0, daddr = 0;
      arg_uint16 sport = 0, dport = 0;
      
      switch (policy->type) {
      case RA_SRCROUTED: {
         struct ArgusIPAttrStruct *attr = (void *)argus->dsrs[ARGUS_IPATTR_INDEX];
         if (attr != NULL) {
            if ((attr->src.options & (ARGUS_SSRCROUTE | ARGUS_LSRCROUTE)) || 
                (attr->dst.options & (ARGUS_SSRCROUTE | ARGUS_LSRCROUTE)))
               retn++;
         }
         break;
      }

      case RA_ACCESSLIST:
         saddr = flow->ip_flow.ip_src;
         daddr = flow->ip_flow.ip_dst;
         sport = flow->ip_flow.sport;
         dport = flow->ip_flow.dport;
      
         for (i = 0, retn = 1; ((i < POLICYTESTCRITERIA) && retn); i++) {
            retn = 0;
            switch (i) {
               case POLICYTESTPROTO:
                  if (policy->flags & (RA_PROTO_SET)) {
                     if (policy->proto) {
                        if (policy->proto == proto)
                           retn++;
                     } else
                        retn++;
                  }
                  break;
      
               case POLICYTESTSRC:
                  if ((saddr & ~policy->src.mask) == policy->src.addr) {
                     retn++;
                     }
                  break;
               case POLICYTESTDST:
                  if ((daddr & ~policy->dst.mask) == policy->dst.addr) {
                     retn++;
                     }
                  break;
               case POLICYTESTSRCPORT:
                  switch (policy->src_action) {
                     case  RA_EQ:
                        if (sport == policy->src_port_low) {
                           retn++;
                        } else {
                        }
                        continue;
                     case  RA_LT:
                        if (sport < policy->src_port_low) {
                           retn++;
                           }
                           continue;
                     case  RA_GT:
                        if (sport > policy->src_port_low) {
                           retn++;
                           }
                           continue;
                     case RA_NEQ:
                        if (sport != policy->src_port_low) {
                           retn++;
                           }
                           continue;
                     case RA_RANGE:
                        if ((sport < policy->src_port_low) ||
                            (sport > policy->src_port_hi)) {
                           retn++;
                           }
                           continue;

                     case  RA_EST: {
                        int status = 0;
                        struct ArgusNetworkStruct *net = (void *)argus->dsrs[ARGUS_NETWORK_INDEX];

                        if (net != NULL) {
                           switch (net->hdr.subtype) {
                              case ARGUS_TCP_STATUS: {
                                 struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;
                                 status = tcp->status;
                                 break;
                              }
                              case ARGUS_TCP_PERF: {
                                 struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                                 status = tcp->status;
                                 break;
                              }
                           }
                           if ((status & ARGUS_SAW_SYN_SENT))
                              retn++;
                        }
                        continue;
                     }
                  }

               case POLICYTESTDSTPORT:
                  switch (policy->dst_action) {
                     case  RA_EQ:
                        if (dport == policy->dst_port_low) {
                           retn++;
                        } else {
                        }
                        continue;
                     case  RA_LT:
                        if (dport < policy->dst_port_low) {
                           retn++;
                           }
                           continue;
                     case  RA_GT:
                        if (dport > policy->dst_port_low) {
                           retn++;
                           }
                           continue;
                     case RA_NEQ:
                        if (dport != policy->dst_port_low) {
                           retn++;
                           }
                           continue;
                     case RA_RANGE:
                        if ((dport >= policy->dst_port_low) || (dport <= policy->dst_port_hi))
                           retn++;
                        continue;
                     case  RA_EST: {
                        int status = 0;
                        struct ArgusNetworkStruct *net = (void *)argus->dsrs[ARGUS_NETWORK_INDEX];

                        if (net != NULL) {
                           switch (net->hdr.subtype) {
                              case ARGUS_TCP_STATUS: {
                                 struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;
                                 status = tcp->status;
                                 break;
                              }
                              case ARGUS_TCP_PERF: {
                                 struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                                 status = tcp->status;
                                 break;
                              }
                           }
                           if ((status & ARGUS_SAW_SYN_SENT))
                              retn++;
                        }
                        continue;
                     }

                     default: retn++; break;
              }
            }
         }
      }
   }

   return (retn);
}

int
RaDoNotification (struct ArgusRecordStruct *argus, struct RaPolicyPolicyStruct *policy)
{
   int retn = 1;

   if (policy) {
      if (policy->flags & RA_PERMIT) {
         if (ArgusParser->dflag > 1) {
            printf ("%s %s ", "policy: permitted", policy->str);
         } else
            retn = 0;

      } else {
         if (ArgusParser->dflag)
            printf ("%s %s ", "policy: denyed", policy->str);
      }
   }

   return (retn);
}


