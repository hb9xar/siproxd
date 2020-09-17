/*
    Copyright (C) 2016  Thomas Ries <tries@gmx.net>

    This file is part of Siproxd.

    Siproxd is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Siproxd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warrantry of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Siproxd; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
*/

/* must be defined before including <plugin.h> */
#define PLUGIN_NAME	plugin_stats

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "rtpproxy.h"
#include "plugins.h"
#include "log.h"


static char const ident[]="$Id$";

/* Plug-in identification */
static char name[]="plugin_stats";
static char desc[]="Upon receiving SIGUSR1, dump some call statistics";

/* constants */
#define STATS_SYSLOG	0x01
#define STATS_FILE	0x02
#define STATS_ALL	0xff

/* global configuration storage - required for config file location */
extern struct siproxd_config configuration;
/* need access to the proxy table */
/*&&& should not do that. Instead, should get a copy/clone of the proxytable
      (lock mutex, clone, unlock mutex) and work with this copy.
      Avoids a possible race condition if RTP thread starts/stops
      a stream during stats dump.
*/
extern rtp_proxytable_t rtp_proxytable[];
extern struct urlmap_s urlmap[];

/* plugin configuration storage */
static struct plugin_config {
   int  to_syslog;	// 0: off, -1 only upon SIGUSR1, >0, every n seconds
   int  to_file;	// 0: off, -1 only upon SIGUSR1, >0, every n seconds
   char *filename;
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_stats_to_syslog",	TYP_INT4,   &plugin_cfg.to_syslog,		{0, NULL} },
   { "plugin_stats_to_file",	TYP_INT4,   &plugin_cfg.to_file,		{0, NULL} },
   { "plugin_stats_filename",	TYP_STRING, &plugin_cfg.filename,		{0, NULL} },
   {0, 0, 0}
};

/* local storage needed by plugin */
static int dump_stats=0;
static int idx_to_rtp_proxytable[RTPPROXY_SIZE];	// <0: empty, >=0, index into rtp_proxytable
static int stats_num_streams=0;
static int stats_num_calls=0;
static int stats_num_act_clients=0;
static int stats_num_reg_clients=0;


/* local prototypes */
static void stats_sighandler(int sig);
static void stats_prepare(void);
static void stats_to_syslog(void);
static void stats_to_file(void);

/* 
 * Initialization.
 * Called once suring siproxd startup.
 */
int  PLUGIN_INIT(plugin_def_t *plugin_def) {
   struct sigaction act;

  /* API version number of siproxd that this plugin is built against.
    * This constant will change whenever changes to the API are made
    * that require adaptions in the plugin. */
   plugin_def->api_version=SIPROXD_API_VERSION;

   /* Name and descriptive text of the plugin */
   plugin_def->name=name;
   plugin_def->desc=desc;

   /* Execution mask - during what stages of SIP processing shall
    * the plugin be called. */
   plugin_def->exe_mask=PLUGIN_TIMER;

   /* read the config file */
   if (read_config(configuration.configfile,
                   configuration.config_search,
                   plugin_cfg_opts, name) == STS_FAILURE) {
      ERROR("Plugin '%s': could not load config file", name);
      return STS_FAILURE;
   }

   /* check if statistics dump is actually enabled, if not exit */
   if ((plugin_cfg.to_syslog == 0) && (plugin_cfg.to_file == 0)) {
      plugin_def->exe_mask=PLUGIN_NOOP;
      WARN("Plugin_stats loaded but not enabled in config.");
      return STS_SUCCESS;
   }
/*&&& require rtp_proxy_enable==1, otherwise no stats in rtp_proxytable */

   /* setup signal handler - SIGUSR1 */
   act.sa_handler=stats_sighandler;
   sigemptyset(&act.sa_mask);
   act.sa_flags=SA_RESTART;
   if (sigaction(SIGUSR1, &act, NULL)) {
      ERROR("Failed to install SIGUSR1 handler");
   }

   INFO("plugin_stats is initialized and armed");
   return STS_SUCCESS;
}

/*
 * Processing.
 * 
 */
int  PLUGIN_PROCESS(int stage, sip_ticket_t *ticket){
   static time_t last_run=0;
   time_t now=0;
   /* stage contains the PLUGIN_* value - the stage of SIP processing. */
//   INFO("plugin_stats: processing - stage %i",stage);

   time(&now);
   if (last_run==0) { last_run=now; }

   if ((plugin_cfg.to_syslog > 0) &&
       (now - last_run > plugin_cfg.to_syslog)) { dump_stats |= STATS_SYSLOG; }
   if ((plugin_cfg.to_file > 0) &&
       (now - last_run > plugin_cfg.to_file)) { dump_stats |= STATS_FILE; }

   if (dump_stats) {
      DEBUGC(DBCLASS_PLUGIN, "plugin_stats: triggered, dump_stats=0x%x", dump_stats);
      stats_prepare();
      if (dump_stats & STATS_SYSLOG) { stats_to_syslog(); }
      if (dump_stats & STATS_FILE)   { stats_to_file(); }
      dump_stats=0;
      last_run=now;
   }


   return STS_SUCCESS;
}

/*
 * De-Initialization.
 * Called during shutdown of siproxd. Gives the plugin the chance
 * to clean up its mess (e.g. dynamic memory allocation, database
 * connections, whatever the plugin messes around with)
 */
int  PLUGIN_END(plugin_def_t *plugin_def){
   INFO("plugin_stats ends here");
   return STS_SUCCESS;
}


/*
 * module-local functions
 */

/*
 * Signal handler
 *
 * this one is called asynchronously whevener a registered
 * signal is applied. Just set a flag and don't do any funny
 * things here.
 */
static void stats_sighandler(int sig) {
   /* set flag to dump statistics at next Tick */
   if (sig==SIGUSR1) dump_stats=STATS_ALL;
   return;
}

/*
 * qsort compare function
 */
static int stats_compare(const void *p1, const void *p2) {
   int i1;
   int i2;
   int sts;

   // safety: don't do anythigng if bad data given.
   if ((p1 == NULL) || (p2 == NULL)) return 0;

   i1=*(int*)p1;
   i2=*(int*)p2;
DEBUGC(DBCLASS_PLUGIN,"sort: i1=%i, i=%i", i1, i2);

   // sort by (1)client-id, (2)call-id, (3)stream number

   // check client-id
   sts = strncmp(rtp_proxytable[i1].client_id.idstring, 
                 rtp_proxytable[i2].client_id.idstring, 
                 CLIENT_ID_SIZE);
DEBUGC(DBCLASS_PLUGIN,"sort: strncmp client_id=%i", sts);
   if (sts != 0) return sts;

   // check call-id host
   sts = strncmp(rtp_proxytable[i1].callid_host, 
                 rtp_proxytable[i2].callid_host, 
                 CALLIDHOST_SIZE);
DEBUGC(DBCLASS_PLUGIN,"sort: strncmp callid_host=%i", sts);
   if (sts != 0) return sts;

   // check call-id number
   sts = strncmp(rtp_proxytable[i1].callid_number, 
                 rtp_proxytable[i2].callid_number, 
                 CALLIDNUM_SIZE);
DEBUGC(DBCLASS_PLUGIN,"sort: strncmp callid_number=%i", sts);
   if (sts != 0) return sts;

   // check media stream number
   sts=0;
   if (rtp_proxytable[i1].media_stream_no < rtp_proxytable[i2].media_stream_no) {
      sts=-1;
   } else if (rtp_proxytable[i1].media_stream_no > rtp_proxytable[i2].media_stream_no) {
      sts=1;
   }

DEBUGC(DBCLASS_PLUGIN,"sort: cmp media_stream_no=%i", sts);
   return sts;
}

/*
 * prepare and sort statistics data
 */
static void stats_prepare(void) {
   int i;
   int j=0;
   int sts;

#define TESTING 0
#if TESTING
   {
   int k=RTPPROXY_SIZE/2;
   rtp_proxytable[k].rtp_rx_sock=555;
   strcpy(rtp_proxytable[k].client_id.idstring, "Client-Id");
   strcpy(rtp_proxytable[k].callid_number, "CallID-Number2");
   strcpy(rtp_proxytable[k].callid_host, "CallID-Host");
   rtp_proxytable[k].direction=DIR_INCOMING;
   rtp_proxytable[k].call_direction=DIR_INCOMING;
   rtp_proxytable[k].media_stream_no=1;
   rtp_proxytable[k].timestamp=1472844291;
   k++;
   rtp_proxytable[k].rtp_rx_sock=555;
   strcpy(rtp_proxytable[k].client_id.idstring, "Client-Id");
   strcpy(rtp_proxytable[k].callid_number, "CallID-Number2");
   strcpy(rtp_proxytable[k].callid_host, "CallID-Host");
   rtp_proxytable[k].direction=DIR_OUTGOING;
   rtp_proxytable[k].call_direction=DIR_INCOMING;
   rtp_proxytable[k].media_stream_no=2;
   rtp_proxytable[k].timestamp=1472844291;

   k++;
   rtp_proxytable[k].rtp_rx_sock=555;
   strcpy(rtp_proxytable[k].client_id.idstring, "Client-Id");
   strcpy(rtp_proxytable[k].callid_number, "CallID-Number1");
   strcpy(rtp_proxytable[k].callid_host, "CallID-Host2");
   rtp_proxytable[k].direction=DIR_INCOMING;
   rtp_proxytable[k].call_direction=DIR_INCOMING;
   rtp_proxytable[k].media_stream_no=1;
   rtp_proxytable[k].timestamp=1472844291;
   k++;
   rtp_proxytable[k].rtp_rx_sock=555;
   strcpy(rtp_proxytable[k].client_id.idstring, "Client-Id");
   strcpy(rtp_proxytable[k].callid_number, "CallID-Number1");
   strcpy(rtp_proxytable[k].callid_host, "CallID-Host2");
   rtp_proxytable[k].direction=DIR_OUTGOING;
   rtp_proxytable[k].call_direction=DIR_INCOMING;
   rtp_proxytable[k].media_stream_no=2;
   rtp_proxytable[k].timestamp=1472844291;

   k++;
   rtp_proxytable[k].rtp_rx_sock=555;
   strcpy(rtp_proxytable[k].client_id.idstring, "Client-02");
   strcpy(rtp_proxytable[k].callid_number, "CallID-Number");
   strcpy(rtp_proxytable[k].callid_host, "CallID-Host");
   rtp_proxytable[k].direction=DIR_INCOMING;
   rtp_proxytable[k].call_direction=DIR_INCOMING;
   rtp_proxytable[k].media_stream_no=1;
   rtp_proxytable[k].timestamp=1472848291;
   k++;
   rtp_proxytable[k].rtp_rx_sock=555;
   strcpy(rtp_proxytable[k].client_id.idstring, "Client-02");
   strcpy(rtp_proxytable[k].callid_number, "CallID-Number");
   strcpy(rtp_proxytable[k].callid_host, "CallID-Host");
   rtp_proxytable[k].direction=DIR_OUTGOING;
   rtp_proxytable[k].call_direction=DIR_INCOMING;
   rtp_proxytable[k].media_stream_no=2;
   rtp_proxytable[k].timestamp=1472848291;

   k++;
   rtp_proxytable[k].rtp_rx_sock=555;
   strcpy(rtp_proxytable[k].client_id.idstring, "ABC-02");
   strcpy(rtp_proxytable[k].callid_number, "XXX02-Number");
   strcpy(rtp_proxytable[k].callid_host, "CallID-Host");
   rtp_proxytable[k].direction=DIR_INCOMING;
   rtp_proxytable[k].call_direction=DIR_OUTGOING;
   rtp_proxytable[k].media_stream_no=1;
   rtp_proxytable[k].timestamp=1472848291;
   k++;
   rtp_proxytable[k].rtp_rx_sock=555;
   strcpy(rtp_proxytable[k].client_id.idstring, "ABC-02");
   strcpy(rtp_proxytable[k].callid_number, "XXX02-Number");
   strcpy(rtp_proxytable[k].callid_host, "CallID-Host");
   rtp_proxytable[k].direction=DIR_OUTGOING;
   rtp_proxytable[k].call_direction=DIR_OUTGOING;
   rtp_proxytable[k].media_stream_no=2;
   rtp_proxytable[k].timestamp=1472848291;
   }
#endif

   // loop through rtp_proxytable and populate idx_to_rtp_proxytable
   for (i=0; i < RTPPROXY_SIZE; i++) {
      if (rtp_proxytable[i].rtp_rx_sock) {
         DEBUGC(DBCLASS_PLUGIN,"populate: rtpproxytable[%i] -> idx[%i]", i, j);
         idx_to_rtp_proxytable[j++] = i;
      }
   }

   // put the EOT mark
   idx_to_rtp_proxytable[j]=-1;

   // run Q-Sort
   qsort(idx_to_rtp_proxytable, j, sizeof(idx_to_rtp_proxytable[0]), stats_compare);

   // run through sorted table and calculate counters
   stats_num_streams=0;
   stats_num_calls=0;
   stats_num_act_clients=0;
   stats_num_reg_clients=0;

   for (i=0; i < j; i++) {
      DEBUGC(DBCLASS_PLUGIN,"calculate: idx[%i] -> rtpproxytable[%i]", i, idx_to_rtp_proxytable[i]);
      // each entry -> +1 stream
      stats_num_streams++;

      if (i>0) {
         if (i == 1) { stats_num_calls++; stats_num_act_clients++;}
         // change of call-id? -> +1 call
         // check call-id host
         sts = strncmp(rtp_proxytable[idx_to_rtp_proxytable[i]].callid_host, 
                       rtp_proxytable[idx_to_rtp_proxytable[i-1]].callid_host, 
                       CALLIDHOST_SIZE);
         DEBUGC(DBCLASS_PLUGIN,"calc: strncmp callid_host=%i", sts);
         if (sts != 0) {
            stats_num_calls++;
         } else {
            // check call-id number
            sts = strncmp(rtp_proxytable[idx_to_rtp_proxytable[i]].callid_number, 
                          rtp_proxytable[idx_to_rtp_proxytable[i-1]].callid_number, 
                          CALLIDNUM_SIZE);
            DEBUGC(DBCLASS_PLUGIN,"calc: strncmp callid_number=%i", sts);
            if (sts != 0) {
               stats_num_calls++;
            }
         }
         //&&& use client_id.idstring only, otherwise wrong counting...
         // change of client-id -> +1 client
         sts = strncmp(rtp_proxytable[idx_to_rtp_proxytable[i]].client_id.idstring, 
                       rtp_proxytable[idx_to_rtp_proxytable[i-1]].client_id.idstring, 
                       CLIENT_ID_SIZE);
         DEBUGC(DBCLASS_PLUGIN,"calc: strncmp client_id=%i", sts);
         if (sts != 0) {
            stats_num_act_clients++;
         }
      }
   }
   
   for (i=0; i < URLMAP_SIZE; i++) {
      if ((urlmap[i].active == 1) && (urlmap[j].expires >= time(NULL))) {
         stats_num_reg_clients++;
      }
   }

}

static void stats_to_syslog(void) {
   INFO("STATS: %i active Streams, %i active Calls, %i active Clients, %i registered Clients", 
        stats_num_streams, stats_num_calls, stats_num_act_clients, stats_num_reg_clients);
}

static void stats_to_file(void) {
   int i;
   int ii;
   FILE *stream;
   char remip[IPSTRING_SIZE];
   char lclip[IPSTRING_SIZE];
   time_t now;

   if (plugin_cfg.filename) {
      DEBUGC(DBCLASS_PLUGIN,"opening stats file for write");
      /* write urlmap back to file */
      stream = fopen(plugin_cfg.filename, "w+");
      if (!stream) {
         /* try to unlink it and open again */
         unlink(plugin_cfg.filename);
         stream = fopen(plugin_cfg.filename, "w+");

         /* open file for write failed, complain */
         if (!stream) {
            ERROR("unable to write statistics file, disabling statistics");
            plugin_cfg.to_file = 0;
            return;
         }
      }

      // write header
      time(&now);
      fprintf(stream, "Date: %s", asctime(localtime(&now)));
      fprintf(stream, "PID:  %i\n", getpid());

      fprintf(stream, "\nSummary\n-------\n");
      fprintf(stream, "registered Clients: %6i\n", stats_num_reg_clients);
      fprintf(stream, "active Clients:     %6i\n", stats_num_act_clients);
      fprintf(stream, "active Calls:       %6i\n", stats_num_calls);
      fprintf(stream, "active Streams:     %6i\n", stats_num_streams);

#if 0
//&&& future feature:
      fprintf(stream, "\nRegistered Clients\n------------------\n");
// loop through urlmap and write out stuff. needs sorting, too :-/
#endif


      fprintf(stream, "\nRTP-Details\n-----------\n");
      fprintf(stream, "Header; Client-Id; Call-Id; Call Direction; Stream Direction; local IP; remote IP\n");

      for (i=0; i < RTPPROXY_SIZE; i++) {
         ii=idx_to_rtp_proxytable[i];
         if (ii < 0) break;

           fprintf(stream, "Data;%s;", rtp_proxytable[ii].client_id.idstring);
           fprintf(stream, "%s@%s;", rtp_proxytable[ii].callid_number, rtp_proxytable[ii].callid_host);
           fprintf(stream, "%s;", (rtp_proxytable[ii].call_direction==DIR_INCOMING)? "Incoming":"Outgoing");
           fprintf(stream, "%s;", (rtp_proxytable[ii].direction==DIR_INCOMING)? "Incoming":"Outgoing");
           strncpy(lclip, utils_inet_ntoa(rtp_proxytable[ii].local_ipaddr), sizeof(lclip));
           lclip[sizeof(lclip)-1]='\0';
           fprintf(stream, "%s;", lclip);
           strncpy(remip, utils_inet_ntoa(rtp_proxytable[ii].remote_ipaddr), sizeof(lclip));
           remip[sizeof(remip)-1]='\0';
           fprintf(stream, "%s", remip);
           fprintf(stream, "\n");

//  - # of RTP streams
//  - last activity time


      }
      fclose(stream);
      DEBUGC(DBCLASS_PLUGIN,"closed stats file");
   } else {
      ERROR("no statistics file name given, disabling statistics");
      plugin_cfg.to_file = 0;
   }
   return;
}
