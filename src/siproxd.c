/*
    Copyright (C) 2002  Thomas Ries <tries@gmx.net>

    This file is part of Siproxd.
    
    Siproxd is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    
    Siproxd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with Siproxd; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
*/

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <getopt.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


/* configuration storage */
struct siproxd_config configuration;

/* socket used for sending SIP datagrams */
int sip_socket=0;

/* -h help option text */
static const char str_helpmsg[] =
PACKAGE"-"VERSION"-"BUILDSTR" (c) 2002-2003 Thomas Ries\n" \
"\nUsage: siproxd [options]\n\n" \
"options:\n" \
"       --help              (-h) help\n" \
"       --debug <pattern>   (-d) set debug-pattern\n" \
"       --config <cfgfile>  (-c) use the specified config file\n"\
"";



/*
 * module local data
 */
static  int dmalloc_dump=0;
static  int exit_program=0;

/*
 * local prototypes
 */
static void sighandler(int sig);


int main (int argc, char *argv[]) 
{
   int sts;
   int i;
   int access;
   struct sockaddr_in from;
   char buff [BUFFER_SIZE];
   osip_message_t *my_msg=NULL;

   extern char *optarg;
   int ch1;
   
   char configfile[64]="siproxd";	/* basename of configfile */
   int  config_search=1;		/* search the config file */
   int  cmdline_debuglevel=0;

   struct sigaction act;

/*
 * setup signal handlers
 */
   act.sa_handler=sighandler;
   sigemptyset(&act.sa_mask);
   act.sa_flags=SA_RESTART;
   if (sigaction(SIGTERM, &act, NULL)) {
      ERROR("Failed to install SIGTERM handler");
   }
   if (sigaction(SIGINT, &act, NULL)) {
      ERROR("Failed to install SIGINT handler");
   }
   if (sigaction(SIGUSR1, &act, NULL)) {
      ERROR("Failed to install SIGUSR1 handler");
   }


/*
 * prepare default configuration
 */
   memset (&configuration, 0, sizeof(configuration));
   configuration.sip_listen_port=SIP_PORT;

   log_set_pattern(configuration.debuglevel);      

/*
 * parse command line
 */
{
   int option_index = 0;
   static struct option long_options[] = {
      {"help", no_argument, NULL, 'h'},
      {"config", required_argument, NULL, 'c'},
      {"debug", required_argument, NULL, 'd'},
      {0,0,0,0}
   };

    while ((ch1 = getopt_long(argc, argv, "hc:d:n",
                  long_options, &option_index)) != -1) {
      switch (ch1) {
      case 'h':	/* help */
         DEBUGC(DBCLASS_CONFIG,"option: help");
         fprintf(stderr,str_helpmsg);
         exit(0);
	 break;

      case 'c':	/* load config file */
         DEBUGC(DBCLASS_CONFIG,"option: config file=%s",optarg);
         strncpy(configfile,optarg,sizeof(configfile)-1);
	 configfile[sizeof(configfile)]='\0';
	 config_search=0;
	 break; 

      case 'd':	/* set debug level */
         DEBUGC(DBCLASS_CONFIG,"option: set debug level: %s",optarg);
	 cmdline_debuglevel=atoi(optarg);
         log_set_pattern(cmdline_debuglevel);
	 break;

      default:
         DEBUGC(DBCLASS_CONFIG,"no command line options");
	 break; 
      }
   }
}

/*
 * Init stuff
 */

   /* read the config file */
   if (read_config(configfile, config_search) == STS_FAILURE) exit(1);

   /* if a debug level > 0 has been given on the commandline use its
      value and not what is in the config file */
   if (cmdline_debuglevel != 0) {
      configuration.debuglevel=cmdline_debuglevel;
   }

   /* set debug level as desired */
   log_set_pattern(configuration.debuglevel);

   /* change user and group IDs */
   secure_enviroment();

   /* daemonize if requested to */
   if (configuration.daemonize) {
      DEBUGC(DBCLASS_CONFIG,"daemonizing");
      if (fork()!=0) exit(0);
      setsid();
      if (fork()!=0) exit(0);

      log_set_tosyslog(1);
   }
#ifdef MOREDEBUG /*&&&&*/
INFO("daemonizing done (pid=%i)", getpid());
#endif

   /* initialize the RTP proxy */
   sts=rtpproxy_init();
   if (sts != STS_SUCCESS) {
      ERROR("unable to initialize RTP proxy - aborting"); 
      exit(1);
   }

   /* init the oSIP parser */
   parser_init();

   /* initialize the registration facility */
   register_init();

   /* listen for incoming messages */
   sts=sipsock_listen();
   if (sts == STS_FAILURE) {
      /* failure to allocate SIP socket... */
      ERROR("unable to bind to SIP listening socket - aborting"); 
      exit(1);
   }

   INFO(PACKAGE"-"VERSION"-"BUILDSTR" started");
/*
 * silence the log - if so required...
 */
   log_set_silence(configuration.silence_log);

/*
 * Main loop
 */
   while (!exit_program) {

      DEBUGC(DBCLASS_BABBLE,"going into sip_wait\n");
      while (sipsock_wait()<=0) {
         /* got no input, here by timeout. do aging */
         register_agemap();

         /* dump memory stats if requested to do so */
         if (dmalloc_dump) {
            dmalloc_dump=0;
#ifdef DMALLOC
            INFO("SIGUSR1 - DMALLOC statistics is dumped");
            dmalloc_log_stats();
            dmalloc_log_unfreed();
#else
            INFO("SIGUSR1 - DMALLOC support is not compiled in");
#endif
         }

         if (exit_program) goto exit_prg;
      }

      /* got input, process */
      DEBUGC(DBCLASS_BABBLE,"back from sip_wait");

      i=sipsock_read(&buff, sizeof(buff)-1, &from);
      buff[i]='\0';

#ifdef MOREDEBUG /*&&&&*/
{char tmp[32];
strncpy(tmp, buff, 30);
tmp[30]='\0';
INFO("got packet [%i bytes]from %s [%s]", i, inet_ntoa(from.sin_addr), tmp);}
#endif
      /* evaluate the access lists (IP based filter)*/
      access=accesslist_check(from);
      if (access == 0) continue; /* there are no resources to free */

      /* integrity checks */
      sts=security_check_raw(buff, i);
      if (sts != STS_SUCCESS) continue; /* there are no resources to free */

      /* parse the received message */
      sts=osip_message_init(&my_msg);
      my_msg->message=NULL;

      if (sts != 0) {
         ERROR("osip_message_init() failed... this is not good");
	 continue; /* skip, there are no resources to free */
      }

      sts=osip_message_parse(my_msg, buff);
      if (sts != 0) {
         ERROR("osip_message_parse() failed... this is not good");
         DUMP_BUFFER(-1, buff, i);
         goto end_loop; /* skip and free resources */
      }

      /* integrity checks - parsed buffer*/
      sts=security_check_sip(my_msg);
      if (sts != STS_SUCCESS) {
         ERROR("security_check_sip() failed... this is not good");
         DUMP_BUFFER(-1, buff, i);
         goto end_loop; /* skip and free resources */
      }

      DEBUGC(DBCLASS_SIP,"received SIP type %s:%s",
	     (MSG_IS_REQUEST(my_msg))? "REQ" : "RES",
	     (my_msg->sip_method)?
              my_msg->sip_method : "NULL") ;

      /*
      * if an RQ REGISTER, check if it is directed to myself,
      * or am I just the outbound proxy but no registrar.
      * - If I'm the registrar, register & generate answer
      * - If I'm just the outbound proxy, register, rewrite & forward
      */
      if (MSG_IS_REGISTER(my_msg) && MSG_IS_REQUEST(my_msg)) {
         if (access & ACCESSCTL_REG) {
            osip_uri_t *url;
            struct in_addr addr1, addr2, addr3;

            url = osip_message_get_uri(my_msg);
            sts = get_ip_by_host(url->host, &addr1);
            sts = get_ip_by_ifname(configuration.inbound_if,&addr2);
            sts = get_ip_by_ifname(configuration.outbound_if,&addr3);

            if ((memcmp(&addr1, &addr2, sizeof(addr1)) == 0) ||
                (memcmp(&addr1, &addr3, sizeof(addr1)) == 0)) {
               /* I'm the registrar, send response myself */
               sts = register_client(my_msg, 0);
               sts = register_response(my_msg, sts);
            } else {
               /* I'm just the outbound proxy */
               DEBUGC(DBCLASS_SIP,"proxying REGISTER request to:%s",url->host);
               sts = register_client(my_msg, 1);
               sts = proxy_request(my_msg);
            }
	 } else {
            WARN("non-authorized registration attempt from %s",
	         inet_ntoa(from.sin_addr));
	 }

      /*
       * check if outbound interface is UP.
       * If not, send back error to UA and
       * skip any proxying attempt
       */
      } else if (get_ip_by_ifname(configuration.outbound_if,NULL) !=
                 STS_SUCCESS) {
         DEBUGC(DBCLASS_SIP, "got a %s to proxy, but outbound interface "
                "is down", (MSG_IS_REQUEST(my_msg))? "REQ" : "RES");

         if (MSG_IS_REQUEST(my_msg))
            sip_gen_response(my_msg, 408 /*request timeout*/);
      
      /*
       * MSG is a request, add current via entry,
       * do a lookup in the URLMAP table and
       * send to the final destination
       */
      } else if (MSG_IS_REQUEST(my_msg)) {
         if (access & ACCESSCTL_SIP) {
            sts = proxy_request(my_msg);
	 } else {
            INFO("non-authorized request received from %s",
	            inet_ntoa(from.sin_addr));
	 }

      /*
       * MSG is a response, remove current via and
       * send to the next VIA in chain
       */
      } else if (MSG_IS_RESPONSE(my_msg)) {
         if (access & ACCESSCTL_SIP) {
            sts = proxy_response(my_msg);
	 } else {
            INFO("non-authorized response received from %s",
	            inet_ntoa(from.sin_addr));
	 }
	 
      /*
       * unsupported message
       */
      } else {
         ERROR("received unsupported SIP type %s %s",
	       (MSG_IS_REQUEST(my_msg))? "REQ" : "RES",
	       my_msg->sip_method);
      }


/*
 * free the SIP message buffers
 */
      end_loop:
      osip_message_free(my_msg);

   } /* while TRUE */
   exit_prg:
   INFO("properly terminating siproxd");

   return 0;
} /* main */

/*
 * Signal handler
 *
 * this one is called asynchronously whevener a registered
 * signal is applied. Just set a flag and don't do any funny
 * things here.
 */
static void sighandler(int sig) {
   if (sig==SIGTERM) exit_program=1;
   if (sig==SIGINT)  exit_program=1;
   if (sig==SIGUSR1) dmalloc_dump=1;
   return;
}
