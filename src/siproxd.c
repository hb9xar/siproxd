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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <getopt.h>

#include <osip/smsg.h>

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


/* configuration storage */
struct siproxd_config configuration;

/* socket used for sending SIP datagrams */
int sip_socket=0;

int main (int argc, char *argv[]) 
{
   int sts;
   int i;
   char buff [BUFFER_SIZE];
   sip_t *my_msg=NULL;

   extern char *optarg;
   int ch1;
   
   char configfile[64]="siproxd";	/* basename of configfile */
   int  config_search=1;		/* search the config file */

   /* prepare default configuration */
   configuration.debuglevel=0;
   configuration.daemonize=0;
   configuration.sip_listen_port=SIP_PORT;
   configuration.inboundhost=NULL;
   configuration.outboundhost=NULL;

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

    while ((ch1 = getopt_long_only(argc, argv, "hc:d:n",
                  long_options, &option_index)) != -1) {
      switch (ch1) {
      case 'h':	/* help */
         DEBUGC(DBCLASS_CONFIG,"option: help");

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
	 configuration.debuglevel=atoi(optarg);
	 log_set_pattern(configuration.debuglevel);
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
   if (read_config(configfile, config_search) != 0) exit(1);
   /* if a debug_level statement was in the config file, make sure
      the debug pattern is set after reading the config */
   log_set_pattern(configuration.debuglevel);

   /* init the oSIP parser */
   parser_init();

   /* initialize the registration facility */
   register_init();

   /* listen for incomming messages */
   sts=sipsock_listen();
   if (sts != 0) {
      /* failure to allocate SIP socket... */
      ERROR("unable to bind to SIP listening socket - aborting"); 
      return 0;
   }

   /* initialize the RTP proxy thread */
   rtpproxy_init();

   /* daemonize if requested to */
   if (configuration.daemonize) {
      DEBUGC(DBCLASS_CONFIG,"daemonizing");
      if (fork()!=0) exit(0);
      /* close STDIN, STDOUT, STDERR */
      close(0);close(1);close(2);
   }


/*
 * Main loop
 */
   while (1) {

      DEBUGC(DBCLASS_BABBLE,"going into sip_wait\n");
      while (sipsock_wait()==0) {
         /* got no input, here by timeout. do aging */
         register_agemap();
      }

      /* got input, process */
      DEBUGC(DBCLASS_BABBLE,"back from sip_wait");

      i=sipsock_read(&buff, sizeof(buff));
/*
 * more integrity checks of received packet needed !!
 * it's possible to crash msg_parse with some crap-input.
 */
      sts=msg_init(&my_msg);
      sts=msg_parse( my_msg, buff);
/*
 * if message parsing was ok go on - otherwise skip
 */
      if (sts != 0) continue;

      DEBUGC(DBCLASS_SIP,"received SIP type %s:%s",
	     (MSG_IS_REQUEST(my_msg))? "REQ" : "RES",
	     my_msg->strtline->sipmethod);

      /* if RQ REGISTER, just register and send an answer */
      if (MSG_IS_REGISTER(my_msg) && MSG_IS_REQUEST(my_msg)) {
         sts = register_client(my_msg);
         sts = register_response(my_msg, sts);

      /* MSG is a request, add current via entry,
       * do a lookup in the URLMAP table and
       * send to the final destination */
      } else if (MSG_IS_REQUEST(my_msg)) {
         sts = proxy_request(my_msg);

      /* MSG is a response, remove current via and
       * send to next via in chain */
      } else if (MSG_IS_RESPONSE(my_msg)) {
         sts = proxy_response(my_msg);
	 
      /* unsupported message */
      } else {
         ERROR("received unsupported SIP type %s %s",
	       (MSG_IS_REQUEST(my_msg))? "REQ" : "RES",
	       my_msg->strtline->sipmethod);
      }


/*
 * free the SIP message buffers
 */
      msg_free(my_msg);
      free(my_msg);

   } /* while TRUE */

} /* main */

