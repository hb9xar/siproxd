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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/types.h>
#include <pwd.h>

#include <osip/smsg.h>
#include <osip/port.h>

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";

/* configuration storage */
extern struct siproxd_config configuration;

extern int h_errno;

/*
 * create a reply template from an given SIP request
 */
sip_t *msg_make_template_reply (sip_t * request, int code) {
   sip_t *response;
   char *tmp;
   int pos;

   msg_init (&response);
   msg_setversion (response, sgetcopy ("SIP/2.0"));
   tmp = malloc(STATUSCODE_SIZE);
   snprintf (tmp, STATUSCODE_SIZE, "%i", code);
   msg_setstatuscode (response, tmp);
   msg_setreasonphrase (response, msg_getreason (code));

   to_clone (request->to, &response->to);
   from_clone (request->from, &response->from);


   /* via headers */
   pos = 0;
   while (!list_eol (request->vias, pos)) {
      via_t *via;
      via = (via_t *) list_get (request->vias, pos);
      via_2char (via, &tmp);

      msg_setvia (response, tmp);
      free (tmp);
      pos++;
   }

   call_id_clone(request->call_id,&response->call_id);
   cseq_clone(request->cseq,&response->cseq);

   return response;
}


/*
 * check for a via loop.
 * It checks for the presense of a via entry that holds one of
 * my IP addresses and is *not* the topmost via.
 */
int check_vialoop (sip_t *my_msg) {
   int sts;
   int pos;
   int found_own_via;

   found_own_via=0;
   pos = 1;	/* for detecting a loop, don't check the first entry 
   		   as this is my VIA! */
   while (!list_eol (my_msg->vias, pos)) {
      via_t *via;
      via = (via_t *) list_get (my_msg->vias, pos);
      sts = is_via_local (via);
      if (sts == 1) found_own_via=1;
      pos++;
   }
   return found_own_via;
}


/*
 * check if a given via_t is local. I.e. its address is owned
 * by my inbound or outbound interface
 */
int is_via_local (via_t *via) {
   int sts;
   struct in_addr addr_via, addr_myself;
   char *my_hostnames[]=
        { configuration.inboundhost, configuration.outboundhost, NULL };
   int port;
   int i;
   char *ptr;

   DEBUGC(DBCLASS_BABBLE,"via name %s",via->host);
   if (inet_aton(via->host,&addr_via) == 0) {
      /* need name resolution */
      get_ip_by_host(via->host, &addr_via);
   }   

   sts=0;
   for (i=0; ; i++) {
      ptr=my_hostnames[i];
      if (ptr==NULL) break;

      DEBUGC(DBCLASS_BABBLE,"local name %s",ptr);
      /* check the extracted VIA against my own host addresses */
      sts = get_ip_by_host(ptr, &addr_myself);

      if (via->port) port=atoi(via->port);
      else port=SIP_PORT;

      if ( (memcmp(&addr_myself, &addr_via, sizeof(addr_myself))==0) &&
           (port == configuration.sip_listen_port) ) {
         sts=1;
	 break;
      }
   }

   return sts; 
}


/*
 * resolve a hostname and return in_addr
 * handles its own little DNS cache.
 */
int get_ip_by_host(char *hostname, struct in_addr *addr) {
   int i, j;
   time_t t;
   struct hostent *hostentry;
   static struct {
      time_t timestamp;
      struct in_addr addr;
      char hostname[HOSTNAME_SIZE];
   } dns_cache[DNS_CACHE_SIZE];
   static int cache_initialized=0;

   if (hostname == NULL) return 1;

   /* first time: initialize DNS cache */
   if (cache_initialized == 0) {
      DEBUGC(DBCLASS_DNS, "initializing DNS cache (%i entries)", DNS_CACHE_SIZE);
      memset(dns_cache, 0, sizeof(dns_cache));
      cache_initialized=1;
   }

   time(&t);
   /* clean expired entries */
   for (i=0; i<DNS_CACHE_SIZE; i++) {
      if (dns_cache[i].hostname[0]=='\0') continue;
      if ( (dns_cache[i].timestamp+DNS_MAX_AGE) < t ) {
         DEBUGC(DBCLASS_DNS, "cleaning DNS cache, entry %i)", i);
         memset (&dns_cache[i], 0, sizeof(dns_cache[0]));
      }
   }

   /*
    * search requested entry in cache
    */
   for (i=0; i<DNS_CACHE_SIZE; i++) {
      if (dns_cache[i].hostname[0]=='\0') continue; /* empty */
      if (strcmp(hostname, dns_cache[i].hostname) == 0) { /* match */
         memcpy(addr, &dns_cache[i].addr, sizeof(struct in_addr));
         DEBUGC(DBCLASS_DNS, "DNS lookup - from cache: %s -> %s",
	        hostname, inet_ntoa(*addr));
         return 0;
      }
   }
   
   /* did not find it in cache, so I have to resolve it */
   hostentry=gethostbyname(hostname);

   if (hostentry==NULL) {
      ERROR("gethostbyname(%s) failed: %s",hostname,hstrerror(h_errno));
      return 1;
   }

   memcpy(addr, hostentry->h_addr, sizeof(struct in_addr));
   DEBUGC(DBCLASS_DNS, "DNS lookup - resolved: %s -> %s",
          hostname, inet_ntoa(*addr));

   /*
    * remember the result in the cache
    */
   /* find an empty slot */
   j=0;
   for (i=0; i<DNS_CACHE_SIZE; i++) {
      if (dns_cache[i].hostname[0]=='\0') break;
      if (dns_cache[i].timestamp < t) {
         /* remember oldest entry */
         t=dns_cache[i].timestamp;
	 j=i;
      }
   }
   /* if no empty slot found, take oldest one */
   if (i >= DNS_CACHE_SIZE) i=j;

   /* store in cache */
   DEBUGC(DBCLASS_DNS, "DNS lookup - store into cache, entry %i)", i);
   memset(&dns_cache[i], 0, sizeof(dns_cache[0]));
   strncpy(dns_cache[i].hostname, hostname, HOSTNAME_SIZE);
   time(&dns_cache[i].timestamp);
   memcpy(&dns_cache[i].addr, addr, sizeof(struct in_addr));

   return 0;
}

/*
 * compares two URLs
 * returns 0 if equal, <0 if non equal, >0 if error
 * (by now, only hostname and username are compared)
 */
int compare_url(url_t *url1, url_t *url2) {
   int sts;

   if ((url1 == NULL) || (url2 == NULL)) return 1;

   /* comparison of hosts should be based on IP addresses, no? */
   DEBUGC(DBCLASS_BABBLE, "comparng urls: %s@%s -> %s@%s",
         url1->username, url1->host, url2->username, url2->host);
   if ((strcmp(url1->username, url2->username)==0) &&
       (strcmp(url1->host, url2->host)==0)) {
      sts = 0;
   } else {
      sts = -1;
   }

   return sts;
}


/*
 * Secure enviroment:
 * If running as root,change UID/GID to user as requested in config
 */
void secure_enviroment (void) {
   int sts;
   struct passwd *passwd=NULL;

   DEBUGC(DBCLASS_CONFIG,"running w/uid=%i, euid=%i, gid=%i, egid=%i",
          getuid(), geteuid(), getgid(), getegid());

   if ((getuid()==0)|| (geteuid()==0)) {
      /*
       * preparation - after chrooting there will be NOTHING more around
       */
      if (configuration.user) passwd=getpwnam(configuration.user);


      /*
       * change root directory into chroot jail
       */
      if (configuration.chrootjail) {
         DEBUGC(DBCLASS_CONFIG,"chrooting to %s",
                configuration.chrootjail);
         sts = chroot(configuration.chrootjail);
	 if (sts != 0) DEBUGC(DBCLASS_CONFIG,"chroot(%s) failed: %s",
	                      configuration.chrootjail, strerror(errno));
         chdir("/");
      }


      /*
       * change user ID and group ID 
       */
      if (passwd) {
         DEBUGC(DBCLASS_CONFIG,"changing uid/gid to %s",
                configuration.user);
         sts = setgid(passwd->pw_gid);
         DEBUGC(DBCLASS_CONFIG,"changed gid to %i - %s",
	        passwd->pw_gid, (sts==0)?"Ok":"Failed");

         sts = setegid(passwd->pw_uid);
         DEBUGC(DBCLASS_CONFIG,"changed egid to %i - %s",
	        passwd->pw_gid, (sts==0)?"Ok":"Failed");

         sts = setuid(passwd->pw_uid);
         DEBUGC(DBCLASS_CONFIG,"changed uid to %i - %s",
	        passwd->pw_uid, (sts==0)?"Ok":"Failed");

         sts = seteuid(passwd->pw_uid);
         DEBUGC(DBCLASS_CONFIG,"changed euid to %i - %s",
	        passwd->pw_uid, (sts==0)?"Ok":"Failed");
      }
   }
}
