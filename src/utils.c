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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <pwd.h>

#ifdef HAVE_OSIP2
   #include <osip2/smsg.h>
#else
   #include <osip/smsg.h>
#endif

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";

/* configuration storage */
extern struct siproxd_config configuration;

extern int h_errno;


/*
 * resolve a hostname and return in_addr
 * handles its own little DNS cache.
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on failure
 */
int get_ip_by_host(char *hostname, struct in_addr *addr) {
   int i, j;
   time_t t;
   struct hostent *hostentry;
   static struct {
      time_t timestamp;
      struct in_addr addr;
      char hostname[HOSTNAME_SIZE+1];
   } dns_cache[DNS_CACHE_SIZE];
   static int cache_initialized=0;

   if (hostname == NULL) {
      ERROR("get_ip_by_host: NULL hostname requested");
      return STS_FAILURE;
   }

   if (addr == NULL) {
      ERROR("get_ip_by_host: NULL in_addr passed");
      return STS_FAILURE;
   }

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
         DEBUGC(DBCLASS_DNS, "cleaning DNS cache (entry %i)", i);
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
         return STS_SUCCESS;
      }
   }
   
   /* did not find it in cache, so I have to resolve it */
   hostentry=gethostbyname(hostname);

   if (hostentry==NULL) {
      if (h_errno == HOST_NOT_FOUND) {
         /* this is actually not really an error */
#ifdef HAVE_HSTRERROR
         DEBUGC(DBCLASS_DNS, "gethostbyname(%s) failed: %s",
                hostname, hstrerror(h_errno));
#else
         DEBUGC(DBCLASS_DNS, "gethostbyname(%s) failed: h_errno=%i",
                hostname, h_errno);
#endif
      } else {
#ifdef HAVE_HSTRERROR
         ERROR("gethostbyname(%s) failed: %s",hostname, hstrerror(h_errno));
#else
         ERROR("gethostbyname(%s) failed: h_errno=%i",hostname, h_errno);
#endif
      }
      return STS_FAILURE;
   }

   memcpy(addr, hostentry->h_addr, sizeof(struct in_addr));
   DEBUGC(DBCLASS_DNS, "DNS lookup - resolved: %s -> %s",
          hostname, inet_ntoa(*addr));

   /*
    * find an empty slot in the cache
    */
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

   /*
    * store the result in the cache
    */
   DEBUGC(DBCLASS_DNS, "DNS lookup - store into cache, entry %i)", i);
   memset(&dns_cache[i], 0, sizeof(dns_cache[0]));
   strncpy(dns_cache[i].hostname, hostname, HOSTNAME_SIZE);
   time(&dns_cache[i].timestamp);
   memcpy(&dns_cache[i].addr, addr, sizeof(struct in_addr));

   return STS_SUCCESS;
}


/*
 * Secure enviroment:
 * If running as root, put myself into a chroot jail and
 * change UID/GID to user as requested in config file
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


/*
 * get_ip_by_ifname:
 * fetches own IP address by its interface name
 *
 * STS_SUCCESS on returning a valid IP and interface is UP
 * STS_FAILURE if interface is DOWN or other problem
 */
int get_ip_by_ifname(char *ifname, struct in_addr *retaddr) {
   struct ifreq ifr;
   struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
   int sockfd;
   int i, j;
   int ifflags, isup;
   time_t t;
   static struct {
      time_t timestamp;
      struct in_addr ifaddr;	/* IP */
      int isup;			/* interface is UP */
      char ifname[IFNAME_SIZE+1];
   } ifaddr_cache[IFADR_CACHE_SIZE];
   static int cache_initialized=0;

   if (ifname == NULL) {
      WARN("get_ip_by_ifname: got NULL ifname passed - please check config"
           "file ('if_inbound' and 'if_outbound')");
      return STS_FAILURE;
   }

   /* first time: initialize ifaddr cache */
   if (cache_initialized == 0) {
      DEBUGC(DBCLASS_DNS, "initializing ifaddr cache (%i entries)", 
             IFADR_CACHE_SIZE);
      memset(ifaddr_cache, 0, sizeof(ifaddr_cache));
      cache_initialized=1;
   }

   time(&t);
   /* clean expired entries */
   for (i=0; i<IFADR_CACHE_SIZE; i++) {
      if (ifaddr_cache[i].ifname[0]=='\0') continue;
      if ( (ifaddr_cache[i].timestamp+IFADR_MAX_AGE) < t ) {
         DEBUGC(DBCLASS_DNS, "cleaning ifaddr cache (entry %i)", i);
         memset (&ifaddr_cache[i], 0, sizeof(ifaddr_cache[0]));
      }
   }

   /*
    * search requested entry in cache
    */
   for (i=0; i<IFADR_CACHE_SIZE; i++) {
      if (ifaddr_cache[i].ifname[0]=='\0') continue;
      if (strcmp(ifname, ifaddr_cache[i].ifname) == 0) { /* match */
         if (retaddr) memcpy(retaddr, &ifaddr_cache[i].ifaddr,
                             sizeof(struct in_addr));
         DEBUGC(DBCLASS_DNS, "ifaddr lookup - from cache: %s -> %s %s",
	        ifname, inet_ntoa(ifaddr_cache[i].ifaddr),
                (ifaddr_cache[i].isup)? "UP":"DOWN");
         return (ifaddr_cache[i].isup)? STS_SUCCESS: STS_FAILURE;
      } /* if */
   } /* for i */

   /* not found in cache, go and get it */
   bzero(&ifr, sizeof(ifr));

   if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      ERROR("Error in socket: %s\n",strerror(errno));
      return STS_FAILURE;
   }

   strcpy(ifr.ifr_name, ifname);
   sin->sin_family = AF_INET;

   /* get interface flags */
   if(ioctl(sockfd, SIOCGIFFLAGS, &ifr) != 0) {
      ERROR("Error in ioctl SIOCGIFFLAGS: %s\n",strerror(errno));
      close(sockfd);
      return STS_FAILURE;
   } 
   ifflags=ifr.ifr_flags;

   /* get address */
   if(ioctl(sockfd, SIOCGIFADDR, &ifr) != 0) {
      ERROR("Error in ioctl SIOCGIFADDR: %s\n",strerror(errno));
      close(sockfd);
      return STS_FAILURE;
   } 

   if (ifflags & IFF_UP) isup=1;
   else isup=0;

   DEBUGC(DBCLASS_DNS, "get_ip_by_ifname: if %s has IP:%s (flags=%x) %s",
          ifname, inet_ntoa(sin->sin_addr), ifflags,
          (isup)? "UP":"DOWN");

   /*
    *find an empty slot in the cache
    */
   j=0;
   for (i=0; i<IFADR_CACHE_SIZE; i++) {
      if (ifaddr_cache[i].ifname[0]=='\0') break;
      if (ifaddr_cache[i].timestamp < t) {
         /* remember oldest entry */
         t=ifaddr_cache[i].timestamp;
	 j=i;
      }
   }
   /* if no empty slot found, take oldest one */
   if (i >= IFADR_CACHE_SIZE) i=j;

   /*
    * store the result in the cache
    */
   DEBUGC(DBCLASS_DNS, "ifname lookup - store into cache, entry %i)", i);
   memset(&ifaddr_cache[i], 0, sizeof(ifaddr_cache[0]));
   strncpy(ifaddr_cache[i].ifname, ifname, IFNAME_SIZE);
   ifaddr_cache[i].timestamp=t;
   memcpy(&ifaddr_cache[i].ifaddr, &sin->sin_addr, sizeof(sin->sin_addr));
   ifaddr_cache[i].isup=isup;

   if (retaddr) memcpy(retaddr, &sin->sin_addr, sizeof(sin->sin_addr));

   close(sockfd);
   return (isup)? STS_SUCCESS : STS_FAILURE;
}


