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

/*				function returns STS_* status values     vvv */

/* sock.c */
int sipsock_listen (void);						/*X*/
int sipsock_wait(void);
int sipsock_read(void *buf, size_t bufsize, struct sockaddr_in *from);
int sipsock_send_udp(int *sock, struct in_addr addr, int port,		/*X*/
                     char *buffer, int size, int allowdump);
int sockbind(struct in_addr ipaddr, int localport);

/* register.c */
void register_init(void);
int  register_client(sip_t *request);					/*X*/
void register_agemap(void);
int register_response(sip_t *request, int flag);			/*X*/

/* proxy.c */
int proxy_request (sip_t *request);					/*X*/
int proxy_response (sip_t *response);					/*X*/
int proxy_gen_response(sip_t *request, int code);			/*X*/
int proxy_add_myvia (sip_t *request, int interface);			/*X*/
int proxy_del_myvia (sip_t *response);					/*X*/
int proxy_rewrite_invitation_body(sip_t *mymsg);			/*X*/

/* utils.c */
sip_t * msg_make_template_reply (sip_t * request, int code);
int check_vialoop (sip_t *my_msg);					/*X*/
int is_via_local (via_t *via);						/*X*/
int get_ip_by_host(char *hostname, struct in_addr *addr);		/*X*/
int compare_url(url_t *url1, url_t *url2);				/*X*/
void secure_enviroment (void);

/* readconf.c */
int read_config(char *name, int search);				/*X*/

/* rtpproxy.c */
int rtpproxy_init( void );						/*X*/
int rtp_start_fwd (call_id_t *callid,					/*X*/
		   struct in_addr outbound_ipaddr, int *outboundport,
                   struct in_addr lcl_client_ipaddr, int lcl_clientport);
int rtp_stop_fwd (call_id_t *callid, int nolock);			/*X*/

/* accessctl.c */
int accesslist_check(struct sockaddr_in from);

/* security.c */
int security_check(char *sip_buffer, int size);				/*X*/

/* auth.c */
int authenticate_proxy(sip_t *request);					/*X*/
int auth_include_authrq(sip_t *response);				/*X*/



/*
 * table to hold the client registrations
 */
struct urlmap_s {
   int  active;
   int  expires;
   url_t *true_url;
   url_t *masq_url;
   via_t *via;
};


/*
 * configuration option table
 */
struct siproxd_config {
   int debuglevel;
   char *inboundhost;
   char *outboundhost;
   int sip_listen_port;
   int daemonize;
   int rtp_port_low;
   int rtp_port_high;
   int rtp_timeout;
   int rtp_proxy_enable;
   char *user;
   char *chrootjail;
   char *hosts_allow_reg;
   char *hosts_allow_sip;
   char *hosts_deny_sip;
   char *proxy_auth_realm;
   char *proxy_auth_passwd;
   char *proxy_auth_pwfile;
};


/*
 * some constant definitions
 */
#define SIP_PORT	5060

#define URLMAP_SIZE	8	/* number of URL mapping table entries	*/
#define RTPPROXY_SIZE	8	/* number of rtp proxy entries		*/

#define BUFFER_SIZE	1024	/* input buffer for read from socket	*/
#define RTP_BUFFER_SIZE	512	/* max size of an RTP frame		*/
#define URL_STRING_SIZE	128	/* max size of an URL/URI string	*/
#define STATUSCODE_SIZE 5	/* size of string representation of status */
#define DNS_CACHE_SIZE  32	/* number of entries in internal DNS cache */
#define DNS_MAX_AGE	60	/* maximum age of an cache entry (sec)	*/
#define HOSTNAME_SIZE	32	/* max string length of a hostname	*/
#define USERNAME_SIZE	32	/* max string length of a username (auth) */
#define PASSWORD_SIZE	32	/* max string length of a password (auth) */


#define ACCESSCTL_SIP	1	/* for access control - SIP allowed	*/
#define ACCESSCTL_REG	2	/* --"--              - registr. allowed */

/* symbolic return status */

#define STS_SUCCESS	0	/* SUCCESS				*/
#define STS_TRUE	0	/* TRUE					*/
#define STS_FAILURE	1	/* FAILURE				*/
#define STS_FALSE	1	/* FALSE				*/
#define STS_NEED_AUTH	1001	/* need authentication			*/

/*
 * optional hacks
 */
#define HACK1	/* linphone-0.9.0pre4: broken RQ URI hack */
/* 14-Aug-2002 TR
   Linphone puts in the proxies hostname in the request URI when
   OUTBOUND proxy is activated. But ONLY the hostname. Username and
   Port (!!!) are kept from the SIP address given by the user.
   This issue is fixed in linphone-0.9.1pre1
*/
