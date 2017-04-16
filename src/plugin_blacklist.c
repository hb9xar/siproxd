/*
    Copyright (C) 2017  Thomas Ries <tries@gmx.net>

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
#define PLUGIN_NAME	plugin_blacklist

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "plugins.h"
#include "log.h"

static char const ident[]="$Id$";

/*&&&+++ Workaround sqlite3 3.3.6 (header/symbol errors)*/
#define sqlite3_clear_bindings		UNDEFINED_SYMBOL
#define sqlite3_prepare_v2		UNDEFINED_SYMBOL
/*&&&---*/

/* Plug-in identification */
static char name[]="plugin_blacklist";
static char desc[]="Blacklist client IPs / SIP accounts upon auth failures";

/* global configuration storage - required for config file location */
extern struct siproxd_config configuration;

/* plugin configuration storage */
static struct plugin_config {
   char *dbpath;	/* path to sqlite DB file (/var/lib/siproxd/bl.db */
//   int  block_mode;	/* 0: no, 1: IP based, 2: IP & SIP-user */ 
   int  simulate;	/* 0: no, 1: don't block, just log */ 
   int  duration;	/* in seconds, 0: forever, dont' expire */ 
   int  hitcount;	/* required attempts until blocked */ 
   int  register_window;/* time window for REGISTER reesponse to arrive */ 
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_blacklist_dbpath",		TYP_STRING, &plugin_cfg.dbpath,	{0, "/var/lib/siproxd/blacklist.sqlite"} },
//   { "plugin_blacklist_mode",		TYP_INT4,   &plugin_cfg.block_mode,	{2, NULL} },
   { "plugin_blacklist_simulate",	TYP_INT4,   &plugin_cfg.simulate,	{0, NULL} },
   { "plugin_blacklist_duration",	TYP_INT4,   &plugin_cfg.duration,	{3600, NULL} },
   { "plugin_blacklist_hitcount",	TYP_INT4,   &plugin_cfg.hitcount,	{10, NULL} },
   { "plugin_blacklist_register_window", TYP_INT4,  &plugin_cfg.register_window, {30, NULL} },
   {0, 0, 0}
};

/* SQLITE related variables */
static sqlite3 *db=NULL;

/* prepared SQL statements */
typedef struct {
   int id;
   sqlite3_stmt *stmt;
   char *sql_query;
} sql_statement_t;

static sql_statement_t sql_statement[] = {
   /* blacklist_check() */
   {  0, NULL, "SELECT count(*) from blacklist WHERE ip=?001 and sipuri=?002 AND (type=1 or failcount>?003);" },
   {  1, NULL, "UPDATE OR IGNORE blacklist SET lastseen=?003 WHERE ip=?001 and sipuri=?002;" },
   {  2, NULL, "UPDATE OR IGNORE requests SET timestamp=?001, callid=?004 WHERE ip=?002 AND sipuri=?003;" },
   {  3, NULL, "INSERT OR IGNORE INTO requests (timestamp, ip, sipuri, callid) VALUES (?001, ?002, ?003, ?004);" },
   /* blacklist_update() */
   {  4, NULL, "DELETE FROM requests WHERE timestamp<?001;" },
   {  5, NULL, "SELECT count(*) from requests WHERE ip=?001 and sipuri=?002 AND callid=?003;" },
   {  6, NULL, "INSERT OR IGNORE INTO blacklist (ip, sipuri) VALUES (?001, ?002);" },
   {  7, NULL, "UPDATE OR IGNORE blacklist SET failcount=failcount+1, lastseen=?003, lastfail=?003 WHERE type=0 and ip=?001 and sipuri=?002;" },
   {  8, NULL, "UPDATE OR IGNORE blacklist SET lastseen=?003 WHERE ip=?001 and sipuri=?002;" },
   {  9, NULL, "UPDATE OR IGNORE blacklist SET failcount=0, lastseen=?003 WHERE type=0 and ip=?001 and sipuri=?002;" },
   { 10, NULL, "UPDATE OR IGNORE blacklist SET failcount=0 WHERE type=0 and failcount<?001 and lastseen<?002;" },
};
#define SQL_CHECK_1	0
#define SQL_CHECK_2	1
#define SQL_CHECK_3	2
#define SQL_CHECK_4	3

#define SQL_UPDATE_1	4	/* expire old request records */
#define SQL_UPDATE_2	5	/* check if REGISTER response matches a know record */
#define SQL_UPDATE_3	6	/* insert new blacklist record to DB */
#define SQL_UPDATE_4	7	/* increment failcount */
#define SQL_UPDATE_5	8	/* just update lastseen */
#define SQL_UPDATE_6	9	/* reset failcount upon successful registration */
#define SQL_UPDATE_7	10	/* cleanup blacklist table */

/* string magic in C preprocessor */
#define xstr(s) str(s)
#define str(s) #s

/* SQL statements */
#define CALLID_SIZE	256
#define DB_SQL_CREATE \
	"CREATE TABLE IF NOT EXISTS "\
	    "control ( "\
		"action VARCHAR(32) UNIQUE, "\
		"count INTEGER DEFAULT 0, "\
		"time VARCHAR(32) "\
	    ");" \
	"CREATE TABLE IF NOT EXISTS "\
	    "blacklist ( "\
		"type INTEGER DEFAULT 0, "\
		"ip VARCHAR(" xstr(IPSTRING_SIZE) "), "\
		"sipuri VARCHAR(" xstr(USERNAME_SIZE) "), "\
		"failcount INTEGER DEFAULT 0, "\
		"lastfail INTEGER DEFAULT 0, "\
		"lastseen INTEGER DEFAULT 0, "\
		"CONSTRAINT unique_src UNIQUE (ip, sipuri) " \
	    ");" \
	"CREATE TABLE IF NOT EXISTS "\
	    "requests ( "\
		"timestamp INTEGER DEFAULT 0, "\
		"ip VARCHAR(" xstr(IPSTRING_SIZE) "), "\
		"sipuri VARCHAR(" xstr(USERNAME_SIZE) "), "\
		"callid VARCHAR(" xstr(CALLID_SIZE) "), "\
		"CONSTRAINT unique_req UNIQUE (ip, sipuri) " \
	    ");"

/* tables
control
blacklist
    - type	0: automatic entry, 1: manual entry (manually added to DB, will not expire)
    - ip	IP address of source (xxx.xxx.xxx.xxx)
    - sipuri	SIP authentication username
    - failcount	count of failed attempts
    - lastfail	UNIX timestamp of last failure activity (last failed auth)
    - lastseen	UNIX timestamp of last activity
requests
    - timestamp	timestamp of outgoing REGISTER request
    - ip	IP address of source (xxx.xxx.xxx.xxx)
    - sipuri	SIP authentication username
    - callid	SIP CallID of REGISTER request
*/


/* local prototypes */
static int blacklist_check(sip_ticket_t *ticket);
static int blacklist_update(sip_ticket_t *ticket);
#if 0
static int blacklist_expire(sip_ticket_t *ticket);
#endif
/* helpers */
static int sqlite_begin(void);
static int sqlite_end(void);
static int sqlite_exec_stmt_none(sql_statement_t *sql_statement);
static int sqlite_exec_stmt_int(sql_statement_t *sql_statement, int *retval);

/* 
 * Initialization.
 * Called once suring siproxd startup.
 */
int  PLUGIN_INIT(plugin_def_t *plugin_def) {
   /* API version number of siproxd that this plugin is built against.
    * This constant will change whenever changes to the API are made
    * that require adaptions in the plugin. */
   plugin_def->api_version=SIPROXD_API_VERSION;

   /* Name and descriptive text of the plugin */
   plugin_def->name=name;
   plugin_def->desc=desc;

   /* Execution mask - during what stages of SIP processing shall
    * the plugin be called. */
   plugin_def->exe_mask=PLUGIN_VALIDATE | PLUGIN_POST_PROXY;

   /* read the config file */
   if (read_config(configuration.configfile,
                   configuration.config_search,
                   plugin_cfg_opts, name) == STS_FAILURE) {
      ERROR("Plugin '%s': could not load config file", name);
      return STS_FAILURE;
   }

   if (sqlite_begin() != STS_SUCCESS) {
      return STS_FAILURE;
   }

   INFO("plugin_blacklist is initialized (sqlite version %s)", sqlite3_libversion());
   return STS_SUCCESS;
}

/*
 * Processing.
 * 
 */
int  PLUGIN_PROCESS(int stage, sip_ticket_t *ticket){
   int sts;
   /* stage contains the PLUGIN_* value - the stage of SIP processing. */
   DEBUGC(DBCLASS_BABBLE, "plugin_blacklist: processing - stage %i",stage);
   DEBUGC(DBCLASS_BABBLE, "plugin_blacklist: MSG_IS_REQUEST %i",MSG_IS_REQUEST(ticket->sipmsg));
   DEBUGC(DBCLASS_BABBLE, "plugin_blacklist: MSG_IS_RESPONSE %i",MSG_IS_RESPONSE(ticket->sipmsg));
   DEBUGC(DBCLASS_BABBLE, "plugin_blacklist: MSG_IS_REGISTER %i",MSG_IS_REGISTER(ticket->sipmsg));
   DEBUGC(DBCLASS_BABBLE, "plugin_blacklist: MSG_IS_RESPONSE_FOR(REGISTER) %i",MSG_IS_RESPONSE_FOR(ticket->sipmsg,"REGISTER"));
   DEBUGC(DBCLASS_BABBLE, "plugin_blacklist: MSG_IS_STATUS_4XX %i",MSG_IS_STATUS_4XX(ticket->sipmsg));

   if ((stage == PLUGIN_VALIDATE) 
       && MSG_IS_REQUEST(ticket->sipmsg)) {
      sts = blacklist_check(ticket);
      if (sts != STS_SUCCESS) {
         return STS_FAILURE;
      }
   } else if ((stage == PLUGIN_POST_PROXY) 
              && MSG_IS_RESPONSE(ticket->sipmsg)
              && MSG_IS_RESPONSE_FOR(ticket->sipmsg, "REGISTER")) {
      sts = blacklist_update(ticket);
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
   int sts;

   sts = sqlite_end();

   INFO("plugin_blacklist ends here");
   return STS_SUCCESS;
}

/*--------------------------------------------------------------------*/
/* private plugin code */
static int blacklist_check(sip_ticket_t *ticket) {
   int sts;
   int retval=0;
   sql_statement_t *sql_stmt = NULL;
   char *srcip=NULL;	/* IP address from UAC issuing the REGSITER */
   osip_uri_t *from_url = NULL;
   char *from=NULL;
   char *call_id=ticket->sipmsg->call_id->number;
   osip_authorization_t *auth=NULL;


   DEBUGC(DBCLASS_BABBLE, "entering blacklist_check");

   /* get source IP address as string */
   srcip=utils_inet_ntoa(ticket->from.sin_addr);

   /* From: 1st preference is From header, then try contact header */
   if (ticket->sipmsg->from->url) {
      from_url = ticket->sipmsg->from->url;
   } else {
      DEBUGC(DBCLASS_BABBLE,"no from header in packet, skipping BL handling");
      return STS_SUCCESS;
   }
   osip_uri_to_str(from_url, &from);

   DEBUGC(DBCLASS_BABBLE,"checking user %s from IP %s (Call-Id=[%s])",from, srcip, call_id);

   /* Query 1: SELECT for blacklisted entries */
   /* bind */
   sql_stmt = &sql_statement[SQL_CHECK_1];
   sts = sqlite3_bind_text(sql_stmt->stmt, 001, srcip, -1, SQLITE_TRANSIENT);
   sts = sqlite3_bind_text(sql_stmt->stmt, 002, from, -1, SQLITE_TRANSIENT);
   sts = sqlite3_bind_int(sql_stmt->stmt,  003, plugin_cfg.hitcount);
   /* execute & eval result */
   sts = sqlite_exec_stmt_int(sql_stmt, &retval); /* retval: nunber of records found that */
                                                  /* the blocked query */
   sql_stmt = NULL;

   /* Query 2: UPDATE  (last seen TS) */
   /* bind */
   sql_stmt = &sql_statement[SQL_CHECK_2];
   sts = sqlite3_bind_text(sql_stmt->stmt, 001, srcip, -1, SQLITE_TRANSIENT);
   sts = sqlite3_bind_text(sql_stmt->stmt, 002, from, -1, SQLITE_TRANSIENT);
   sts = sqlite3_bind_int(sql_stmt->stmt,  003, ticket->timestamp);
   sts = sqlite_exec_stmt_none(sql_stmt);
   sql_stmt = NULL;

   if (MSG_IS_REGISTER(ticket->sipmsg)) {
      /* Disarm initial REGISTER requests that carry no Authentication header data. */
      /* So if no Auth Header is present, then set CALL-Id=<empty> */
      if (osip_message_get_authorization(ticket->sipmsg, 0, &auth) < 0) {
         DEBUGC(DBCLASS_BABBLE, "REGISTER without Auth data");
         call_id="";
      }

      /* Query 3: UPDATE OR IGNORE REGISTER request into requests DB */
      /* bind */
      sql_stmt = &sql_statement[SQL_CHECK_3];
      sts = sqlite3_bind_int(sql_stmt->stmt,  001, ticket->timestamp);
      sts = sqlite3_bind_text(sql_stmt->stmt, 002, srcip, -1, SQLITE_TRANSIENT);
      sts = sqlite3_bind_text(sql_stmt->stmt, 003, from, -1, SQLITE_TRANSIENT);
      sts = sqlite3_bind_text(sql_stmt->stmt, 004, call_id,-1, SQLITE_TRANSIENT);
      sts = sqlite_exec_stmt_none(sql_stmt);
      sql_stmt = NULL;
      /* Query 3: INSERT OR IGNORE REGISTER request into requests DB */
      /* bind */
      sql_stmt = &sql_statement[SQL_CHECK_4];
      sts = sqlite3_bind_int(sql_stmt->stmt,  001, ticket->timestamp);
      sts = sqlite3_bind_text(sql_stmt->stmt, 002, srcip, -1, SQLITE_TRANSIENT);
      sts = sqlite3_bind_text(sql_stmt->stmt, 003, from, -1, SQLITE_TRANSIENT);
      sts = sqlite3_bind_text(sql_stmt->stmt, 004, call_id,-1, SQLITE_TRANSIENT);
      sts = sqlite_exec_stmt_none(sql_stmt);
      sql_stmt = NULL;
   }

   // not present in sqlite 3.3.6   sts = sqlite3_clear_bindings(stmt1);

   if ((retval > 0) && (plugin_cfg.simulate==0)) {
      DEBUGC(DBCLASS_BABBLE, "leaving blacklist_check, UAC is blocked");
      INFO ("UAC with IP %s [%s] is blocked", srcip, from);
      osip_free(from);
      return STS_FAILURE;
   } else if (retval > 0) {
      DEBUGC(DBCLASS_BABBLE, "leaving blacklist_check, UAC is blocked");
      INFO ("UAC with IP %s [%s] would be blocked (simulate=1)", srcip, from);
   }

   /* free resources */
   osip_free(from);

   DEBUGC(DBCLASS_BABBLE, "leaving blacklist_check, UAC is permitted");
   return STS_SUCCESS;
}


static int blacklist_update(sip_ticket_t *ticket) {
   int sts;
   int retval=0;
   sql_statement_t *sql_stmt = NULL;
   char *dstip=NULL;	/* IP address from UAC issuing the REGSITER */
   osip_uri_t *from_url = NULL;
   char *from=NULL;
   char *call_id=ticket->sipmsg->call_id->number;

   DEBUGC(DBCLASS_BABBLE, "entering blacklist_update");

   /* Query 1: remove old records (> register_window seconds) */
   /* bind */
   sql_stmt = &sql_statement[SQL_UPDATE_1];
   sts = sqlite3_bind_int(sql_stmt->stmt,  001, ticket->timestamp - plugin_cfg.register_window);
   sts = sqlite_exec_stmt_none(sql_stmt);
   sql_stmt = NULL;

   /* get target IP address as string */
   dstip=utils_inet_ntoa(ticket->next_hop.sin_addr);

   /* From: 1st preference is From header, then try contact header */
   if (ticket->sipmsg->from->url) {
      from_url = ticket->sipmsg->from->url;
   } else {
      DEBUGC(DBCLASS_BABBLE,"no from header in packet, skipping BL handling");
      return STS_SUCCESS;
   }
   osip_uri_to_str(from_url, &from);


   DEBUGC(DBCLASS_BABBLE,"checking user %s at IP %s (Call-Id=[%s])",from, dstip, call_id);

   /* Query 2: check if this REGISTER response has a known record in the requests table */
   /* bind */
   sql_stmt = &sql_statement[SQL_UPDATE_2];
   sts = sqlite3_bind_text(sql_stmt->stmt, 001, dstip, -1, SQLITE_TRANSIENT);
   sts = sqlite3_bind_text(sql_stmt->stmt, 002, from, -1, SQLITE_TRANSIENT);
   sts = sqlite3_bind_text(sql_stmt->stmt, 003, call_id, -1, SQLITE_TRANSIENT);
   sts = sqlite_exec_stmt_int(sql_stmt, &retval);
   sql_stmt = NULL;

   if (retval > 0) {
      DEBUGC(DBCLASS_BABBLE, "response to existing query, continue processing");

      /* a failed request? then instert resp. update DB blacklist record */
      if (MSG_IS_STATUS_4XX(ticket->sipmsg)) {
         DEBUGC(DBCLASS_BABBLE, "inserting blacklist record for user %s at IP %s ", from, dstip);
         /* Query 3: failed REGISTER, add new record in blacklist in not yet existing */
         /* bind */
         sql_stmt = &sql_statement[SQL_UPDATE_3];
         sts = sqlite3_bind_text(sql_stmt->stmt, 001, dstip, -1, SQLITE_TRANSIENT);
         sts = sqlite3_bind_text(sql_stmt->stmt, 002, from, -1, SQLITE_TRANSIENT);
         sts = sqlite_exec_stmt_int(sql_stmt, &retval);
         sql_stmt = NULL;
      }


      if (MSG_IS_STATUS_4XX(ticket->sipmsg)) {
         /* REGISTER 4xx failure: increment error counter */
         DEBUGC(DBCLASS_BABBLE, "4XX: incrementing error counter for user %s at IP %s ", from, dstip);
         sql_stmt = &sql_statement[SQL_UPDATE_4];
      } else if (MSG_IS_STATUS_2XX(ticket->sipmsg)) {
         /* REGISTER 2xx success: set error counter to 0 */
         DEBUGC(DBCLASS_BABBLE, "2XX: setting error counter=0 for user %s at IP %s ", from, dstip);
         sql_stmt = &sql_statement[SQL_UPDATE_6];
      } else {
         /* update last-seen */
         DEBUGC(DBCLASS_BABBLE, "update last seen for user %s at IP %s ", from, dstip);
         sql_stmt = &sql_statement[SQL_UPDATE_5];
      }
      if (sql_stmt) {
         /* Query 4/5/6 */
         /* bind */
         sts = sqlite3_bind_text(sql_stmt->stmt, 001, dstip, -1, SQLITE_TRANSIENT);
         sts = sqlite3_bind_text(sql_stmt->stmt, 002, from, -1, SQLITE_TRANSIENT);
         sts = sqlite3_bind_int(sql_stmt->stmt,  003, ticket->timestamp);
         /* execute query */
         sts = sqlite_exec_stmt_none(sql_stmt);
         sql_stmt = NULL;
      }

   } /* if Q2 true */

   /* expire old blacklist records */
   /* Query7 */
   /* bind */
   sql_stmt = &sql_statement[SQL_UPDATE_7];
   sts = sqlite3_bind_int(sql_stmt->stmt,  001, plugin_cfg.hitcount);
   sts = sqlite3_bind_int(sql_stmt->stmt,  002, ticket->timestamp-plugin_cfg.duration);
   /* execute query */
   sts = sqlite_exec_stmt_none(sql_stmt);
   sql_stmt = NULL;

   /* free resources */
   osip_free(from);


   DEBUGC(DBCLASS_BABBLE, "leaving blacklist_update");
   return STS_SUCCESS;
}


#if 0
static int blacklist_expire(sip_ticket_t *ticket) {
//   int sts;
//   char *zErrMsg = NULL;

   DEBUGC(DBCLASS_BABBLE, "entering blacklist_expire");
   /* set failcount=0 for all records where last_seen is older than block_period */
   /* or remove records */

   DEBUGC(DBCLASS_BABBLE, "leaving blacklist_expire");
   return STS_SUCCESS;
}
#endif

/*--------------------------------------------------------------------*/
/* helper functions */
static int sqlite_begin(void){
   int sts;
   int i;
   char *zErrMsg = NULL;

   /* open the database */
   sts = sqlite3_open(plugin_cfg.dbpath, &db);
   if( sts != SQLITE_OK ){
      ERROR("Can't open database: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return STS_FAILURE;
   }

   /* create table structure if not existing */
   sts = sqlite3_exec(db, DB_SQL_CREATE, NULL, 0, &zErrMsg);
   if( sts != SQLITE_OK ){
      ERROR( "SQL exec error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
      sqlite3_close(db);
      return STS_FAILURE;
   }

   /* write check (DB update) */
#define DB_SQL_STARTUP \
	"INSERT OR IGNORE INTO control (action, count) VALUES ('bl_started', 0); "\
	"UPDATE control set count = count + 1, time  =  datetime('now') where action ='bl_started';"
   sts = sqlite3_exec(db, DB_SQL_STARTUP, NULL, 0, &zErrMsg);
   if( sts != SQLITE_OK ){
      ERROR( "SQL exec error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
      sqlite3_close(db);
      return STS_FAILURE;
   }

   /* create prepared statements */
   DEBUGC(DBCLASS_BABBLE, "PLUGIN_INIT: preparing %i statements", 
          sizeof(sql_statement) / sizeof(sql_statement[0]));
   for (i=0; i < sizeof(sql_statement) / sizeof(sql_statement[0]); i++) {
      if (sql_statement[i].sql_query == NULL) {
         DEBUGC(DBCLASS_BABBLE, "PLUGIN_INIT: skiping empty SQL statement");
         continue;
      }
      if (sql_statement[i].stmt == NULL) {
         DEBUGC(DBCLASS_BABBLE, "PLUGIN_INIT: preparing stmt %i [%s]", 
                i, sql_statement[i].sql_query);
         sts = sqlite3_prepare(db, sql_statement[i].sql_query, -1, 
                               &sql_statement[i].stmt, NULL );
         if( sts != SQLITE_OK ){
            ERROR("SQL prepare error [query=%i]: %s\n", i, sqlite3_errmsg(db));
            sqlite3_close(db);
            return STS_FAILURE;
         }
      }
   }

   return STS_SUCCESS;
}

static int sqlite_end(void){
   int sts;
   int i;
   char *zErrMsg = NULL;

   /* Mark shutdown in DB (pure informational reasons) */
#define DB_SQL_SHUTDOWN \
	"INSERT OR IGNORE INTO control (action, count) VALUES ('bl_stopped', 0); "\
	"UPDATE control set count = count + 1, time  =  datetime('now') where action ='bl_stopped';"
   sts = sqlite3_exec(db, DB_SQL_SHUTDOWN, NULL, 0, &zErrMsg);
   if( sts != SQLITE_OK ){
      ERROR( "SQL exec error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   }

   /* free ressources of prepared queries */
   for (i=0; i < sizeof(sql_statement) / sizeof(sql_statement[0]); i++) {
      if (sql_statement[i].stmt != NULL) {
         sts = sqlite3_finalize(sql_statement[i].stmt);
      }
   }

   sqlite3_close(db);

   return STS_SUCCESS;
}

static int sqlite_exec_stmt_none(sql_statement_t *sql_statement){
   int sts;

   /* execute & eval result */
   DEBUGC(DBCLASS_BABBLE, "executing query [%s]", sql_statement->sql_query);
   do {
      sts = sqlite3_step(sql_statement->stmt);
   } while (sts == SQLITE_ROW);
   if ( sts == SQLITE_ERROR) {
      sts = sqlite3_reset(sql_statement->stmt);
      ERROR("SQL step error [%i]: %s\n", sts, sqlite3_errmsg(db));
   } else if ( sts != SQLITE_DONE ) {
      ERROR("SQL step error [%i]: %s\n", sts, sqlite3_errmsg(db));
   }
   /* cleanup */
   sts = sqlite3_reset(sql_statement->stmt);

   return STS_SUCCESS;
}

static int sqlite_exec_stmt_int(sql_statement_t *sql_statement, int *retval){
   int sts;

   /* execute & eval result */
   DEBUGC(DBCLASS_BABBLE, "executing query [%s]", sql_statement->sql_query);
   do {
      sts = sqlite3_step(sql_statement->stmt);
      if (sts == SQLITE_ROW) {
         if (retval != NULL) {
            *retval = sqlite3_column_int(sql_statement->stmt, 0);
            DEBUGC(DBCLASS_BABBLE, "sqlite_exec_stmt_int: query returned INT %i", *retval);
         }
      }
   } while (sts == SQLITE_ROW);
   if ( sts == SQLITE_ERROR) {
      sts = sqlite3_reset(sql_statement->stmt);
      ERROR("SQL step error [%i]: %s\n", sts, sqlite3_errmsg(db));
   } else if ( sts != SQLITE_DONE ) {
      ERROR("SQL step error [%i]: %s\n", sts, sqlite3_errmsg(db));
   }
   /* cleanup */
   sts = sqlite3_reset(sql_statement->stmt);

   return STS_SUCCESS;
}

//&&& implement cache of open REGISTER requests, only honor failed REGISTERS responses where a
//&&& REQUEST has been sent before from one of our clients.
