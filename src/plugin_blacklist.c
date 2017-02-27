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

/*&&&+++ Workaround sqlite3 3.3.6 header/symbol errors)*/
#define sqlite3_clear_bindings		UNDEFINED_SYMBOL
#define sqlite3_prepare_v2		UNDEFINED_SYMBOL
/*&&&---*/

/* Plug-in identification */
static char name[]="plugin_blacklist";
static char desc[]="Blacklists client IPs / SIP accounts upon auth failures";

/* global configuration storage - required for config file location */
extern struct siproxd_config configuration;

/* plugin configuration storage */
static struct plugin_config {
   char *dbpath;	/* path to sqlite DB file (/var/lib/siproxd/bl.db */
   int  block_mode;	/* 0: no, 1: IP based, 2: IP & SIP-user */ 
   int  simulate;	/* 0: no, 1: don't block, just log */ 
   int  duration;	/* in seconds, 0: forever, dont' expire */ 
   int  hitcount;	/* required attempts until blocked */ 
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_blacklist_dbpath",		TYP_STRING, &plugin_cfg.dbpath,	{0, "/var/lib/siproxd/blacklist.sqlite"} },
   { "plugin_blacklist_mode",		TYP_INT4,   &plugin_cfg.block_mode,	{0, NULL} },
   { "plugin_blacklist_simulate",	TYP_INT4,   &plugin_cfg.simulate,	{0, NULL} },
   { "plugin_blacklist_duration",	TYP_INT4,   &plugin_cfg.duration,	{3600, NULL} },
   { "plugin_blacklist_hitcount",	TYP_INT4,   &plugin_cfg.hitcount,	{10, NULL} },
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
   {  0, NULL, "SELECT count(id) from blacklist WHERE ip=?001 and sipuri=?002 AND failcount>?003;" },
   {  1, NULL, "UPDATE OR IGNORE blacklist SET lastseen=?003 WHERE ip=?001 and sipuri=?002;" },
   /* blacklist_update_fail() */
   {  2, NULL, "INSERT OR IGNORE INTO blacklist (ip, sipuri) VALUES (?001, ?002);" },
   {  3, NULL, "UPDATE OR IGNORE blacklist SET failcount=failcount+1, lastseen=?003, lastfail=?003 WHERE ip=?001 and sipuri=?002;" },
   {  4, NULL, "UPDATE OR IGNORE blacklist SET lastseen=?003 WHERE ip=?001 and sipuri=?002;" },
   {  5, NULL, "UPDATE OR IGNORE blacklist SET failcount=0, lastseen=?003 WHERE ip=?001 and sipuri=?002;" },
};
#define SQL_CHECK_1		0
#define SQL_CHECK_2		1

#define SQL_UPDATE_FAIL_1	2	/* insert new record to DB */
#define SQL_UPDATE_FAIL_2	3	/* increment failcount */
#define SQL_UPDATE_FAIL_3	4	/* just update lastseen */
#define SQL_UPDATE_FAIL_4	5	/* reset failcount upon successful registration */

/* string magic in C preprocessor */
#define xstr(s) str(s)
#define str(s) #s

/* SQL statements */
#define DB_SQL_CREATE \
	"CREATE TABLE IF NOT EXISTS "\
	    "control ( "\
		"action VARCHAR(32) UNIQUE, "\
		"count INTEGER DEFAULT 0, "\
		"time VARCHAR(32) "\
	    ");" \
	"CREATE TABLE IF NOT EXISTS "\
	    "blacklist ( "\
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "\
		"type INTEGER DEFAULT 0, "\
		"ip VARCHAR(" xstr(IPSTRING_SIZE) "), "\
		"sipuri VARCHAR(" xstr(USERNAME_SIZE) "), "\
		"failcount INTEGER DEFAULT 0, "\
		"lastfail INTEGER DEFAULT 0, "\
		"lastseen INTEGER DEFAULT 0, "\
		"CONSTRAINT unique_src UNIQUE (ip, sipuri) " \
	    ");"

/* tables
control
blacklist
    - id
    - type	0: automatic entry, 1: manual entry (manually added to DB, will not expire)
    - ip	IP address of source (xxx.xxx.xxx.xxx)
    - sipuri	SIP authentication username
    - failcount	count of failed attempts
    - lastfail	UNIX timestamp of last failure activity (last failed auth)
    - lastseen	UNIX timestamp of last activity
*/


/* local prototypes */
static int blacklist_check(sip_ticket_t *ticket);
static int blacklist_update_fail(sip_ticket_t *ticket);
static int blacklist_expire(sip_ticket_t *ticket);
/* helpers */
static int sqlite_begin(void);
static int sqlite_end(void);
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
      sts = blacklist_update_fail(ticket);
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

   DEBUGC(DBCLASS_BABBLE, "entering blacklist_check");

   /* bind */
   sql_stmt = &sql_statement[SQL_CHECK_1];
   sts = sqlite3_bind_text(sql_stmt->stmt, 001, "1.2.3.4", -1, SQLITE_TRANSIENT);
   sts = sqlite3_bind_text(sql_stmt->stmt, 002, "foo@bar.org", -1, SQLITE_TRANSIENT);
   sts = sqlite3_bind_int(sql_stmt->stmt,  003, plugin_cfg.hitcount);
   /* execute & eval result */
   sts = sqlite_exec_stmt_int(sql_stmt, &retval);
   sql_stmt = NULL;

   /* bind */
   sql_stmt = &sql_statement[SQL_CHECK_2];
   sts = sqlite3_bind_text(sql_stmt->stmt, 001, "1.2.3.4", -1, SQLITE_TRANSIENT);
   sts = sqlite3_bind_text(sql_stmt->stmt, 002, "foo@bar.org", -1, SQLITE_TRANSIENT);
   sts = sqlite3_bind_int(sql_stmt->stmt,  003, ticket->timestamp);
   sts = sqlite_exec_stmt_int(sql_stmt, &retval);
   sql_stmt = NULL;

// not present in 3.3.6   sts = sqlite3_clear_bindings(stmt1);






   /* SELECT and find if a record exists
      last_seen no older than block_duration
      failcount >0
      return failcount */

   /* update last_seen */

   /* if failcount > maxfail, block */



#define DB_SQL_BL_CHECK \
	"SELECT * from blacklist where "


   DEBUGC(DBCLASS_BABBLE, "leaving blacklist_check");
   return STS_SUCCESS;
}

static int blacklist_update_fail(sip_ticket_t *ticket) {
   int sts;
   int retval=0;
   sql_statement_t *sql_stmt = NULL;

   DEBUGC(DBCLASS_BABBLE, "entering blacklist_update_fail");

   if (MSG_IS_STATUS_4XX(ticket->sipmsg)) {
      /* bind */
      sql_stmt = &sql_statement[SQL_UPDATE_FAIL_1];
      //&&& fetch UAC IP from telegram
      //&&& fetch SIP URI (contact?) from telegram
      sts = sqlite3_bind_text(sql_stmt->stmt, 001, "1.2.3.41", -1, SQLITE_TRANSIENT);
      sts = sqlite3_bind_text(sql_stmt->stmt, 002, "foo@bar.org", -1, SQLITE_TRANSIENT);
      sts = sqlite_exec_stmt_int(sql_stmt, &retval);
      sql_stmt = NULL;
   }


   sql_stmt = NULL;
   if (MSG_IS_STATUS_4XX(ticket->sipmsg)) {
      /* REGISTER 4xx failure: increment error counter */
      sql_stmt = &sql_statement[SQL_UPDATE_FAIL_2];
   } else if (MSG_IS_STATUS_2XX(ticket->sipmsg)) {
      /* REGISTER 2xx success: set error counter to 0 */
      sql_stmt = &sql_statement[SQL_UPDATE_FAIL_4];
   } else {
      /* update last-seen */
      sql_stmt = &sql_statement[SQL_UPDATE_FAIL_3];
   }
   if (sql_stmt) {
      /* bind */
      //&&& fetch UAC IP from telegram
      //&&& fetch SIP URI (contact?) from telegram
      sts = sqlite3_bind_text(sql_stmt->stmt, 001, "1.2.3.41", -1, SQLITE_TRANSIENT);
      sts = sqlite3_bind_text(sql_stmt->stmt, 002, "foo@bar.org", -1, SQLITE_TRANSIENT);
      sts = sqlite3_bind_int(sql_stmt->stmt,  003, ticket->timestamp);
      /* execute query */
      sts = sqlite_exec_stmt_int(sql_stmt, &retval);
      sql_stmt = NULL;
   }

   /* INSERT OR IGNORE records to DB: IP, sipuri */
   /* UPDATE records failcount=failcount+1, lastseen=now, lastfail=now */

   DEBUGC(DBCLASS_BABBLE, "leaving blacklist_update_fail");
   return STS_SUCCESS;
}

static int blacklist_expire(sip_ticket_t *ticket) {
   int sts;
   char *zErrMsg = NULL;

   DEBUGC(DBCLASS_BABBLE, "entering blacklist_expire");
   /* set failcount=0 for all records where last_seen is older than block_period */
   /* or remove records */

   DEBUGC(DBCLASS_BABBLE, "leaving blacklist_expire");
   return STS_SUCCESS;
}


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
