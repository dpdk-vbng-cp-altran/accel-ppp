#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <aio.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <stdbool.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>

#include <json.h>

#include "log.h"
#include "events.h"
#include "ppp.h"
#include "spinlock.h"
#include "mempool.h"

#include "utils.h"
#include "memdebug.h"
#include "ipdb.h"

extern char** environ;
extern struct list_head conn_list;

#define DEFAULT_NAS_ID "accel-ppp"
#define DEFAULT_REDIS_HOST    "localhost"
#define DEFAULT_REDIS_PORT     6379
#define DEFAULT_REDIS_PUBCHAN "accel-ppp"
#define DEFAULT_REDIS_SUBCHAN "accel-ppp-5g"

enum ap_redis_events_t {
	REDIS_EV_SES_STARTING         = 0x00000001,
	REDIS_EV_SES_STARTED          = 0x00000002,
	REDIS_EV_SES_FINISHING        = 0x00000004,
	REDIS_EV_SES_FINISHED         = 0x00000008,
	REDIS_EV_SES_AUTHORIZED       = 0x00000010,
	REDIS_EV_CTRL_STARTING        = 0x00000020,
	REDIS_EV_CTRL_STARTED         = 0x00000040,
	REDIS_EV_CTRL_FINISHED        = 0x00000080,
	REDIS_EV_SES_PRE_UP           = 0x00000100,
	REDIS_EV_SES_ACCT_START       = 0x00000200,
	REDIS_EV_CONFIG_RELOAD        = 0x00000400,
	REDIS_EV_SES_AUTH_FAILED      = 0x00000800,
	REDIS_EV_SES_PRE_FINISHED     = 0x00001000,
	REDIS_EV_IP_CHANGED           = 0x00002000,
	REDIS_EV_SHAPER               = 0x00004000,
	REDIS_EV_MPPE_KEYS            = 0x00008000,
	REDIS_EV_DNS                  = 0x00010000,
	REDIS_EV_WINS                 = 0x00020000,
	REDIS_EV_FORCE_INTERIM_UPDATE = 0x00040000,
	REDIS_EV_RADIUS_ACCESS_ACCEPT = 0x00080000,
	REDIS_EV_RADIUS_COA           = 0x00100000,
	REDIS_EV_5G_REGISTRATION      = 0x00200000,
	REDIS_EV_5G_DEREGISTRATION    = 0x00400000,
	REDIS_EV_5G_PACKET            = 0x00800000,
};

enum ap_redis_session_t {
	REDIS_SES_CTRL_TYPE_PPTP      = 1,
	REDIS_SES_CTRL_TYPE_L2TP      = 2,
	REDIS_SES_CTRL_TYPE_PPPOE     = 3,
	REDIS_SES_CTRL_TYPE_IPOE      = 4,
	REDIS_SES_CTRL_TYPE_OPENVPN   = 5,
	REDIS_SES_CTRL_TYPE_SSTP      = 6,
};

enum ap_redis_flags_t {
	REDIS_FLAG_KEEP_BG_THREAD_RUNNING = 0x00000001,
	REDIS_FLAG_BG_THREAD_IS_RUNNING   = 0x00000002,
};

struct ap_redis_msg_t {
	struct list_head entry;
	int event;
	int ses_ctrl_type;
	char* calling_station_id;
	char* called_station_id;
	char* name;
	char* chan_name;
	char* username;
	char* ip_addr;
	char* sessionid;
	char* circuit_id;
	char* remote_id;
	uint32_t xid;
	int pppoe_sessionid;
	char* ctrl_ifname;
	char* nas_identifier;
	uint8_t data[1500];
	int   len;
	int   giaddr;
	int   siaddr;
};

struct ap_redis_t {
	mempool_t *msg_pool;
	mempool_t *sub_pool;
	struct list_head entry;
	struct list_head msg_queue;
	spinlock_t msg_queue_lock;
	int need_free:1;
	int queued:1;
	struct ap_redis_pd_t *lpd;

	/* eventfd file descriptor */
	int evfd;

	/* dedicated thread for running redis main loop */
	pthread_t thread;
	pthread_t sub_thread;
	/* thread return value */
	int thread_exit_code;
	int sub_thread_exit_code;
	/* flags */
	uint32_t flags;

	/*radius nas-identifier */
	char* nas_id;
	/* redis host */
	char* host;
	/* redis port */
	uint16_t port;
	/* redis channel (publish) */
	char* pubchan;
	char* subchan;
	char* pathname;
	uint32_t events;
};

struct ap_redis_pd_t {
	struct ap_private pd;
	struct ap_redis_t lf;
	unsigned long tmp;
};


static struct ap_redis_t *ap_redis;

static mempool_t redis_pool;

void ap_construct_msg (uint8_t *dhcp_pkt, uint32_t pkt_len, json_object* jobj)
{
    uint8_t     *ptr; 

    ptr = dhcp_pkt; 
    json_object *jarray = json_object_new_array();

    for (int i = 0; i< pkt_len; i++)
    {
	json_object *jint = json_object_new_int(*(ptr+i));
	json_object_array_add(jarray,jint);
    }

    json_object_object_add(jobj,"packet", jarray);
    return;
}

static void ap_redis_dequeue(struct ap_redis_t* ap_redis, redisContext* ctx)
{
	spin_lock(&ap_redis->msg_queue_lock);

	while (!list_empty(&ap_redis->msg_queue)) {

		struct ap_redis_msg_t* msg = list_first_entry(&(ap_redis->msg_queue), typeof(*msg), entry);
		list_del(&msg->entry);

		json_object* jobj = json_object_new_object();
		json_object* jstring;

		/* event type */
		switch (msg->event) {
		case REDIS_EV_SES_STARTING:             jstring = json_object_new_string("session-starting");       break;
		case REDIS_EV_SES_STARTED:              jstring = json_object_new_string("session-started");        break;
		case REDIS_EV_SES_FINISHING:		jstring = json_object_new_string("session-finishing");      break;
		case REDIS_EV_SES_FINISHED:             jstring = json_object_new_string("session-finished");       break;
		case REDIS_EV_SES_AUTHORIZED:		jstring = json_object_new_string("session-authorized");     break;
		case REDIS_EV_CTRL_STARTING:		jstring = json_object_new_string("control-starting");       break;
		case REDIS_EV_CTRL_STARTED:             jstring = json_object_new_string("control-started");        break;
		case REDIS_EV_CTRL_FINISHED:		jstring = json_object_new_string("control-finished");       break;
		case REDIS_EV_SES_PRE_UP:               jstring = json_object_new_string("session-pre-up");         break;
		case REDIS_EV_SES_ACCT_START:           jstring = json_object_new_string("session-acct-start");     break;
		case REDIS_EV_CONFIG_RELOAD:            jstring = json_object_new_string("config-reload");          break;
		case REDIS_EV_SES_AUTH_FAILED:          jstring = json_object_new_string("session-auth-failed");    break;
		case REDIS_EV_SES_PRE_FINISHED:         jstring = json_object_new_string("session-pre-finished");   break;
		case REDIS_EV_IP_CHANGED:               jstring = json_object_new_string("ip-changed");             break;
		case REDIS_EV_SHAPER:                   jstring = json_object_new_string("shaper");                 break;
		case REDIS_EV_MPPE_KEYS:                jstring = json_object_new_string("mppe-keys");              break;
		case REDIS_EV_DNS:                      jstring = json_object_new_string("dns");                    break;
		case REDIS_EV_WINS:                     jstring = json_object_new_string("wins");                   break;
		case REDIS_EV_FORCE_INTERIM_UPDATE:     jstring = json_object_new_string("force-interim-update");   break;
		case REDIS_EV_RADIUS_ACCESS_ACCEPT:     jstring = json_object_new_string("radius-access-accept");   break;
		case REDIS_EV_RADIUS_COA:               jstring = json_object_new_string("coa");                    break;
		case REDIS_EV_5G_REGISTRATION:          jstring = json_object_new_string("register");               break;
		case REDIS_EV_5G_DEREGISTRATION:        jstring = json_object_new_string("deregister");             break;
		case REDIS_EV_5G_PACKET:                jstring = json_object_new_string("packet");                 break;
		default:                                jstring = json_object_new_string("unknown");                break;
		}
		json_object_object_add(jobj, "event", jstring);

		/* session ctrl type */
		switch (msg->ses_ctrl_type) {
		case REDIS_SES_CTRL_TYPE_PPTP:    jstring = json_object_new_string("pptp");    break;
		case REDIS_SES_CTRL_TYPE_L2TP:    jstring = json_object_new_string("l2tp");    break;
		case REDIS_SES_CTRL_TYPE_PPPOE:   jstring = json_object_new_string("pppoe");   break;
		case REDIS_SES_CTRL_TYPE_IPOE:    jstring = json_object_new_string("ipoe");    break;
		case REDIS_SES_CTRL_TYPE_OPENVPN: jstring = json_object_new_string("openvpn"); break;
		case REDIS_SES_CTRL_TYPE_SSTP:    jstring = json_object_new_string("sstp");    break;
		default: {};
		}
		json_object_object_add(jobj, "ctrl_type", jstring);

		/* session channel name */
		if (msg->chan_name)
			json_object_object_add(jobj, "channel_name", json_object_new_string(msg->chan_name));

		/* session id */
		if (msg->sessionid)
			json_object_object_add(jobj, "session_id", json_object_new_string(msg->sessionid));

		/* called_station_id */
		if (msg->called_station_id)
			json_object_object_add(jobj, "called_station_id", json_object_new_string(msg->called_station_id));

		/* calling_station_id */
		if (msg->calling_station_id)
			json_object_object_add(jobj, "calling_station_id", json_object_new_string(msg->calling_station_id));
		/* name */
		if (msg->name)
			json_object_object_add(jobj, "name", json_object_new_string(msg->name));

		/* username */
		if (msg->username)
			json_object_object_add(jobj, "username", json_object_new_string(msg->username));

		/* ip_addr */
		if (msg->ip_addr)
			json_object_object_add(jobj, "ip_addr", json_object_new_string(msg->ip_addr));

          	/* pppoe_sessionid */
		if (msg->pppoe_sessionid)
			json_object_object_add(jobj, "pppoe_sessionid", json_object_new_int(msg->pppoe_sessionid));

                /* ipoe_xid */
		if (msg->event == REDIS_EV_5G_REGISTRATION ||
                    msg->event == REDIS_EV_5G_DEREGISTRATION)
		{
			json_object_object_add(jobj, "xid", json_object_new_int(msg->xid));
		}

		if (msg->giaddr)
			json_object_object_add(jobj, "giaddr", json_object_new_int(msg->giaddr));

		if (msg->siaddr)
			json_object_object_add(jobj, "siaddr", json_object_new_int(msg->siaddr));

		/*circuit_id */
		if (msg->circuit_id)
			json_object_object_add(jobj, "circuit_id", json_object_new_string(msg->circuit_id));

		/*remote_id */
		if (msg->remote_id)
			json_object_object_add(jobj, "remote_id", json_object_new_string(msg->remote_id));

		/* ctrl_ifname */
		if (msg->ctrl_ifname)
			json_object_object_add(jobj, "ctrl_ifname", json_object_new_string(msg->ctrl_ifname));

                /* nas_identifier */
                if (msg->nas_identifier)
                        json_object_object_add(jobj, "nas_identifier", json_object_new_string(msg->nas_identifier));

                if (msg->data)
			ap_construct_msg (msg->data, msg->len, jobj);

          // TODO: send msg to redis instance
		redisReply* reply;
		reply = redisCommand(ctx, "PUBLISH %s %s", ap_redis->pubchan, json_object_to_json_string(jobj));

		log_msg (" Redis PUBLISH: %s \n",json_object_to_json_string(jobj));
		if (reply) {
			// TODO
		}

		/* delete json object */
		json_object_put(jobj);

		/* release strings pointed to by message */
		if (msg->chan_name)
			free(msg->chan_name);
		if (msg->sessionid)
			free(msg->sessionid);
		if (msg->called_station_id)
			free(msg->called_station_id);
		if (msg->calling_station_id)
			free(msg->calling_station_id);
		if (msg->name)
			free(msg->name);
		if (msg->username)
			free(msg->username);
		if (msg->ip_addr)
			free(msg->ip_addr);
		if (msg->ctrl_ifname)
			free(msg->ctrl_ifname);
		if (msg->nas_identifier)
			free(msg->nas_identifier);
		if (msg->circuit_id)
			free(msg->circuit_id);
		if (msg->remote_id)
			free(msg->remote_id);

		mempool_free(msg);
	}

	spin_unlock(&ap_redis->msg_queue_lock);
}

void onMessage(redisAsyncContext * c, void *reply, void * privdata)
{
	int j;
	redisReply * r = reply;
	struct json_object* pppoe_id;
	struct json_object* ip_addr;
	struct json_object* ifname;
	struct json_object* packet;
	struct json_object* value;
	struct json_object* iftype;
	struct json_object *ipoe_xid;
	struct json_object *ipoe_sessionid;
	char sessionid[AP_SESSIONID_LEN+1];
	enum json_tokener_error error;
        struct ap_session_msg_t* msg = NULL;
	uint8_t pkt[1024];
	int exists, i, len, skip_len;
        int xid =0;

	if (reply == NULL) return;

	log_debug ("got a message of type: %i\n", r->type);

	if (r->type == REDIS_REPLY_ARRAY) {
		for (j = 0; j < r->elements; j++) {
			if (j !=2)
				continue;

			if (r->element[j]->str == NULL)
				continue;

			log_debug ("%u) %s\n", j, r->element[j]->str);

			json_object *jobj = json_tokener_parse_verbose(r->element[j]->str, &error);
			if (error != json_tokener_success) {
				printf("Parse error. \n");
				return;
			}

			json_object_object_get_ex (jobj, "ctrl_iftype", &iftype);
			if (strcmp (json_object_get_string(iftype), "pppoe") == 0)
			{
				json_object_object_get_ex (jobj, "pppoe_id", &pppoe_id);
				json_object_object_get_ex (jobj, "ip_addr", &ip_addr);
				json_object_object_get_ex (jobj, "ctrl_ifname", &ifname);

				msg = mempool_alloc(ap_redis->sub_pool);
				if (!msg) {
					log_error("ap_redis_enqueue: out of memory\n");
					return;
				}

				memset(msg, 0, sizeof(struct ap_session_msg_t));

				msg->pppoe_sessionid = json_object_get_int(pppoe_id);
				strcpy (msg->ip_addr, json_object_get_string(ip_addr));
				strcpy (msg->ifname, json_object_get_string(ifname));

				if (! pppoe_interface_find (msg->ifname)) {
					mempool_free(msg);
					return;
				}

				list_add_tail(&(msg->entry), &conn_list);

				triton_event_fire(EV_SES_5G_STARTED, msg);
			}
			else if (strcmp (json_object_get_string(iftype), "ipoe") == 0)
			{
				exists = json_object_object_get_ex(jobj, "packet", &packet);
				if (TRUE == exists)
				{
					memset (&pkt, 0, sizeof(pkt));

					/* Copying the packet length in first offset */
					len = json_object_array_length(packet);
					memcpy (&pkt, &len, sizeof(int));
					skip_len = sizeof(int);

					for (i = 0; i < json_object_array_length(packet); i++ )
					{
						value = json_object_array_get_idx(packet, i);
						pkt[i+skip_len] = (uint8_t) json_object_get_int(value);
					}

					triton_event_fire(EV_5G_DHCP_PKT_RCVD, &pkt);
				}
                                else
				{
					json_object_object_get_ex (jobj, "xid", &ipoe_xid);
				        json_object_object_get_ex (jobj, "session_id", &ipoe_sessionid);
				        strcpy (sessionid, json_object_get_string(ipoe_sessionid));

					xid = json_object_get_int (ipoe_xid);
					triton_event_fire (EV_SES_5G_REGISTERED, &sessionid);
				}
			}
		}
	}
}

static void* ap_redis_sub_thread(void* arg)
{
	struct event_base *base = event_base_new();

	if (!arg) {
		return NULL;
	}
	struct ap_redis_t* ap_sub_redis = (struct ap_redis_t*)arg;
	ap_sub_redis->sub_thread_exit_code = -1;
	/* establish connection to redis server */
	redisAsyncContext *ctx;
	ctx = redisAsyncConnect (ap_sub_redis->host, ap_sub_redis->port);
	if ((ctx == NULL) || (ctx->err)) {
		if (ctx) {
			log_error("ap_redis: redisAsyncConnect failed: (%s)\n", ctx->errstr);
		} else {
			log_error("ap_redis: failed to allocate redis context\n");
		}
		return &(ap_sub_redis->sub_thread_exit_code);
	}

	redisLibeventAttach(ctx, base);
	redisAsyncCommand(ctx, onMessage, NULL, "SUBSCRIBE accel-ppp-5g");
	event_base_dispatch(base);

	/* release redis context */
	redisAsyncFree(ctx);

	return &(ap_sub_redis->sub_thread_exit_code);
}

static void* ap_redis_thread(void* arg)
{
	uint64_t num = 1;
	int nbytes;

	if (!arg) {
	    return NULL;
	}
	struct ap_redis_t* ap_redis = (struct ap_redis_t*)arg;
	ap_redis->thread_exit_code = -1;

	/* establish connection to redis server */
	redisContext *ctx;
	ctx = redisConnect(ap_redis->host, ap_redis->port);
	if ((ctx == NULL) || (ctx->err)) {
		if (ctx) {
			log_error("ap_redis: redisConnect failed: (%s)\n", ctx->errstr);
		} else {
			log_error("ap_redis: failed to allocate redis context\n");
		}
		return &(ap_redis->thread_exit_code);
	}

	/* create epoll device */
	int epfd;
	if ((epfd = epoll_create(1)) < 0) {
		log_error("ap_redis: epoll_create failed: %d (%s)\n", errno, strerror(errno));
		return &(ap_redis->thread_exit_code);
	}

	/* add eventfd to epoll device */
	int rc;
	struct epoll_event epev[32];
	memset(epev, 0, sizeof(epev));
	epev[0].events = EPOLLIN;
	epev[0].data.fd = ap_redis->evfd;
	if ((rc = epoll_ctl(epfd, EPOLL_CTL_ADD, ap_redis->evfd, epev)) < 0) {
		log_error("ap_redis: epoll_ctl failed: %d (%s) exiting !!! \n", errno, strerror(errno));
		return &(ap_redis->thread_exit_code);
	}

	ap_redis->thread_exit_code = 0;
	ap_redis->flags |= REDIS_FLAG_BG_THREAD_IS_RUNNING;
	ap_redis->flags |= REDIS_FLAG_KEEP_BG_THREAD_RUNNING;

	while (ap_redis->flags & REDIS_FLAG_KEEP_BG_THREAD_RUNNING) {

		if ((rc = epoll_wait(epfd, epev, 32, /*timeout=*/10)) == 0) {
			/* no events, just loop and continue waiting */
			continue;
		} else if (rc == -1) {
			/* log error event, loop and continue waiting */
			continue;
		}

		for (unsigned int i = 0; i < 32; i++) {
		    if (epev[i].data.fd == ap_redis->evfd) {
			if ((nbytes = read(ap_redis->evfd, &num, sizeof(num))) != sizeof(num)) {
			    log_error("ap_redis: failed to read event via eventfd\n");
			}
			ap_redis_dequeue(ap_redis, ctx);
		    }
		}
	}


	ap_redis->flags &= ~REDIS_FLAG_BG_THREAD_IS_RUNNING;

	/* close epoll device */
	close(epfd);

	/* release redis context */
	redisFree(ctx);

	return &(ap_redis->thread_exit_code);
}


static void ap_redis_init(struct ap_redis_t *ap_redis)
{
	spinlock_init(&ap_redis->msg_queue_lock);
	INIT_LIST_HEAD(&ap_redis->msg_queue);
	ap_redis->thread = (pthread_t)0;
	ap_redis->thread_exit_code = 0;
	ap_redis->flags = 0;
	ap_redis->pathname = NULL;
	ap_redis->events = (REDIS_EV_SES_AUTHORIZED | REDIS_EV_SES_PRE_FINISHED);
	ap_redis->msg_pool = mempool_create(sizeof(struct ap_redis_msg_t));

	if (NULL == ap_redis->msg_pool) {
		log_error("ap_redis: mempool creation failed\n");
		return;
	}
	memset(ap_redis->msg_pool, 0, sizeof(*(ap_redis->msg_pool)));

	ap_redis->sub_pool = mempool_create(sizeof(struct ap_session_msg_t));
	if (NULL == ap_redis->sub_pool) {
		log_error("ap_redis: mempool creation failed\n");
		return;
	}
	memset(ap_redis->sub_pool, 0, sizeof(*(ap_redis->sub_pool)));
	INIT_LIST_HEAD(&conn_list);


}

static int ap_redis_open(struct ap_redis_t *ap_redis)
{
	char* opt;

	if ((ap_redis->evfd = eventfd(0, 0)) < 0) {
		log_error("ap_redis: eventfd failed: %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	ap_redis->events = 0;

// inserting the nas-identifier from the radius section of accel-ppp.conf
	if (((opt = conf_get_opt("radius", "nas-identifier")) != NULL))
		ap_redis->nas_id = _strdup(opt);
	else
		ap_redis->nas_id = _strdup(DEFAULT_NAS_ID);

	if (((opt = conf_get_opt("redis", "host")) != NULL))
		ap_redis->host = _strdup(opt);
	else
		ap_redis->host = _strdup(DEFAULT_REDIS_HOST);
	if (((opt = conf_get_opt("redis", "port")) != NULL))
		ap_redis->port = strtol(opt, NULL, 0);
	else
		ap_redis->port = DEFAULT_REDIS_PORT;
	if (((opt = conf_get_opt("redis", "pubchan")) != NULL))
		ap_redis->pubchan = _strdup(opt);
	else
		ap_redis->pubchan = _strdup(DEFAULT_REDIS_PUBCHAN);

	if (((opt = conf_get_opt("redis", "subchan")) != NULL))
		ap_redis->subchan = _strdup(opt);
	else
		ap_redis->subchan = _strdup(DEFAULT_REDIS_SUBCHAN);

	if (((opt = conf_get_opt("redis", "ev_ses_starting")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_STARTING;
	if (((opt = conf_get_opt("redis", "ev_ses_finishing")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_FINISHING;
	if (((opt = conf_get_opt("redis", "ev_ses_finished")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_FINISHED;
	if (((opt = conf_get_opt("redis", "ev_ses_authorized")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_AUTHORIZED;
	if (((opt = conf_get_opt("redis", "ev_ctrl_starting")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_CTRL_STARTING;
	if (((opt = conf_get_opt("redis", "ev_ctrl_started")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_CTRL_STARTED;
	if (((opt = conf_get_opt("redis", "ev_ctrl_finished")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_CTRL_FINISHED;
	if (((opt = conf_get_opt("redis", "ev_ses_pre_up")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_PRE_UP;
	if (((opt = conf_get_opt("redis", "ev_ses_acct_start")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_ACCT_START;
	if (((opt = conf_get_opt("redis", "ev_config_reload")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_CONFIG_RELOAD;
	if (((opt = conf_get_opt("redis", "ev_ses_auth_failed")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_AUTH_FAILED;
	if (((opt = conf_get_opt("redis", "ev_ses_pre_finished")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_PRE_FINISHED;
	if (((opt = conf_get_opt("redis", "ev_ip_changed")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_IP_CHANGED;
	if (((opt = conf_get_opt("redis", "ev_shaper")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SHAPER;
	if (((opt = conf_get_opt("redis", "ev_mppe_keys")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_MPPE_KEYS;
	if (((opt = conf_get_opt("redis", "ev_dns")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_DNS;
	if (((opt = conf_get_opt("redis", "ev_wins")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_WINS;
	if (((opt = conf_get_opt("redis", "ev_force_interim_update")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_FORCE_INTERIM_UPDATE;
	if (((opt = conf_get_opt("redis", "ev_radius_access_accept")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_RADIUS_ACCESS_ACCEPT;
	if (((opt = conf_get_opt("redis", "ev_radius_coa")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_RADIUS_COA;
	if (((opt = conf_get_opt("redis", "ev_5g_registration")) != NULL) && (strcmp(opt, "yes") == 0))
	{
		ap_redis->events |= REDIS_EV_5G_REGISTRATION;
		ap_redis->events |= REDIS_EV_5G_DEREGISTRATION;
		ap_redis->events |= REDIS_EV_5G_PACKET;
	}

	if (pthread_create(&(ap_redis->thread), NULL, &ap_redis_thread, ap_redis) < 0) {
		log_emerg("ap_redis: unable to create background thread %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	if (pthread_create(&(ap_redis->sub_thread), NULL, &ap_redis_sub_thread, ap_redis) < 0) {
		log_emerg("ap_redis: unable to create background thread %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}


static void ap_redis_enqueue(struct ap_session *ses, const int event)
{
	char tmp_addr[128];
	uint64_t num = 1;
	int nbytes;

	/* redis background thread not running? => return */
	if (!(ap_redis->flags & REDIS_FLAG_BG_THREAD_IS_RUNNING)) {
		return;
	}

	switch (event) {
	case REDIS_EV_SES_STARTING:
	case REDIS_EV_SES_STARTED:
	case REDIS_EV_SES_FINISHING:
	case REDIS_EV_SES_FINISHED:
	case REDIS_EV_SES_AUTHORIZED:
	case REDIS_EV_CTRL_STARTING:
	case REDIS_EV_CTRL_STARTED:
	case REDIS_EV_CTRL_FINISHED:
	case REDIS_EV_SES_PRE_UP:
	case REDIS_EV_SES_ACCT_START:
	case REDIS_EV_CONFIG_RELOAD:
	case REDIS_EV_SES_AUTH_FAILED:
	case REDIS_EV_SES_PRE_FINISHED:
	case REDIS_EV_IP_CHANGED:
	case REDIS_EV_SHAPER:
	case REDIS_EV_MPPE_KEYS:
	case REDIS_EV_DNS:
	case REDIS_EV_WINS:
	case REDIS_EV_FORCE_INTERIM_UPDATE:
	case REDIS_EV_RADIUS_ACCESS_ACCEPT:
	case REDIS_EV_RADIUS_COA: 
	case REDIS_EV_5G_REGISTRATION:
        case REDIS_EV_5G_DEREGISTRATION:
        case REDIS_EV_5G_PACKET:{
		/* do nothing */
	} break;
	default: {
		return;
	};
	}

	struct ap_redis_msg_t* msg = mempool_alloc(ap_redis->msg_pool);
	if (!msg) {
		log_error("ap_redis_enqueue: out of memory\n");
		return;
	}
	memset(msg, 0, sizeof(*msg));

	/* get IP address*/
	memset(tmp_addr, 0, sizeof(tmp_addr));
	if (ses && ses->ipv4 && ses->ipv4->peer_addr) {
		u_inet_ntoa(ses->ipv4->peer_addr,tmp_addr);
	}

	msg->event = event;
	if (ses->chan_name)
		msg->chan_name = _strdup(ses->chan_name);
	if (ses->sessionid)
		msg->sessionid = _strdup(ses->sessionid);
	if (ses->ctrl->called_station_id)
		msg->called_station_id = _strdup(ses->ctrl->called_station_id);
	if (ses->ctrl->calling_station_id)
		msg->calling_station_id = _strdup(ses->ctrl->calling_station_id);
	if (ses->ctrl->name)
		msg->name = _strdup(ses->ctrl->name);
	if (ses->username)
		msg->username = _strdup(ses->username);
        if (ses->xid)
                msg->xid = ses->xid;
	if (ses->conn_pppoe_sid)
		msg->pppoe_sessionid = ses->conn_pppoe_sid;
	if (ses->circuit_id)
		msg->circuit_id = _strdup(ses->circuit_id);
	if (ses->remote_id)
		msg->remote_id = _strdup(ses->remote_id);
	if (ses->ctrl->ifname)
		msg->ctrl_ifname = _strdup(ses->ctrl->ifname);

	if (msg->event == REDIS_EV_5G_PACKET){
		if (ses->giaddr)
			msg->giaddr = ses->giaddr;
		if (ses->siaddr)
			msg->siaddr = ses->siaddr;
	}

    	msg->ip_addr = _strdup(tmp_addr);
	msg->nas_identifier = _strdup(ap_redis->nas_id);

	if (ses->data)
	{
		memcpy (msg->data, ses->data, ses->len);
		msg->len = ses->len;
	}

	switch(ses->ctrl->type) {
	case CTRL_TYPE_PPTP:    msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_PPTP;    break;
	case CTRL_TYPE_L2TP:    msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_L2TP;    break;
	case CTRL_TYPE_PPPOE:   msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_PPPOE;   break;
	case CTRL_TYPE_IPOE:    msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_IPOE;    break;
	case CTRL_TYPE_OPENVPN: msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_OPENVPN; break;
	case CTRL_TYPE_SSTP:    msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_SSTP;    break;
	default:{
	}
	}

	spin_lock(&ap_redis->msg_queue_lock);
	list_add_tail(&(msg->entry), &(ap_redis->msg_queue));
	spin_unlock(&ap_redis->msg_queue_lock);

	/* notify redis background thread */
	if ((nbytes = write(ap_redis->evfd, &num, sizeof(num))) != sizeof(num)) {
		log_error("ap_redis_enqueue: failed to send event via eventfd\n");
	}
}

static void ev_ses_starting(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_STARTING);
}

static void ev_ses_started(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_STARTED);
}

static void ev_ses_finishing(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_FINISHING);
}

static void ev_ses_finished(struct ap_session *ses)
{
	struct ap_session_msg_t* msg = NULL; 

	if (ap_redis->events & REDIS_EV_5G_REGISTRATION)
	{
		list_for_each_entry(msg, &conn_list, entry) {
			if(ses->conn_pppoe_sid == msg->pppoe_sessionid)
			{
				list_del(&msg->entry);
				mempool_free(msg);
				break;
			}
		}
	}

	ap_redis_enqueue(ses, REDIS_EV_SES_FINISHED);
}

static void ev_ses_authorized(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_AUTHORIZED);
}

static void ev_ctrl_starting(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_CTRL_STARTING);
}

static void ev_ctrl_started(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_CTRL_STARTED);
}

static void ev_ctrl_finished(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_CTRL_FINISHED);
}

static void ev_ses_pre_up(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_PRE_UP);
}

static void ev_ses_acct_start(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_ACCT_START);
}

static void ev_ses_auth_failed(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_AUTH_FAILED);
}

static void ev_ses_pre_finished(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_PRE_FINISHED);
}

static void ev_radius_access_accept(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_RADIUS_ACCESS_ACCEPT);
}

static void ev_radius_coa(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_RADIUS_COA);
}

static void ev_5g_registration(struct ap_session *ses)
{
       ap_redis_enqueue(ses, REDIS_EV_5G_REGISTRATION);
}

static void ev_5g_deregistration(struct ap_session *ses)
{
       ap_redis_enqueue(ses, REDIS_EV_5G_DEREGISTRATION);
}

static void ev_5g_packet(struct ap_session *ses)
{
       ap_redis_enqueue(ses, REDIS_EV_5G_PACKET);
}

static void init(void)
{
	redis_pool = mempool_create(sizeof(struct ap_redis_t));

	ap_redis = mempool_alloc(redis_pool);
	if (NULL == ap_redis) {
		log_error("ap_redis_init: out of memory\n");
		return;
	}
	memset(ap_redis, 0, sizeof(struct ap_redis_t));

	ap_redis_init(ap_redis);

	if (ap_redis_open(ap_redis)) {
		free(ap_redis);
		_exit(EXIT_FAILURE);
	}

	if (ap_redis->events & REDIS_EV_SES_STARTING)
		triton_event_register_handler(EV_SES_STARTING, (triton_event_func)ev_ses_starting);
	if (ap_redis->events & REDIS_EV_SES_STARTED)
	        triton_event_register_handler(EV_SES_STARTED, (triton_event_func)ev_ses_started);
	if (ap_redis->events & REDIS_EV_SES_FINISHING)
		triton_event_register_handler(EV_SES_FINISHING, (triton_event_func)ev_ses_finishing);
	if (ap_redis->events & REDIS_EV_SES_FINISHED)
		triton_event_register_handler(EV_SES_FINISHED, (triton_event_func)ev_ses_finished);
	if (ap_redis->events & REDIS_EV_SES_AUTHORIZED)
		triton_event_register_handler(EV_SES_AUTHORIZED, (triton_event_func)ev_ses_authorized);
	if (ap_redis->events & REDIS_EV_CTRL_STARTING)
		triton_event_register_handler(EV_CTRL_STARTING, (triton_event_func)ev_ctrl_starting);
	if (ap_redis->events & REDIS_EV_CTRL_STARTED)
		triton_event_register_handler(EV_CTRL_STARTED, (triton_event_func)ev_ctrl_started);
	if (ap_redis->events & REDIS_EV_CTRL_FINISHED)
		triton_event_register_handler(EV_CTRL_FINISHED, (triton_event_func)ev_ctrl_finished);
	if (ap_redis->events & REDIS_EV_SES_PRE_UP)
		triton_event_register_handler(EV_SES_PRE_UP, (triton_event_func)ev_ses_pre_up);
	if (ap_redis->events & REDIS_EV_SES_ACCT_START)
		triton_event_register_handler(EV_SES_ACCT_START, (triton_event_func)ev_ses_acct_start);
	if (ap_redis->events & REDIS_EV_SES_AUTH_FAILED)
		triton_event_register_handler(EV_SES_AUTH_FAILED, (triton_event_func)ev_ses_auth_failed);
	if (ap_redis->events & REDIS_EV_SES_PRE_FINISHED)
		triton_event_register_handler(EV_SES_PRE_FINISHED, (triton_event_func)ev_ses_pre_finished);
	if (ap_redis->events & REDIS_EV_RADIUS_ACCESS_ACCEPT)
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
	if (ap_redis->events & REDIS_EV_RADIUS_COA)
		triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
	if (ap_redis->events & REDIS_EV_5G_REGISTRATION)
		triton_event_register_handler(EV_5G_REGISTRATION, (triton_event_func)ev_5g_registration);
	if (ap_redis->events & REDIS_EV_5G_DEREGISTRATION)
	        triton_event_register_handler (EV_5G_DEREGISTRATION, (triton_event_func) ev_5g_deregistration);
	if (ap_redis->events & REDIS_EV_5G_PACKET)
	        triton_event_register_handler (EV_5G_PACKET, (triton_event_func) ev_5g_packet);


}



DEFINE_INIT(1, init);
