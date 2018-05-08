/**
 * @file sr_uci.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for parse.c.
 *
 * @copyright
 * Copyright (C) 2018 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SR_UCI_H
#define SR_UCI_H

#include <sysrepo.h>
#include "sysrepo/plugins.h"

#ifdef PLUGIN
#define ERR(MSG, ...) SRP_LOG_ERR(MSG, ...)
#define ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG)
#define WRN(MSG, ...) define SRP_LOG_WRN(MSG, ...)
#define WRN_MSG(MSG) define SRP_LOG_WRN_MSG(MSG)
#define INF(MSG, ...) SRP_LOG_INF(MSG, ...)
#define INF_MSG(MSG) SRP_LOG_INF_MSG(MSG)
#define DBG(MSG, ...) SRP_LOG_DBG(MSG, ...)
#define DBG_MSG(MSG) SRP_LOG_DBG_MSG(MSG)
#else
#define ERR(MSG, ...) SRP_LOG__STDERR(SR_LL_ERR, MSG, __VA_ARGS__)
#define ERR_MSG(MSG) SRP_LOG__STDERR(SR_LL_ERR, MSG "%s", "")
#define WRN(MSG, ...) SRP_LOG__STDERR(SR_LL_WRN, MSG, __VA_ARGS__)
#define WRN_MSG(MSG) SRP_LOG__STDERR(SR_LL_WRN, MSG "%s", "")
#define INF(MSG, ...) SRP_LOG__STDERR(SR_LL_INF, MSG, __VA_ARGS__)
#define INF_MSG(MSG) SRP_LOG__STDERR(SR_LL_INF, MSG "%s", "")
#define DBG(MSG, ...) SRP_LOG__STDERR(SR_LL_DBG, MSG, __VA_ARGS__)
#define DBG_MSG(MSG) SRP_LOG__STDERR(SR_LL_DBG, MSG "%s", "")
#endif

#define CHECK_RET_MSG(RET, LABEL, MSG)\
	do {\
		if (SR_ERR_OK != RET) {\
			ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG);\
			goto LABEL;\
		}\
	} while (0)

#define CHECK_RET(RET, LABEL, MSG, ...)\
	do {\
		if (SR_ERR_OK != RET) {\
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);\
			goto LABEL;\
		}\
	} while (0)

#define CHECK_NULL_MSG(VALUE, RET, LABEL, MSG)\
	do {\
		if (NULL == VALUE) {\
			*RET = SR_ERR_NOMEM;\
			ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG);\
			goto LABEL;\
		}\
	} while (0)

#define CHECK_NULL(VALUE, RET, LABEL, MSG, ...)\
	do {\
		if (NULL == VALUE) {\
			*RET = SR_ERR_NOMEM;\
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);\
			goto LABEL;\
		}\
	} while (0)

#define UCI_CHECK_RET_MSG(UCI_RET, SR_RET, LABEL, MSG)\
	do {\
		if (UCI_OK != UCI_RET) {\
			ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG);\
            *SR_RET = SR_ERR_INTERNAL;\
            goto LABEL;\
		}\
	} while (0)

#define UCI_CHECK_RET(UCI_RET, SR_RET, LABEL, MSG, ...)\
	do {\
		if (UCI_OK != UCI_RET) {\
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);\
            *SR_RET = SR_ERR_INTERNAL;\
			goto LABEL;\
		}\
	} while (0)

#define UCI_CHECK_ITEM(VALUE, RET, LABEL, MSG, ...)\
	do {\
		if (NULL == VALUE) {\
			*RET = SR_ERR_NOT_FOUND;\
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);\
			goto LABEL;\
		}\
	} while (0)


typedef struct sr_uci_mapping_s sr_uci_mapping_t;

typedef struct sr_ctx_s {
    const char *yang_model;
    const char *config_file;
    struct uci_context *uctx;
    struct uci_package *package;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
    sr_conn_ctx_t *startup_conn;
    sr_session_ctx_t *startup_sess;
    sr_uci_mapping_t *map;
    int map_size;
    void *data; //private data
    const char *uci_sections[];
} sr_ctx_t;

int uci_del(sr_ctx_t *, const char *);
int set_uci_section(sr_ctx_t *, char *);
int get_uci_item(struct uci_context *, char *, char **);
int set_uci_item(struct uci_context *, char *, char *);

typedef int (*sr_callback) (sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, char *, char *);
typedef int (*uci_callback) (sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);
/* additinonal check */
typedef bool (*check_callback) (sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);

/* Configuration part of the plugin. */
struct sr_uci_mapping_s {
    sr_callback sr_cb;
    uci_callback uci_cb;
    check_callback check_cb;
    char *ucipath;
    char *xpath;
};

/* sysrepo callback for containers/groupings */
int sr_section_cb(sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, char *, char *);
/* sysrepo callback for leaf's */
int sr_option_cb(sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, char *, char *);
/* sysrepo callback for boolean values */
int sr_boolean_cb(sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, char *, char *);
/* sysrepo callback for inverse boolean values, true in sysrepo is false in UCI */
int sr_boolean_reverse_cb(sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, char *, char *);
/* sysrepo callback for list's */
int sr_list_cb(sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, char *, char *);

int uci_section_cb(sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);
int uci_boolean_cb(sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);
int uci_boolean_reverse_cb(sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);
int uci_option_cb(sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);
int uci_list_cb(sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);

int sync_datastores(sr_ctx_t *);
int load_startup_datastore(sr_ctx_t *);
void sr_uci_free_context(sr_ctx_t *);
int sr_uci_init_data(sr_ctx_t *, const char *, const char *[]);
int sysrepo_to_uci(sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, sr_notif_event_t);
int fill_state_data(sr_ctx_t *, char *, sr_val_t **, size_t *);

typedef struct sr_values_s {
    sr_ctx_t *ctx;
    sr_val_t **values;
    size_t *values_cnt;
} sr_values_t;

#endif /* SR_UCI_H */
