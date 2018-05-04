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

#define ARR_SIZE(a) sizeof a / sizeof a[0]

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

#define CHECK_RET_MSG(RET, LABEL, MSG)                                                                                                               \
	do {                                                                                                                                             \
		if (SR_ERR_OK != RET) {                                                                                                                      \
			ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG);                                                                                                       \
			goto LABEL;                                                                                                                              \
		}                                                                                                                                            \
	} while (0)

#define CHECK_RET(RET, LABEL, MSG, ...)                                                                                                              \
	do {                                                                                                                                             \
		if (SR_ERR_OK != RET) {                                                                                                                      \
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);                                                                                     \
			goto LABEL;                                                                                                                              \
		}                                                                                                                                            \
	} while (0)

#define CHECK_NULL_MSG(VALUE, RET, LABEL, MSG)                                                                                                       \
	do {                                                                                                                                             \
		if (NULL == VALUE) {                                                                                                                         \
			*RET = SR_ERR_NOMEM;                                                                                                                     \
			ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG);                                                                                                       \
			goto LABEL;                                                                                                                              \
		}                                                                                                                                            \
	} while (0)

#define CHECK_NULL(VALUE, RET, LABEL, MSG, ...)                                                                                                      \
	do {                                                                                                                                             \
		if (NULL == VALUE) {                                                                                                                         \
			*RET = SR_ERR_NOMEM;                                                                                                                     \
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);                                                                                     \
			goto LABEL;                                                                                                                              \
		}                                                                                                                                            \
	} while (0)

#define UCI_CHECK_RET_MSG(UCI_RET, SR_RET, LABEL, MSG)                                                                                               \
	do {                                                                                                                                             \
		if (UCI_OK != UCI_RET) {                                                                                                                     \
			ERR_MSG(MSG) SRP_LOG_ERR_MSG(MSG);                                                                                                       \
            *SR_RET = SR_ERR_INTERNAL;                                                                                                               \
            goto LABEL;                                                                                                                              \
		}                                                                                                                                            \
	} while (0)

#define UCI_CHECK_RET(UCI_RET, SR_RET, LABEL, MSG, ...)                                                                                              \
	do {                                                                                                                                             \
		if (UCI_OK != UCI_RET) {                                                                                                                     \
			ERR(MSG, __VA_ARGS__) SRP_LOG_ERR(MSG, __VA_ARGS__);                                                                                     \
            *SR_RET = SR_ERR_INTERNAL;                                                                                                               \
			goto LABEL;                                                                                                                              \
		}                                                                                                                                            \
	} while (0)


struct sr_uci_mapping;

typedef struct sr_ctx_s {
    const char *yang_model;
    const char *config_file;
    struct uci_context *uctx;
    struct uci_package *package;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
    sr_conn_ctx_t *startup_conn;
    sr_session_ctx_t *startup_sess;
    void *data; //private data
    struct sr_uci_mapping *map;
    const char *uci_sections[];
} sr_ctx_t;

typedef int (*sr_callback) (sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, sr_notif_event_t, void *);
typedef int (*uci_callback) (sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);

/* Configuration part of the plugin. */
struct sr_uci_mapping {
    uci_callback uci_callback;
    sr_callback sr_callback;
    char *ucipath;
    char *xpath;
};

int sync_datastores(sr_ctx_t *);
int load_startup_datastore(sr_ctx_t *);
int sysrepo_to_uci(sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, sr_notif_event_t);
int fill_state_data(sr_ctx_t *, char *, sr_val_t **, size_t *);

typedef struct sr_values_s {
    sr_ctx_t *ctx;
    sr_val_t **values;
    size_t *values_cnt;
} sr_values_t;

#endif /* SR_UCI_H */
