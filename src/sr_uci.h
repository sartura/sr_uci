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

struct sr_uci_mapping;

typedef struct ctx_s {
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
} ctx_t;

typedef int (*sr_callback) (ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, sr_notif_event_t, void *);
typedef int (*uci_callback) (ctx_t *, char *, char *, void *, sr_edit_flag_t, void *);

/* Configuration part of the plugin. */
struct sr_uci_mapping {
    uci_callback uci_callback;
    sr_callback sr_callback;
    char *default_value;
    char *ucipath;
    char *xpath;
};

int sync_datastores(ctx_t *ctx);
int load_startup_datastore(ctx_t *ctx);
int sysrepo_to_uci(ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, sr_notif_event_t event);
int fill_state_data(ctx_t *ctx, char *xpath, sr_val_t **values, size_t *values_cnt);

typedef struct ubus_ctx_s {
    ctx_t *ctx;
    sr_val_t **values;
    size_t *values_cnt;
} ubus_ctx_t;

#endif /* SR_UCI_H */
