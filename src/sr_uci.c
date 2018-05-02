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

#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uci.h>
#include <sysrepo.h>
#include <sysrepo/plugins.h>
#include <sysrepo/xpath.h>
#include <sysrepo/values.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "sr_uci.h"
#include "common.h"

int uci_del(sr_ctx_t *ctx, const char *uci)
{
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr = {};

    uci_ret = uci_lookup_ptr(ctx->uctx, &ptr, (char *) uci, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_lookup_ptr %d, path %s", rc, uci);

    uci_ret = uci_delete(ctx->uctx, &ptr);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d, path %s", rc, uci);

    uci_ret = uci_save(ctx->uctx, ptr.p);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "UCI save error %d, path %s", rc, uci);

    uci_ret = uci_commit(ctx->uctx, &ptr.p, 1);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "UCI commit error %d, path %s", rc, uci);

cleanup:

    return rc;
}

int set_uci_section(sr_ctx_t *ctx, char *uci)
{
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr = {0};

    uci_ret = uci_lookup_ptr(ctx->uctx, &ptr, (char *) uci, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_lookup_ptr %d, path %s", rc, uci);

    uci_ret = uci_set(ctx->uctx, &ptr);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d, path %s", rc, uci);

    uci_ret = uci_save(ctx->uctx, ptr.p);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "UCI save error %d, path %s", rc, uci);

    uci_ret = uci_commit(ctx->uctx, &ptr.p, 1);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "UCI commit error %d, path %s", rc, uci);

cleanup:
    return rc;
}

int get_uci_item(struct uci_context *uctx, char *ucipath, char **value)
{
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr;

    char *path = malloc(sizeof(char) * (strlen(ucipath) + 1));
    CHECK_NULL(path, &rc, cleanup, "malloc %s", ucipath);
    sprintf(path, "%s", ucipath);

    uci_ret = uci_lookup_ptr(uctx, &ptr, path, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", rc, path);
    CHECK_NULL(ptr.o, &rc, cleanup, "Uci item %s not found", ucipath);
    CHECK_NULL(ptr.o->v.string, &rc, cleanup, "Uci item %s not found", ucipath);

    *value = strdup(ptr.o->v.string);
    CHECK_NULL(*value, &rc, cleanup, "strdup failed for %s", ucipath);

cleanup:
    if (NULL != path) {
        free(path);
    }
    return rc;
}

int set_uci_item(struct uci_context *uctx, char *ucipath, char *value)
{
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr;

    char *path = malloc(sizeof(char) * (strlen(ucipath) + strlen(value) + 2));
    CHECK_NULL_MSG(path, &rc, cleanup, "malloc failed");

    sprintf(path, "%s%s%s", ucipath, "=", value);

    uci_ret = uci_lookup_ptr(uctx, &ptr, path, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", rc, path);

    uci_ret = uci_set(uctx, &ptr);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d %s", rc, path);

    uci_ret = uci_save(uctx, ptr.p);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_save %d %s", rc, path);

    uci_ret = uci_commit(uctx, &(ptr.p), false);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_commit %d %s", rc, path);

cleanup:
    if (NULL != path) {
        free(path);
    }
    return rc;
}

void del_path_key(char **value) {
    if (NULL == *value) {
        return;
    }
    free(*value);
    *value = NULL;
}

char *new_path_key(char *path, char *key) {
    int rc = SR_ERR_OK;
    char *value = NULL;
    int len = 0;

    CHECK_NULL_MSG(path, &rc, cleanup, "missing parameter path");
    CHECK_NULL_MSG(key, &rc, cleanup, "missing parameter key");

    len = strlen(key) + strlen(path);

    value = malloc(sizeof(char) * len);
    CHECK_NULL_MSG(value, &rc, cleanup, "failed malloc");

    snprintf(value, len, path, key);

cleanup:
    return value;
}

char *get_key_value(char *orig_xpath)
{
    char *key = NULL, *node = NULL;
    sr_xpath_ctx_t state = {0, 0, 0, 0};

    node = sr_xpath_next_node(orig_xpath, &state);
    if (NULL == node) {
        goto error;
    }
    while (true) {
        key = sr_xpath_next_key_name(NULL, &state);
        if (NULL != key) {
            key = strdup(sr_xpath_next_key_value(NULL, &state));
            break;
        }
        node = sr_xpath_next_node(NULL, &state);
        if (NULL == node) {
            break;
        }
    }

error:
    sr_xpath_recover(&state);
    return key;
}

int sysrepo_option_callback(sr_ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        char *mem = sr_val_to_str(val);
        CHECK_NULL(mem, &rc, cleanup, "sr_print_val %s", sr_strerror(rc));
        rc = set_uci_item(ctx->uctx, ucipath, mem);
        free(mem);
        CHECK_RET(rc, cleanup, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        CHECK_RET(rc, cleanup, "uci_del %d", rc);
    }

cleanup:
    return rc;
}

int sysrepo_boolean_callback(sr_ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        if (val->data.bool_val) {
            rc = set_uci_item(ctx->uctx, ucipath, "1");
        } else {
            rc = set_uci_item(ctx->uctx, ucipath, "0");
        }
        CHECK_RET(rc, cleanup, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        CHECK_RET(rc, cleanup, "uci_del %d", rc);
    }

cleanup:
    return rc;
}

int sysrepo_section_callback(sr_ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        sprintf(ucipath, "%s.%s=%s", ctx->config_file, key, "TODO");
        rc = set_uci_section(ctx, ucipath);
        CHECK_RET(rc, cleanup, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        CHECK_RET(rc, cleanup, "uci_del %d", rc);
    }

cleanup:
    return rc;
}

int sysrepo_list_callback(sr_ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    size_t count = 0;
    sr_val_t *values = NULL;
    struct uci_ptr ptr = {};
    char set_path[XPATH_MAX_LEN] = {0};

    uci_ret = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_lookup_ptr %d, path %s", rc, ucipath);
    if (NULL != ptr.o) {
        /* remove the UCI list first */
        uci_ret = uci_delete(ctx->uctx, &ptr);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_delete %d, path %s", rc, ucipath);
    }

    /* get all list instances */
    rc = sr_get_items(ctx->sess, xpath, &values, &count);
    CHECK_RET(rc, cleanup, "failed sr_get_items: %s", sr_strerror(rc));

    for (size_t i = 0; i<count; i++){
        sprintf(set_path, "%s%s%s", ucipath, "=", values[i].data.string_val);

        uci_ret = uci_lookup_ptr(ctx->uctx, &ptr, set_path, true);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", rc, set_path);

        uci_ret = uci_add_list(ctx->uctx, &ptr);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d %s", rc, set_path);

        uci_ret = uci_save(ctx->uctx, ptr.p);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_save %d %s", rc, set_path);

        uci_ret = uci_commit(ctx->uctx, &(ptr.p), false);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_commit %d %s", rc, set_path);
    }

cleanup:
    if (NULL != values && 0 != count) {
        sr_free_values(values, count);
    }
    return rc;
}

int sysrepo_list_callback_enable(sr_ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr = {};

    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        if (false == val->data.bool_val) {
            uci_ret = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
            UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_lookup_ptr %d, path %s", rc, ucipath);
            if (NULL != ptr.o) {
                /* remove the UCI list first */
                rc = uci_delete(ctx->uctx, &ptr);
                UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_delete %d, path %s", rc, ucipath);

                rc = uci_save(ctx->uctx, ptr.p);
                UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_save %d %s", rc, ucipath);

                rc = uci_commit(ctx->uctx, &(ptr.p), false);
                UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_commit %d %s", rc, ucipath);
            }
        } else {
            return sysrepo_list_callback(ctx, op, xpath, "voice_client.direct_dial.direct_dial", key, val); 
        }
    } else if (SR_OP_DELETED == op) {
        //TODO
    }

cleanup:
    return rc;
}

void
transform_orig_bool_value(sr_ctx_t *ctx, char **uci_val)
{
    if (0 == strncmp("0", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    } else if (0 == strncmp("off", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    } else if (0 == strncmp("no", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    } else if (0 == strncmp("1", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    } else if (0 == strncmp("on", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    } else if (0 == strncmp("yes", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    }
}

bool string_eq(char *first, char *second)
{
    if (0 == strcmp(first, second) && (strlen(first) == strlen(second))) {
        return true;
    } else {
        return false;
    }
}

static int parse_uci_config(sr_ctx_t *ctx,  char *key)
{
    char *xpath = NULL;
    char *ucipath = NULL;
    int rc = SR_ERR_OK;

    const int n_mappings = ARR_SIZE(ctx->map);
    for (int i = 0; i < n_mappings; i++) {
        char *uci_val = NULL;
        xpath = new_path_key(ctx->map[i].xpath, key);
        CHECK_NULL_MSG(xpath, &rc, cleanup, "failed to generate path");
        ucipath = new_path_key(ctx->map[i].ucipath, key);
        CHECK_NULL_MSG(xpath, &rc, cleanup, "failed to generate path");
        //TODO implement function callback
        rc = get_uci_item(ctx->uctx, ucipath, &uci_val);
        if (UCI_OK == rc) {
            INF("%s : %s", xpath, uci_val);
            rc = sr_set_item_str(ctx->startup_sess, xpath, uci_val, SR_EDIT_DEFAULT);
            free(uci_val);
            CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
        }
        del_path_key(&xpath);
        del_path_key(&ucipath);
    }

cleanup:
    del_path_key(&xpath);
    del_path_key(&ucipath);

    return rc;
}

static int parse_uci_config_list(sr_ctx_t *ctx)
{
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_option *o;
    struct uci_element *el = NULL;
    struct uci_ptr ptr = {};
    char ucipath[] = "UCIPATH";
    char xpath[] = "XPATH";

    uci_ret = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_lookup_ptr %d, path %s", rc, ucipath);
    CHECK_NULL(ptr.o, &rc, cleanup, "ptr.o %s", ucipath);

    uci_foreach_element(&ptr.o->v.list, el) {
        o = uci_to_option(el);
        CHECK_NULL(o, &rc, cleanup, "uci option %s", ucipath);
        CHECK_NULL(o->e.name, &rc, cleanup, "uci option %s", ucipath);
        rc = sr_set_item_str(ctx->startup_sess, xpath, o->e.name, SR_EDIT_DEFAULT);
        CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
    }

cleanup:
    return rc;
}

int sysrepo_to_uci(sr_ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, sr_notif_event_t event)
{
    char *xpath = NULL;
    char *ucipath = NULL;
    char *orig_xpath = NULL;
    char *key = NULL;
    int rc = SR_ERR_OK;

    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        orig_xpath = new_val->xpath;
    } else if (SR_OP_DELETED == op) {
        orig_xpath = old_val->xpath;
    } else {
        return rc;
    }

    key = get_key_value(orig_xpath);
    CHECK_NULL(xpath, &rc, cleanup, "failed to get key from path %s", orig_xpath);

    /* add/change leafs */
    const int n_mappings = ARR_SIZE(ctx->map);
    for (int i = 0; i < n_mappings; i++) {
        xpath = new_path_key(ctx->map[i].xpath, key);
        CHECK_NULL_MSG(xpath, &rc, cleanup, "failed to generate path");
        ucipath = new_path_key(ctx->map[i].ucipath, key);
        CHECK_NULL_MSG(xpath, &rc, cleanup, "failed to generate path");
        if (string_eq(xpath, orig_xpath)) {
            rc = ctx->map[i].sr_callback(ctx, op, old_val, new_val, event, NULL);
            CHECK_RET(rc, cleanup, "failed sysrepo operation %s", sr_strerror(rc));
        }
        del_path_key(&xpath);
        del_path_key(&ucipath);
    }

cleanup:
    del_path_key(&xpath);
    del_path_key(&ucipath);
    if (NULL != key) {
        free(key);
    }
    return rc;
}

static int init_sysrepo_data(sr_ctx_t *ctx)
{
    struct uci_element *e = NULL;
    struct uci_section *s;
    int rc;

    rc = uci_load(ctx->uctx, ctx->config_file, &ctx->package);
    if (rc != UCI_OK) {
        fprintf(stderr, "No configuration (package): %s\n", ctx->config_file);
        goto cleanup;
    }

    uci_foreach_element(&ctx->package->sections, e)
    {
        s = uci_to_section(e);
        //TODO implement char array
        if (string_eq(s->type, "TODO")) {
            INF("key value is: %s", s->e.name)
            rc = parse_uci_config(ctx, s->e.name);
            CHECK_RET(rc, cleanup, "failed to add sysrepo data: %s", sr_strerror(rc));
        }
    }

    /* commit the changes to startup datastore */
    rc = sr_commit(ctx->startup_sess);
    CHECK_RET(rc, cleanup, "failed sr_commit: %s", sr_strerror(rc));

    return SR_ERR_OK;

cleanup:
    if (ctx->uctx) {
        uci_free_context(ctx->uctx);
        ctx->uctx = NULL;
    }
    return rc;
}

int sync_datastores(sr_ctx_t *ctx)
{
    char startup_file[XPATH_MAX_LEN] = {0};
    int rc = SR_ERR_OK;
    struct stat st;

    /* check if the startup datastore is empty
     * by checking the content of the file */
    snprintf(startup_file, XPATH_MAX_LEN, "/etc/sysrepo/data/%s.startup", ctx->yang_model);

    if (stat(startup_file, &st) != 0) {
        ERR("Could not open sysrepo file %s", startup_file);
        return SR_ERR_INTERNAL;
    }

    if (0 == st.st_size) {
        /* parse uci config */
        rc = init_sysrepo_data(ctx);
        INF_MSG("copy uci data to sysrepo");
        CHECK_RET(rc, error, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));
    } else {
        /* copy the sysrepo startup datastore to uci */
        INF_MSG("copy sysrepo data to uci");
        CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));
    }

error:
    return rc;
}

int load_startup_datastore(sr_ctx_t *ctx)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect(ctx->yang_model, SR_CONN_DEFAULT, &connection);
    CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_CONFIG_ONLY, &session);
    CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

    ctx->startup_sess = session;
    ctx->startup_conn = connection;

    return rc;

cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }

    return rc;
}
