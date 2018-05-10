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

/* delete uci option or section */
int uci_del(sr_ctx_t *ctx, const char *uci) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr = {};

    uci_ret = uci_lookup_ptr(ctx->uctx, &ptr, (char *) uci, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_lookup_ptr %d, path %s", uci_ret, uci);

    uci_ret = uci_delete(ctx->uctx, &ptr);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d, path %s", uci_ret, uci);

    uci_ret = uci_save(ctx->uctx, ptr.p);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "UCI save error %d, path %s", uci_ret, uci);

    uci_ret = uci_commit(ctx->uctx, &ptr.p, 1);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "UCI commit error %d, path %s", uci_ret, uci);

cleanup:

    return rc;
}

/* set uci section */
int set_uci_section(sr_ctx_t *ctx, char *uci) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr = {0};

    uci_ret = uci_lookup_ptr(ctx->uctx, &ptr, (char *) uci, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_lookup_ptr %d, path %s", uci_ret, uci);

    uci_ret = uci_set(ctx->uctx, &ptr);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d, path %s", uci_ret, uci);

    uci_ret = uci_save(ctx->uctx, ptr.p);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "UCI save error %d, path %s", uci_ret, uci);

    uci_ret = uci_commit(ctx->uctx, &ptr.p, 1);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "UCI commit error %d, path %s", uci_ret, uci);

cleanup:
    return rc;
}

/* get uci option */
int get_uci_item(struct uci_context *uctx, char *ucipath, char **value) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr;

    char *path = malloc(sizeof(char) * (strlen(ucipath) + 1));
    CHECK_NULL(path, &rc, cleanup, "malloc %s", ucipath);
    sprintf(path, "%s", ucipath);

    uci_ret = uci_lookup_ptr(uctx, &ptr, path, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", uci_ret, path);
    UCI_CHECK_ITEM(ptr.o, &rc, cleanup, "Uci item %s not found", ucipath);
    UCI_CHECK_ITEM(ptr.o->v.string, &rc, cleanup, "Uci item %s not found", ucipath);

    *value = strdup(ptr.o->v.string);
    CHECK_NULL(*value, &rc, cleanup, "strdup failed for %s", ucipath);

cleanup:
    if (NULL != path) {
        free(path);
    }
    return rc;
}

/* set uci option */
int set_uci_item(struct uci_context *uctx, char *ucipath, char *value) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr;

    char *path = malloc(sizeof(char) * (strlen(ucipath) + strlen(value) + 2));
    CHECK_NULL_MSG(path, &rc, cleanup, "malloc failed");

    sprintf(path, "%s%s%s", ucipath, "=", value);

    uci_ret = uci_lookup_ptr(uctx, &ptr, path, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", uci_ret, path);

    uci_ret = uci_set(uctx, &ptr);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d %s", uci_ret, path);

    uci_ret = uci_save(uctx, ptr.p);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_save %d %s", uci_ret, path);

    uci_ret = uci_commit(uctx, &(ptr.p), false);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_commit %d %s", uci_ret, path);

cleanup:
    if (NULL != path) {
        free(path);
    }
    return rc;
}

/* insert key value into a xpath or ucipath with snprintf */
char *new_path_key(char *path, char *key) {
    int rc = SR_ERR_OK;
    char *value = NULL;
    int len = 0;

    CHECK_NULL_MSG(path, &rc, cleanup, "missing parameter path");

    /* if the xpath does not contain list elements, copy string */
    if (NULL == key) {
        return strdup(path);
    }

    len = strlen(key) + strlen(path);

    value = malloc(sizeof(char) * len);
    CHECK_NULL_MSG(value, &rc, cleanup, "failed malloc");

    snprintf(value, len, path, key);

cleanup:
    return value;
}

/* free the memory from new_path_key and set to NULL */
void del_path_key(char **value) {
    if (NULL == *value) {
        return;
    }
    free(*value);
    *value = NULL;
}

/* get the first key value from a sysrepo XPATH */
char *get_key_value(char *orig_xpath)
{
    char *key = NULL, *node = NULL;
    sr_xpath_ctx_t state = {0, 0, 0, 0};

    node = sr_xpath_next_node(orig_xpath, &state);
    if (NULL == node) {
        goto cleanup;
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

cleanup:
    sr_xpath_recover(&state);
    return key;
}

/* check if two strings are equal */
bool string_eq(char *first, char *second)
{
    if (0 == strcmp(first, second) && (strlen(first) == strlen(second))) {
        return true;
    } else {
        return false;
    }
}

/* Per convention, boolean options may have one of the values '0', 'no',
 * 'off', 'false' or 'disabled' to specify a false value or '1' , 'yes',
 * 'on', 'true' or 'enabled' to specify a true value. */
bool uci_true_value(char *uci_val)
{
    if (string_eq("1", uci_val)) {
        return true;
    } else if (string_eq("yes", uci_val)) {
        return true;
    } else if (string_eq("on", uci_val)) {
        return true;
    } else if (string_eq("true", uci_val)) {
        return true;
    } else if (string_eq("enabled", uci_val)) {
        return true;
    } else {
        return false;
    }
}

/* manage uci sections */
int uci_section_cb(sr_ctx_t *ctx, char *xpath, char *ucipath, sr_edit_flag_t flag, void *data)
{
    return SR_ERR_OK;
}

/* manage uci options */
int uci_option_cb(sr_ctx_t *ctx, char *xpath, char *ucipath, sr_edit_flag_t flag, void *data) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    char *uci_val = NULL;

    uci_ret = get_uci_item(ctx->uctx, ucipath, &uci_val);
    if (UCI_OK == uci_ret) {
        rc = sr_set_item_str(ctx->startup_sess, xpath, uci_val, flag);
        free(uci_val);
        CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
    }

cleanup:
    return rc;
}

/* manage uci list's */
int uci_list_cb(sr_ctx_t *ctx, char *xpath, char *ucipath, sr_edit_flag_t flag, void *data) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_context *uci_ctx = NULL;
    struct uci_element *e = NULL;
    struct uci_ptr ptr;

    uci_ctx = uci_alloc_context();
    uci_ret = uci_lookup_ptr (uci_ctx, &ptr, ucipath, true);
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_lookup_ptr %d, path %s", uci_ret, ucipath);

    if (NULL == ptr.o || UCI_TYPE_LIST != ptr.o->type) {
        ERR("ucipath %s does not have a list", ucipath);
        goto cleanup;
    }

    uci_foreach_element(&ptr.o->v.list, e) {
        rc = sr_set_item_str(ctx->startup_sess, xpath, e->name, flag);
        CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
    }

cleanup:
    if (NULL != uci_ctx) {
        uci_free_context (uci_ctx);
    }
    return rc;
}

/* manage uci boolean values */
int uci_boolean_cb(sr_ctx_t *ctx, char *xpath, char *ucipath, sr_edit_flag_t flag, void *data) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    char *uci_val = NULL;

    uci_ret = get_uci_item(ctx->uctx, ucipath, &uci_val);
    if (UCI_OK == uci_ret) {
        if (true == uci_true_value(uci_val)) {
            rc = sr_set_item_str(ctx->startup_sess, xpath, "true", flag);
        } else {
            rc = sr_set_item_str(ctx->startup_sess, xpath, "false", flag);
        }
        free(uci_val);
        CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
    }

cleanup:
    return rc;
}

/* manage uci boolean values but reverse them in sysrepo, used for ignore options */
int uci_boolean_reverse_cb(sr_ctx_t *ctx, char *xpath, char *ucipath, sr_edit_flag_t flag, void *data) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    char *uci_val = NULL;

    uci_ret = get_uci_item(ctx->uctx, ucipath, &uci_val);
    if (UCI_OK == uci_ret) {
        if (true == uci_true_value(uci_val)) {
            rc = sr_set_item_str(ctx->startup_sess, xpath, "false", flag);
        } else {
            rc = sr_set_item_str(ctx->startup_sess, xpath, "true", flag);
        }
        free(uci_val);
        CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
    }

cleanup:
    return rc;
}

/* sysrepo callback for writing leaf's to uci */
int sr_option_cb(sr_ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, char *xpath, char *ucipath) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        char *mem = sr_val_to_str(new_val);
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

/* sysrepo callback for writing bool leaf's to uci, but reverse */
int sr_boolean_reverse_cb(sr_ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, char *xpath, char *ucipath) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        if (new_val->data.bool_val) {
            rc = set_uci_item(ctx->uctx, ucipath, "0");
        } else {
            rc = set_uci_item(ctx->uctx, ucipath, "1");
        }
        CHECK_RET(rc, cleanup, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        CHECK_RET(rc, cleanup, "uci_del %d", rc);
    }

cleanup:
    return rc;
}

/* sysrepo callback for writing bool leaf's to uci */
int sr_boolean_cb(sr_ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, char *xpath, char *ucipath) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        if (new_val->data.bool_val) {
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

/* sysrepo callback for writing containers/groupings to uci */
int sr_section_cb(sr_ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, char *xpath, char *ucipath) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        rc = set_uci_section(ctx, ucipath);
        CHECK_RET(rc, cleanup, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        CHECK_RET(rc, cleanup, "uci_del %d", rc);
    }

cleanup:
    return rc;
}

/* sysrepo callback for writing leaf-lists to uci, every list element is directly add/deleted in uci */
int sr_list_cb(sr_ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, char *xpath, char *ucipath) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr = {};
    char *set_path = NULL;


    if (SR_OP_DELETED == op || SR_OP_MODIFIED == op) {
        int len = strlen(ucipath) + strlen(old_val->data.string_val) + 2;
        set_path = malloc(sizeof(char) * len);
        CHECK_NULL_MSG(set_path, &rc, cleanup, "malloc failed");
        sprintf(set_path, "%s%s%s", ucipath, "=", old_val->data.string_val);

        uci_ret = uci_lookup_ptr(ctx->uctx, &ptr, set_path, true);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", uci_ret, set_path);

        uci_ret = uci_del_list(ctx->uctx, &ptr);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d %s", uci_ret, set_path);

        uci_ret = uci_save(ctx->uctx, ptr.p);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_save %d %s", uci_ret, set_path);

        uci_ret = uci_commit(ctx->uctx, &(ptr.p), false);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_commit %d %s", uci_ret, set_path);
    }

    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        int len = strlen(ucipath) + strlen(new_val->data.string_val) + 2;
        set_path = malloc(sizeof(char) * len);
        CHECK_NULL_MSG(set_path, &rc, cleanup, "malloc failed");
        sprintf(set_path, "%s%s%s", ucipath, "=", new_val->data.string_val);

        rc = uci_lookup_ptr(ctx->uctx, &ptr, set_path, true);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", uci_ret, set_path);

        rc = uci_add_list(ctx->uctx, &ptr);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d %s", uci_ret, set_path);

        rc = uci_save(ctx->uctx, ptr.p);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_save %d %s", uci_ret, set_path);

        rc = uci_commit(ctx->uctx, &(ptr.p), false);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_commit %d %s", uci_ret, set_path);
    }

cleanup:
    if (NULL != set_path) {
        free(set_path);
    }
    return rc;
}

/* parse uci config file and load it into sysrepo */
static int parse_uci_config(sr_ctx_t *ctx,  char *key)
{
    char *xpath = NULL;
    char *ucipath = NULL;
    int rc = SR_ERR_OK;

    for (int i = 0; i < ctx->map_size; i++) {
        xpath = new_path_key(ctx->map[i].xpath, key);
        CHECK_NULL_MSG(xpath, &rc, cleanup, "failed to generate path");
        ucipath = new_path_key(ctx->map[i].ucipath, key);
        CHECK_NULL_MSG(xpath, &rc, cleanup, "failed to generate path");

        rc = ctx->map[i].uci_cb(ctx, xpath, ucipath, SR_EDIT_DEFAULT, NULL);
        /* if not found skip check */
        if (SR_ERR_NOT_FOUND != rc) {
            CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
        } else {
            rc = SR_ERR_OK;
        }
        del_path_key(&xpath);
        del_path_key(&ucipath);
    }

cleanup:
    del_path_key(&xpath);
    del_path_key(&ucipath);

    return rc;
}

/* sysrepo callback used on every change request */
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

    /* add/change leafs */
    for (int i = 0; i < ctx->map_size; i++) {
        xpath = new_path_key(ctx->map[i].xpath, key);
        CHECK_NULL_MSG(xpath, &rc, cleanup, "failed to generate path");
        ucipath = new_path_key(ctx->map[i].ucipath, key);
        CHECK_NULL_MSG(xpath, &rc, cleanup, "failed to generate path");
        if (string_eq(xpath, orig_xpath)) {
            rc = ctx->map[i].sr_cb(ctx, op, old_val, new_val, xpath, ucipath);
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

/* parse uci config file for uci_sections and use their key value */
int sr_uci_init_data(sr_ctx_t *ctx, const char *uci_config, const char *uci_sections[])
{
    struct uci_element *e = NULL;
    struct uci_section *s;
    int uci_ret = UCI_OK;
    int rc = SR_ERR_OK;

    uci_ret = uci_load(ctx->uctx, uci_config, &ctx->package);
    /* skip check if duplicate */
    if (UCI_ERR_DUPLICATE != uci_ret) {
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "No configuration (package) %s, uci_error %d", uci_config, uci_ret);
    }

    uci_foreach_element(&ctx->package->sections, e)
    {
        s = uci_to_section(e);
        const char **section= uci_sections;
        while(*section != 0) {
            if (string_eq(s->type, (char *) *section)) {
                INF("key value is: %s", s->e.name)
                rc = parse_uci_config(ctx, s->e.name);
                CHECK_RET(rc, cleanup, "failed to add sysrepo data: %s", sr_strerror(rc));
            }
            section++;
        }
    }

    /* commit the changes to startup datastore */
    rc = sr_commit(ctx->startup_sess);
    CHECK_RET(rc, cleanup, "failed sr_commit: %s", sr_strerror(rc));

    return rc;

cleanup:
    if (ctx->uctx) {
        uci_free_context(ctx->uctx);
        ctx->uctx = NULL;
    }
    return rc;
}

/* sync sysrepo with uci,
 * in case of first boot, parse uci config file and load it into sysrepo,
 * if sysrepo already has some data, skip this step
 */
int sync_datastores(sr_ctx_t *ctx)
{
    char *startup_file = NULL;
    int rc = SR_ERR_OK;
    struct stat st;

    /* check if the startup datastore is empty
     * by checking the content of the file */
    int len = strlen(ctx->yang_model) + 28;
    startup_file = malloc(sizeof(char) * len);
    CHECK_NULL_MSG(startup_file, &rc, cleanup, "malloc failed");

    snprintf(startup_file, len, "/etc/sysrepo/data/%s.startup", ctx->yang_model);

    if (stat(startup_file, &st) != 0) {
        ERR("Could not open sysrepo file %s", startup_file);
        return SR_ERR_INTERNAL;
    }

    if (0 == st.st_size) {
        /* parse uci config */
        rc = sr_uci_init_data(ctx, ctx->config_file, ctx->uci_sections);
        INF_MSG("copy uci data to sysrepo");
        CHECK_RET(rc, cleanup, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));
    } else {
        /* copy the sysrepo startup datastore to uci */
        INF_MSG("copy sysrepo data to uci");
        CHECK_RET(rc, cleanup, "failed to apply sysrepo startup data: %s", sr_strerror(rc));
    }

cleanup:
    if (NULL != startup_file) {
        free(startup_file);
    }
    return rc;
}

/* free sr_ctx_t */
void sr_uci_free_context(sr_ctx_t *ctx)
{
    if (NULL == ctx) {
        return;
    }
    /* clean startup datastore */
    if (NULL != ctx->startup_sess) {
        sr_session_stop(ctx->startup_sess);
        ctx->startup_sess = NULL;
    }
    if (NULL != ctx->startup_conn) {
        sr_disconnect(ctx->startup_conn);
        ctx->startup_conn = NULL;
    }
    if (NULL != ctx->sub) {
        sr_unsubscribe(ctx->sess, ctx->sub);
        ctx->sub = NULL;
    }
    if (NULL != ctx->uctx) {
        uci_free_context(ctx->uctx);
        ctx->uctx = NULL;
    }
    free(ctx);

    DBG_MSG("Context freed");
}

/* load startup datastore, usually changes from running datastore
 * are saved into startup also */
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
