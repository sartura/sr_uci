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
 *	http://www.apache.org/licenses/LICENSE-2.0
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

int uci_del(ctx_t *ctx, const char *uci)
{
	int rc = UCI_OK;
	struct uci_ptr ptr = {};

	uci_lookup_ptr(ctx->uctx, &ptr, (char *) uci, true);
	UCI_CHECK_RET(rc, error, "uci_lookup_ptr %d, path %s", rc, uci);

	uci_delete(ctx->uctx, &ptr);
	UCI_CHECK_RET(rc, error, "uci_set %d, path %s", rc, uci);

	uci_save(ctx->uctx, ptr.p);
	UCI_CHECK_RET(rc, error, "UCI save error %d, path %s", rc, uci);

	uci_commit(ctx->uctx, &ptr.p, 1);
	UCI_CHECK_RET(rc, error, "UCI commit error %d, path %s", rc, uci);

error:
	return rc;
}

int set_uci_section(ctx_t *ctx, char *uci)
{
	int rc = UCI_OK;
	struct uci_ptr ptr = {0};

	uci_lookup_ptr(ctx->uctx, &ptr, (char *) uci, true);
	UCI_CHECK_RET(rc, error, "uci_lookup_ptr %d, path %s", rc, uci);

	uci_set(ctx->uctx, &ptr);
	UCI_CHECK_RET(rc, error, "uci_set %d, path %s", rc, uci);

	uci_save(ctx->uctx, ptr.p);
	UCI_CHECK_RET(rc, error, "UCI save error %d, path %s", rc, uci);

	uci_commit(ctx->uctx, &ptr.p, 1);
	UCI_CHECK_RET(rc, error, "UCI commit error %d, path %s", rc, uci);

error:
	return rc;
}

int get_uci_item(struct uci_context *uctx, char *ucipath, char **value)
{
	int rc = UCI_OK;
	char path[MAX_UCI_PATH];
	struct uci_ptr ptr;

	sprintf(path, "%s", ucipath);

	rc = uci_lookup_ptr(uctx, &ptr, path, true);
	UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, path);

	if (NULL == ptr.o) {
		INF("Uci item %s not found", ucipath);
		return UCI_ERR_NOTFOUND;
	}

	strcpy(*value, ptr.o->v.string);

exit:
	return rc;
}

int set_uci_item(struct uci_context *uctx, char *ucipath, char *value)
{
	int rc = UCI_OK;
	struct uci_ptr ptr;
	char *set_path = calloc(1, MAX_UCI_PATH);

	sprintf(set_path, "%s%s%s", ucipath, "=", value);

	rc = uci_lookup_ptr(uctx, &ptr, set_path, true);
	UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, set_path);

	rc = uci_set(uctx, &ptr);
	UCI_CHECK_RET(rc, exit, "uci_set %d %s", rc, set_path);

	rc = uci_save(uctx, ptr.p);
	UCI_CHECK_RET(rc, exit, "uci_save %d %s", rc, set_path);

	rc = uci_commit(uctx, &(ptr.p), false);
	UCI_CHECK_RET(rc, exit, "uci_commit %d %s", rc, set_path);

exit:
	free(set_path);

	return rc;
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

int sysrepo_option_callback(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        char *mem = sr_val_to_str(val);
        CHECK_NULL(mem, &rc, error, "sr_print_val %s", sr_strerror(rc));
        rc = set_uci_item(ctx->uctx, ucipath, mem);
        free(mem);
        UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        UCI_CHECK_RET(rc, uci_error, "uci_del %d", rc);
    }

error:
    return rc;
uci_error:
    return SR_ERR_INTERNAL;
}

int sysrepo_boolean_callback(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        if (val->data.bool_val) {
            rc = set_uci_item(ctx->uctx, ucipath, "1");
        } else {
            rc = set_uci_item(ctx->uctx, ucipath, "0");
        }
        UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        UCI_CHECK_RET(rc, uci_error, "uci_del %d", rc);
    }

    return rc;
uci_error:
    return SR_ERR_INTERNAL;
}

int sysrepo_section_callback(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        sprintf(ucipath, "%s.%s=%s", ctx->config_file, key, "TODO");
        rc = set_uci_section(ctx, ucipath);
        UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        UCI_CHECK_RET(rc, uci_error, "uci_del %d", rc);
    }

    return rc;
uci_error:
    return SR_ERR_INTERNAL;
}

int sysrepo_list_callback(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
    int rc = SR_ERR_OK;
    size_t count = 0;
    sr_val_t *values = NULL;
    struct uci_ptr ptr = {};
    char set_path[XPATH_MAX_LEN] = {0};

    rc = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
    UCI_CHECK_RET(rc, uci_error, "uci_lookup_ptr %d, path %s", rc, ucipath);
    if (NULL != ptr.o) {
        /* remove the UCI list first */
        rc = uci_delete(ctx->uctx, &ptr);
        UCI_CHECK_RET(rc, uci_error, "uci_delete %d, path %s", rc, ucipath);
    }

    /* get all list instances */
    rc = sr_get_items(ctx->sess, xpath, &values, &count);
    CHECK_RET(rc, cleanup, "failed sr_get_items: %s", sr_strerror(rc));

    for (size_t i = 0; i<count; i++){
        sprintf(set_path, "%s%s%s", ucipath, "=", values[i].data.string_val);

        rc = uci_lookup_ptr(ctx->uctx, &ptr, set_path, true);
        UCI_CHECK_RET(rc, uci_error, "lookup_pointer %d %s", rc, set_path);

        rc = uci_add_list(ctx->uctx, &ptr);
        UCI_CHECK_RET(rc, uci_error, "uci_set %d %s", rc, set_path);

        rc = uci_save(ctx->uctx, ptr.p);
        UCI_CHECK_RET(rc, uci_error, "uci_save %d %s", rc, set_path);

        rc = uci_commit(ctx->uctx, &(ptr.p), false);
        UCI_CHECK_RET(rc, uci_error, "uci_commit %d %s", rc, set_path);
    }

cleanup:
    if (NULL != values && 0 != count) {
        sr_free_values(values, count);
    }
    return rc;
uci_error:
    if (NULL != values && 0 != count) {
        sr_free_values(values, count);
    }
    return SR_ERR_INTERNAL;
}

int sysrepo_list_callback_enable(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val) {
    int rc = SR_ERR_OK;
    struct uci_ptr ptr = {};

    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        if (false == val->data.bool_val) {
            rc = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
            UCI_CHECK_RET(rc, uci_error, "uci_lookup_ptr %d, path %s", rc, ucipath);
            if (NULL != ptr.o) {
                /* remove the UCI list first */
                rc = uci_delete(ctx->uctx, &ptr);
                UCI_CHECK_RET(rc, uci_error, "uci_delete %d, path %s", rc, ucipath);

                rc = uci_save(ctx->uctx, ptr.p);
                UCI_CHECK_RET(rc, uci_error, "uci_save %d %s", rc, ucipath);

                rc = uci_commit(ctx->uctx, &(ptr.p), false);
                UCI_CHECK_RET(rc, uci_error, "uci_commit %d %s", rc, ucipath);
            }
        } else {
            return sysrepo_list_callback(ctx, op, xpath, "voice_client.direct_dial.direct_dial", key, val); 
        }
    } else if (SR_OP_DELETED == op) {
        //TODO
    }

    return rc;
uci_error:
    return SR_ERR_INTERNAL;
}

void
transform_orig_bool_value(ctx_t *ctx, char **uci_val)
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

static int parse_uci_config(ctx_t *ctx,  char *key)
{
    char xpath[XPATH_MAX_LEN] = {0};
    char ucipath[XPATH_MAX_LEN] = {0};
    char *uci_val = calloc(1, 100);
    int rc = SR_ERR_OK;

    const int n_mappings = ARR_SIZE(ctx->map);
    for (int i = 0; i < n_mappings; i++) {
        snprintf(xpath, XPATH_MAX_LEN, ctx->map[i].xpath, key);
        snprintf(ucipath, XPATH_MAX_LEN, ctx->map[i].ucipath, key);
        //TODO implement function callback
        rc = get_uci_item(ctx->uctx, ucipath, &uci_val);
        if (UCI_OK == rc) {
            INF("%s : %s", xpath, uci_val);
            rc = sr_set_item_str(ctx->startup_sess, xpath, uci_val, SR_EDIT_DEFAULT);
            CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
        }
    }

cleanup:
    if (SR_ERR_NOT_FOUND == rc) {
        rc = SR_ERR_OK;
    }
    if (NULL != uci_val) {
        free(uci_val);
    }

    return rc;
}

static int parse_uci_config_list(ctx_t *ctx)
{
    int rc = SR_ERR_OK;
    struct uci_option *o;
    struct uci_element *el;
    struct uci_ptr ptr = {};
    char ucipath[] = "UCIPATH";
    char xpath[] = "XPATH";

    rc = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
    UCI_CHECK_RET(rc, uci_error, "uci_lookup_ptr %d, path %s", rc, ucipath);

    if (NULL == ptr.o) {
        goto uci_error;
    }

    uci_foreach_element(&ptr.o->v.list, el) {
        o = uci_to_option(el);
        if (NULL == o && NULL == o->e.name) {
            goto uci_error;
        }
        rc = sr_set_item_str(ctx->startup_sess, xpath, o->e.name, SR_EDIT_DEFAULT);
        CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
    }

cleanup:
    return rc;
uci_error:
    return SR_ERR_INTERNAL;
}

int sysrepo_to_uci(ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, sr_notif_event_t event)
{
    char xpath[XPATH_MAX_LEN] = {0};
    char ucipath[XPATH_MAX_LEN] = {0};
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
    const int n_mappings = ARR_SIZE(ctx->map);
    for (int i = 0; i < n_mappings; i++) {
        snprintf(xpath, XPATH_MAX_LEN, ctx->map[i].xpath, key);
        snprintf(ucipath, XPATH_MAX_LEN, ctx->map[i].ucipath, key);
        if (string_eq(xpath, orig_xpath)) {
            rc = ctx->map[i].sr_callback(ctx, op, old_val, new_val, event, NULL);
            CHECK_RET(rc, error, "failed sysrepo operation %s", sr_strerror(rc));
        }
    }

error:
    if (NULL != key) {
        free(key);
    }
    return rc;
}

static int init_sysrepo_data(ctx_t *ctx)
{
    struct uci_element *e;
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

int sync_datastores(ctx_t *ctx)
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

int load_startup_datastore(ctx_t *ctx)
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
