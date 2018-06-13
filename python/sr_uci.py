#!/usr/bin/env python2

__author__ = "Mislav Novakovic <mislav.novakovic@sartura.hr>"
__copyright__ = "Copyright 2018, Deutsche Telekom AG"
__license__ = "Apache 2.0"

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This sample application demonstrates use of Python programming language bindings for sysrepo library.
# Original c application was rewritten in Python to show similarities and differences
# between the two.
#
# Most notable difference is in the very different nature of languages, c is weakly statically typed language
# while Python is strongly dynamiclally typed. Python code is much easier to read and logic easier to comprehend
# for smaller scripts. Memory safety is not an issue but lower performance can be expected.
#
# The original c implementation is also available in the source, so one can refer to it to evaluate trade-offs.

import libsysrepoPython2 as sr
import sys, os
from subprocess import Popen, PIPE

yang_model = "ietf-interfaces"

table_sr_uci = [
    {"ucipath":"network.{}.mtu", "xpath":"/ietf-interfaces:interfaces/interface[name='{}']/ietf-ip:ipv4/mtu"},
    {"ucipath":"network.{}.mtu", "xpath":"/ietf-interfaces:interfaces/interface[name='{}']/ietf-ip:ipv6/mtu"},
    {"ucipath":"network.{}.enabled", "xpath":"/ietf-interfaces:interfaces/interface[name='{}']/ietf-ip:ipv4/enabled"},
    {"ucipath":"network.{}.enabled", "xpath":"/ietf-interfaces:interfaces/interface[name='{}']/ietf-ip:ipv6/enabled"},
    {"ucipath":"network.{}.ip4prefixlen", "xpath":"/ietf-interfaces:interfaces/interface[name='{}']/ietf-ip:ipv4/address[ip='{}']/prefix-length"},
    {"ucipath":"network.{}.ip6prefixlen", "xpath":"/ietf-interfaces:interfaces/interface[name='{}']/ietf-ip:ipv6/address[ip='{}']/prefix-length"},
    {"ucipath":"network.{}.netmask", "xpath":"/ietf-interfaces:interfaces/interface[name='{}']/ietf-ip:ipv4/address[ip='{}']/netmask"},
    {"ucipath":"network.{}.type", "xpath":"/ietf-interfaces:interfaces/interface[name='{}']/type"}
]

# Helper function for printing changes given operation, old and new value.
def print_change(op, old_val, new_val):
    if (op == sr.SR_OP_CREATED):
           print "CREATED: ",
           print new_val.to_string(),
    elif (op == sr.SR_OP_DELETED):
           print "DELETED: ",
           print old_val.to_string(),
    elif (op == sr.SR_OP_MODIFIED):
           print "MODIFIED: ",
           print "old value",
           print old_val.to_string(),
           print "new value",
           print new_val.to_string(),
    elif (op == sr.SR_OP_MOVED):
        print "MOVED: " + new_val.xpath() + " after " + old_val.xpath()

# Helper function for printing events.
def ev_to_str(ev):
    if (ev == sr.SR_EV_VERIFY):
        return "verify"
    elif (ev == sr.SR_EV_APPLY):
        return "apply"
    elif (ev == sr.SR_EV_ABORT):
        return "abort"
    else:
        return "abort"

# Function to print current configuration state.
# It does so by loading all the items of a session and printing them out.
def print_current_config(session, module_name):
    select_xpath = "/" + module_name + ":*//*"

    values = session.get_items(select_xpath)
    if None == values:
        return

    for i in range(values.val_cnt()):
        print values.val(i).to_string(),

def get_key_value(orig_xpath):
    key = ""
    state = sr.Xpath_Ctx()
    node = state.next_node(orig_xpath)
    if None == node:
        return None
    while True:
        ret_key = state.next_key_name(None)
        if None != ret_key:
            key = state.next_key_value(None)
        if None != ret_key:
            node = None
        else:
            node = state.next_node(None)
        if None == node:
            break

    state.recover()
    return key

def get_second_key_value(orig_xpath):
    key = ""
    keys = 0
    state = sr.Xpath_Ctx()
    node = state.next_node(orig_xpath)
    if None == node:
        return None
    while True:
        ret_key = state.next_key_name(None)
        if None != ret_key:
            keys = keys + 1
        if keys == 2:
            key = state.next_key_value(None)
        if keys >= 2:
            node = None
        else:
            node = state.next_node(None)
        if None == node:
            break

    state.recover()
    return key

def sr_option_cb(ctx, op, old_val, new_val, ucipath):
    if sr.SR_OP_CREATED == op or sr.SR_OP_MODIFIED == op:
        p = Popen(["uci","set", ucipath + "=" + new_val.val_to_string()], stdout=PIPE)
        ret = p.communicate()
    else:
        p = Popen(["uci","delete", ucipath], stdout=PIPE)
        ret = p.communicate()

    p_commit = Popen(["uci","commit", ctx["config_file"]], stdout=PIPE)
    ret = p_commit.communicate()

def sysrepo_to_uci(ctx, op, old_val, new_val, event):
    orig_xpath = ""
    if sr.SR_OP_CREATED == op or sr.SR_OP_MODIFIED == op:
        orig_xpath = new_val.xpath()
    else:
        orig_xpath = old_val.xpath()


    key = get_key_value(orig_xpath)
    second_key = get_second_key_value(orig_xpath)

    for item in ctx["map"]:
        ucipath = item["ucipath"].format(key)
        xpath = item["xpath"].format(key, second_key)
        if xpath == orig_xpath:
            sr_option_cb(ctx, op, old_val, new_val, ucipath)

# Function to be called for subscribed client of given session whenever configuration changes.
def module_change_cb(sess, module_name, event, private_ctx):
    print "\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n"

    try:
        print "\n\n ========== Notification " + ev_to_str(event) + " =============================================\n"
        if (sr.SR_EV_APPLY == event):
            print "\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n"
            print_current_config(sess, module_name);

        print "\n ========== CHANGES: =============================================\n"

        change_path = "/" + module_name + ":*"

        it = sess.get_changes_iter(change_path);

        while True:
            change = sess.get_change_next(it)
            if change == None:
                break
            print_change(change.oper(), change.old_val(), change.new_val())
            sysrepo_to_uci(private_ctx, change.oper(), change.old_val(), change.new_val(), event)

        print "\n\n ========== END OF CHANGES =======================================\n"

    except Exception as e:
        print e

    return sr.SR_ERR_OK

def uci_option_cb(ctx,xpath,ucipath):
    if "type" == ucipath[-4:]:
        ctx["startup_sess"].set_item_str(xpath, "iana-if-type:ethernetCsmacd", sr.SR_EDIT_DEFAULT)
        return

    nul_f = open(os.devnull, 'w')
    p = Popen(["uci","get",ucipath], stdout=PIPE, stderr=nul_f)
    nul_f.close()
    ret = p.communicate()
    if None == ret[1] and "" != ret[0]:
        print xpath
        ctx["startup_sess"].set_item_str(xpath, ret[0].rstrip('\n'), sr.SR_EDIT_DEFAULT)

def parse_uci_config(ctx,config_file,key):
    p = Popen(["uci","get",config_file + "." + key + ".ipaddr"], stdout=PIPE)
    ret = p.communicate()
    ipaddr = ""

    if None == ret[1] and "" != ret[0]:
        ipaddr = ret[0].rstrip('\n')

    for item in ctx["map"]:
        ucipath = item["ucipath"].format(key)
        xpath = item["xpath"].format(key, ipaddr)
        uci_option_cb(ctx,xpath,ucipath)
        print xpath

def sr_uci_init_data(ctx, config_file, uci_sections):
    rc = sr.SR_ERR_OK
    def get_uci_sections(config_file, name):
        # if_list=$(uci show network | grep =interface | cut -d. -f2- | cut -d= -f1)
        p1 = Popen(["uci","show",config_file], stdout=PIPE)
        p2 = Popen(["grep","=" + name], stdin=p1.stdout, stdout=PIPE)
        p3 = Popen(["cut","-d.","-f2-"], stdin=p2.stdout, stdout=PIPE)
        p4 = Popen(["cut","-d=","-f1"], stdin=p3.stdout, stdout=PIPE)
        ret = p4.communicate()
        interfaces = filter(None,ret[0].split("\n"))
        return interfaces

    names = []
    for name in uci_sections:
        names = names + get_uci_sections(config_file,name) 

    for name in names:
        parse_uci_config(ctx, config_file, name)

        ctx["startup_sess"].commit()

    return rc

def sync_datastores(ctx):
    rc = sr.SR_ERR_OK
    p = Popen(["uci","show","network"], stdout=PIPE)
    ret = p.communicate()

    if ret[0] == "":
        print "copy uci data to sysrepo"
        rc = sr_uci_init_data(ctx, ctx["config_file"], ctx["uci_sections"])
    else:
        print "copy sysrepo data to uci"
        rc = sr.SR_ERR_OK

    return rc

def load_startup_datastore(ctx):
    conn = sr.Connection(ctx["yang_model"])
    sess = sr.Session(conn, sr.SR_DS_STARTUP, sr.SR_SESS_CONFIG_ONLY)

    if None == conn or None == sess:
        return sr.SR_ERR_INTERNAL

    ctx["startup_conn"] = conn
    ctx["startup_sess"] = sess

    return sr.SR_ERR_OK

def sr_plugin_init_cb(session):
    ctx = {}
    ctx["yang_model"] = yang_model
    ctx["sess"] = session
    ctx["sub"] = sr.Subscribe(session)
    ctx["config_file"] = "network"
    ctx["uci_sections"] = ["interface"]
    ctx["map"] = table_sr_uci

    rc = load_startup_datastore(ctx)
    if sr.SR_ERR_OK != rc:
        return sr.SR_ERR_INTERNAL

    rc = sync_datastores(ctx)
    if sr.SR_ERR_OK != rc:
        return sr.SR_ERR_INTERNAL

    # subscribe for changes in running config */
    ctx["sub"].module_change_subscribe(ctx["yang_model"], module_change_cb, ctx)

    print "\n\n ========== READING STARTUP CONFIG: ==========\n"
    try:
        print_current_config(session, yang_model);
    except Exception as e:
        print e

    print "\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n"

    sr.global_loop()

    return rc

# Main client function
try:
    # connect to sysrepo
    conn = sr.Connection("example_application")
    # start session
    sess = sr.Session(conn)

    rc = sr_plugin_init_cb(sess)
    if (sr.SR_ERR_OK != rc):
        print "error"

    print "Application exit requested, exiting.\n";

except Exception as e:
    print e
