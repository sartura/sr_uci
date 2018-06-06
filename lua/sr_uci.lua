local yang_model = "ietf-interfaces"
local g_ctx = {}

local table_sr_uci = {
    {ucipath={"network","mtu"}, xpath="/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/mtu"},
    {ucipath={"network","mtu"}, xpath="/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/mtu"},
    {ucipath={"network","enabled"}, xpath="/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/enabled"},
    {ucipath={"network","enabled"}, xpath="/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/enabled"},
    {ucipath={"network","ip4prefixlen"}, xpath="/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/prefix-length"},
    {ucipath={"network","ip6prefixlen"}, xpath="/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/address[ip='%s']/prefix-length"},
    {ucipath={"network","netmask"}, xpath="/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/netmask"},
    {ucipath={"network","type"}, xpath="/ietf-interfaces:interfaces/interface[name='%s']/type"}
}

local function dump_table(tbl, indent)
  if not indent then indent = 0 end
  for k, v in pairs(tbl) do
    local formatting = string.rep("  ", indent) .. k .. ": "
    if type(v) == "table" then
      print(formatting)
      dump_table(v, indent+1)
    elseif type(v) == 'boolean' then
      print(formatting .. tostring(v))
    else
      print(formatting .. v)
    end
  end
end

local sr = require("libsysrepoLua")

-- Helper function for printing changes given operation, old and new value.
local function print_change(op, old_val, new_val)
    if (op == sr.SR_OP_CREATED) then
           io.write ("CREATED: ")
           io.write(new_val:to_string())
    elseif (op == sr.SR_OP_DELETED) then
           io.write ("DELETED: ")
           io.write(old_val:to_string());
    elseif (op == sr.SR_OP_MODIFIED) then
           io.write ("MODIFIED: ")
           io.write ("old value ")
           io.write(old_val:to_string())
           io.write ("new value ")
           io.write(new_val:to_string())
    elseif (op == sr.SR_OP_MOVED) then
        io.write ("MOVED: " .. new_val:xpath() .. " after " .. old_val:xpath() .. "\n")
    end
end

-- Function to print current configuration state.
-- It does so by loading all the items of a session and printing them out.
local function print_current_config(sess, module_name)

    local function run()
        local xpath = "/" .. module_name .. ":*//*"
        local values = sess:get_items(xpath)

	if (values == nil) then return end

	for i=0, values:val_cnt() - 1, 1 do
            io.write(values:val(i):to_string())
	end
    end

    local ok,res=pcall(run)
    if not ok then
        io.write("\nerror: ",res, "\n")
    end

end

local function get_key_value(orig_xpath)
    local key
    local state = sr.Xpath_Ctx()
    local node = state:next_node(orig_xpath)
    if nil == node then return nil end
    repeat
        local ret_key = state:next_key_name(nil)
        if ret_key ~= nil then key = state:next_key_value(nil) end
        if ret_key ~= nil then
            node = nil
        else
            node = state:next_node(nil)
        end
    until node == nil
    state:recover()
    return key
end

local function get_second_key_value(orig_xpath)
    local key
    local keys = 0
    local state = sr.Xpath_Ctx()
    local node = state:next_node(orig_xpath)
    if nil == node then return nil end
    repeat
        local ret_key = state:next_key_name(nil)
        if ret_key ~= nil then keys = keys + 1 end
        if keys == 2 then key = state:next_key_value(nil) end
        if keys >= 2 then
            node = nil
        else
            node = state:next_node(nil)
        end
    until node == nil
    state:recover()
    return key
end

local function sr_option_cb(ctx, op, old_val, new_val, ucipath)

    if sr.SR_OP_CREATED == op or sr.SR_OP_MODIFIED == op then
        ctx["uctx"]:set(ucipath[1],ucipath[2],ucipath[3],new_val:val_to_string())
    else
        ctx["uctx"]:delete(ucipath[1],ucipath[2],ucipath[3])
    end
    ctx["uctx"]:commit(ucipath[1])
end

local function sysrepo_to_uci(ctx, op, old_val, new_val, event)
    local orig_xpath
    if sr.SR_OP_CREATED == op or sr.SR_OP_MODIFIED == op then
        orig_xpath = new_val:xpath()
    else
        orig_xpath = old_val:xpath()
    end

    local key = get_key_value(orig_xpath)
    local second_key = get_second_key_value(orig_xpath)

    for _, v in pairs(ctx["map"]) do
        local ucipath = {v["ucipath"][1], key, v["ucipath"][2]}
        local xpath = string.format(v["xpath"],key,second_key)
        if xpath == orig_xpath then
            sr_option_cb(ctx, op, old_val, new_val, ucipath)
        end
    end

end

-- Function to be called for subscribed client of given session whenever configuration changes.
local function module_change_cb(sess, module_name, event, private_ctx)
    io.write("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n")

    local function run()
        print_current_config(sess, module_name)

        io.write("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n")

        io.write("\n\n ========== CHANGES: =============================================\n\n")

        local change_path = "/" .. module_name .. ":*"

        local it = sess:get_changes_iter(change_path);

        while true do
            local change = sess:get_change_next(it)
            if (change == nil) then break end
            print_change(change:oper(), change:old_val(), change:new_val())
            sysrepo_to_uci(g_ctx, change:oper(), change:old_val(), change:new_val(), event)
	    end

	    io.write("\n\n ========== END OF CHANGES =======================================\n\n")

        collectgarbage()
    end

    local ok,res=pcall(run)
    if not ok then
        io.write("\nerror: ",res, "\n")
        return tonumber(sr.SR_ERR_OPERATION_FAILED)
    end

    return tonumber(sr.SR_ERR_OK)
end

local function uci_option_cb(ctx, xpath, ucipath)
    -- set the default type
    if "type" == ucipath[3] then
        ctx["startup_sess"]:set_item_str(xpath, "iana-if-type:ethernetCsmacd", sr.SR_EDIT_DEFAULT)
        return
    end
    local uci_ret = ctx["uctx"]:get(ucipath[1], ucipath[2], ucipath[3])
    if nil ~= uci_ret then
        ctx["startup_sess"]:set_item_str(xpath, uci_ret, sr.SR_EDIT_DEFAULT)
    end
end

local function parse_uci_config(ctx, key)

    for _, v in pairs(ctx["map"]) do
        local ucipath = {v["ucipath"][1], key, v["ucipath"][2]}
        local ipaddr = ctx["uctx"]:get(ucipath[1], key, "ipaddr")
        if nil ~= ipaddr then
            local xpath = string.format(v["xpath"],key,ipaddr)
            uci_option_cb(ctx, xpath, ucipath)
        end
    end
end

local function sr_uci_init_data(ctx, config_file, uci_sections)
    local rc = sr.SR_ERR_OK
    local get = uctx.get_all(config_file)

    for _, v in pairs(get) do
        for _, v2 in pairs(uci_sections) do
            if v[".type"] == v2 then
                parse_uci_config(ctx, v[".name"])
            end
        end
    end

    ctx["startup_sess"]:commit()

    return rc
end

local function sync_datastores(ctx)
    local startup_file =  "/etc/sysrepo/data/"..ctx["yang_model"]..".startup"
    local uci = require("uci")
    local rc

    local uctx = uci.cursor()
    ctx["uctx"] = uctx

    local lines = {}
    for line in io.lines(startup_file) do
        lines[#lines + 1] = line
    end

    if 0 == #lines then
        io.write("copy uci data to sysrepo\n")
        rc = sr_uci_init_data(ctx, ctx["config_file"], ctx["uci_sections"])
    else
        io.write("copy sysrepo data to uci\n")
        rc = sr.SR_ERR_OK
    end

    return rc
end

local function load_startup_datastore(ctx)
    local conn = sr.Connection(ctx["yang_model"])
    local sess = sr.Session(conn, sr.SR_DS_STARTUP, sr.SR_SESS_CONFIG_ONLY)

    if nil == conn or nil == sess then
        return sr.SR_ERR_INTERNAL
    end

    ctx["startup_conn"] = conn
    ctx["startup_sess"] = sess

    return sr.SR_ERR_OK
end

local function sr_plugin_init_cb(session)
    local rc
    local ctx = g_ctx
    ctx["yang_model"] = yang_model
    ctx["sess"] = session
    ctx["sub"] = sr.Subscribe(session)
    ctx["config_file"] = "network"
    ctx["uci_sections"] = {"interface"}
    ctx["map"] = table_sr_uci

    rc = load_startup_datastore(ctx)
    if sr.SR_ERR_OK ~= rc then
        return sr.SR_ERR_INTERNAL
    end

    rc = sync_datastores(ctx)
    if sr.SR_ERR_OK ~= rc then
        return sr.SR_ERR_INTERNAL
    end

    local wrap = sr.Callback_lua(module_change_cb)
    ctx["sub"]:module_change_subscribe(yang_model, wrap);

    return sr.SR_ERR_OK
end

-- Main client function.
local function run()
    local conn = sr.Connection("application")
    local sess = sr.Session(conn)

    local rc = sr_plugin_init_cb(sess)
    if sr.SR_ERR_OK ~= rc then
        return
    end

    sr.global_loop()

    io.write("Application exit requested, exiting.\n\n");
end

local ok,res=pcall(run)
if not ok then
    io.write("\nerror: ",res, "\n")
end
