local table_sr_uci = {
    ucipath={"network","ipaddr"}, xpath="/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/ip"
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

local yang_model = "ietf-interfaces"

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

local function sr_uci_init_data(ctx, config_file, uci_sections)
    local rc = sr.SR_ERR_OK
    local uci = require("uci")

    local uctx = uci.cursor()

    local get = uctx.get_all(config_file)

    for k, v in pairs(get) do
        if v[".type"] == uci_sections then
            io.write("match\n")
        end
        print(k, v[".type"])
        if nil ~= v["ipaddr"] then
        io.write(config_file,".",k,".ipaddr=",v["ipaddr"],"\n")
        end
    end

    return rc
end

local function sync_datastores(ctx)
    local startup_file =  "/etc/sysrepo/data/"..ctx["yang_model"]..".startup"
    local rc

    local lines = {}
    for line in io.lines(startup_file) do
        lines[#lines + 1] = line
    end

    if 0 == #lines then
        io.write("copy uci data to sysrepo\n")
        rc = sr_uci_init_data(ctx, ctx["config_file"], ctx["uci_sections"])
    else
        io.write("copy sysrepo data to uci\n")
        rc = sr_uci_init_data(ctx, ctx["config_file"], ctx["uci_sections"])
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
    local ctx = {}
    ctx["yang_model"] = yang_model
    ctx["sess"] = session
    ctx["sub"] = sr.Subscribe(session)
    ctx["config_file"] = "network"
    ctx["uci_sections"] = "interface"
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
