-- empwifi: employee hotel-wifi RPC backend for GL.iNet firmware 4.x
-- Admin methods (admin_*) require a logged-in admin session (root aclgroup), enforced by
-- the oui dispatcher. Employee methods (emp_*) are registered as no-auth (see postinst)
-- and enforce an employee password + short-lived token inside this module, because the
-- public /wifi page is unauthenticated and anyone on the LAN can reach /rpc.
--
-- WiFi work is delegated to the stock `repeater` RPC module; this module only gates access
-- and passes a whitelisted argument set, so employees can never reach advanced settings.

local rpc = require "oui.rpc"
local uci = require "uci"

local M = {}

local CONFIG = "empwifi"
local TOKEN_FILE = "/tmp/empwifi.session"
local FAIL_FILE = "/tmp/empwifi.fail"
local TOKEN_TTL = 3600
local FAIL_MAX = 10
local FAIL_WINDOW = 300

local function tohex(s)
    return (s:gsub('.', function(c) return string.format('%02x', c:byte()) end))
end

local function read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local d = f:read("*a")
    f:close()
    return d
end

local function rand_hex(n)
    -- read EXACTLY n bytes; never f:read("*a") on /dev/urandom (it never EOFs -> OOM)
    local f = io.open("/dev/urandom", "rb")
    local b
    if f then
        b = f:read(n)
        f:close()
    end
    if b and #b >= n then return tohex(b) end
    -- fallback: time-seeded, low entropy but never blank
    return tohex(ngx.sha1_bin(tostring(ngx.now()) .. ":" .. tostring(os.time())))
end

local function hash_pw(salt, pw)
    -- salted SHA-1 with light key-stretching (no external deps in the nginx Lua env);
    -- raises offline-cracking cost well above a single hash for this shared-gate use.
    local h = ngx.sha1_bin((salt or "") .. ":" .. (pw or ""))
    for _ = 1, 4096 do h = ngx.sha1_bin(h .. (pw or "")) end
    return tohex(h)
end

-- reject NUL and control characters (a string with none is safe to hand downstream)
local function printable(s)
    return type(s) == "string" and s:find("%c") == nil
end

-- best-effort: keep /tmp state files out of "other" reads (paths are constants -> no injection)
local function chmod_600(path)
    os.execute("chmod 600 '" .. path .. "' 2>/dev/null")
end

local function get(opt, default)
    local v = uci.cursor():get(CONFIG, "global", opt)
    if v == nil then return default end
    return v
end

-- Capability probe: camouflage ("disguise") support is chipset-dependent. Detect it from
-- the installed repeater module rather than assuming, so non-supporting devices degrade.
local function camouflage_supported()
    local c = read_file("/usr/lib/oui-httpd/rpc/repeater")
    return c ~= nil and c:find("disguise", 1, true) ~= nil
end

-- token handling -------------------------------------------------------------

local function new_token()
    local tok = rand_hex(16)
    local f = io.open(TOKEN_FILE, "w")
    if f then
        f:write(tok .. " " .. tostring(os.time() + TOKEN_TTL))
        f:close()
        chmod_600(TOKEN_FILE)
    end
    return tok
end

local function token_valid(tok)
    if get("no_password", "0") == "1" then return true end
    if type(tok) ~= "string" or #tok < 8 then return false end
    local line = read_file(TOKEN_FILE)
    if not line then return false end
    local stored, exp = line:match("^(%S+)%s+(%d+)")
    if not stored or stored ~= tok then return false end
    return os.time() <= (tonumber(exp) or 0)
end

-- simple lockout on repeated bad employee logins
local function fail_state()
    local line = read_file(FAIL_FILE)
    if not line then return 0, 0 end
    local cnt, ts = line:match("^(%d+)%s+(%d+)")
    return tonumber(cnt) or 0, tonumber(ts) or 0
end

local function fail_ok()
    local cnt, ts = fail_state()
    if os.time() - ts > FAIL_WINDOW then return true end
    return cnt < FAIL_MAX
end

local function fail_record()
    local cnt, ts = fail_state()
    if os.time() - ts > FAIL_WINDOW then cnt, ts = 0, os.time() end
    local f = io.open(FAIL_FILE, "w")
    if f then f:write((cnt + 1) .. " " .. ts); f:close(); chmod_600(FAIL_FILE) end
end

local function fail_reset()
    os.remove(FAIL_FILE)
end

local function authed(args)
    return token_valid(args and args.token)
end

-- admin methods (admin session required by dispatcher) -----------------------

function M.admin_get_config()
    return {
        no_password = get("no_password", "0") == "1",
        has_password = get("emp_password", "") ~= "",
        camouflage_default = get("camouflage_default", "1") == "1",
        camouflage_supported = camouflage_supported()
    }
end

function M.admin_set_config(args)
    args = args or {}
    local c = uci.cursor()

    if not c:get(CONFIG, "global") then
        c:set(CONFIG, "global", "empwifi")
    end

    if type(args.no_password) == "boolean" then
        c:set(CONFIG, "global", "no_password", args.no_password and "1" or "0")
    end

    if type(args.camouflage_default) == "boolean" then
        c:set(CONFIG, "global", "camouflage_default", args.camouflage_default and "1" or "0")
    end

    if args.clear_password == true then
        c:set(CONFIG, "global", "emp_password", "")
        c:set(CONFIG, "global", "pw_salt", "")
    elseif type(args.emp_password) == "string" and #args.emp_password > 0 then
        if #args.emp_password > 128 then
            return rpc.ERROR_CODE_INVALID_PARAMS, "password_too_long"
        end
        local salt = rand_hex(8)
        c:set(CONFIG, "global", "pw_salt", salt)
        c:set(CONFIG, "global", "emp_password", hash_pw(salt, args.emp_password))
    end

    c:commit(CONFIG)
    return M.admin_get_config()
end

-- employee methods (no-auth at oui layer; gated here) ------------------------

function M.emp_login(args)
    args = args or {}

    if get("no_password", "0") == "1" then
        return { token = new_token(), no_password = true }
    end

    if not fail_ok() then
        return rpc.ERROR_CODE_ACCESS, "locked_out"
    end

    local stored = get("emp_password", "")
    if stored == "" then
        return rpc.ERROR_CODE_ACCESS, "not_configured"
    end

    local salt = get("pw_salt", "")
    if type(args.password) ~= "string" or hash_pw(salt, args.password) ~= stored then
        fail_record()
        return rpc.ERROR_CODE_ACCESS, "bad_password"
    end

    fail_reset()
    return { token = new_token() }
end

function M.emp_scan(args)
    if not authed(args) then return rpc.ERROR_CODE_ACCESS, "unauthorized" end

    local res = rpc.call("repeater", "scan", {})
    if type(res) ~= "table" then return rpc.ERROR_CODE_INTERNAL_ERROR, "scan_failed" end

    -- repeater.scan -> { res = { {ssid, bssid, band, channel, signal,
    --   encryption = {enabled, description}}, ... } }. Expose only what the page needs.
    local src = res.res or res.results or res.list or {}
    local out = {}
    if type(src) == "table" then
        for _, ap in ipairs(src) do
            if type(ap) == "table" and ap.ssid and ap.ssid ~= "" then
                local enc = ap.encryption
                local secured = type(enc) == "table" and enc.enabled == true or false
                out[#out + 1] = {
                    ssid = ap.ssid,
                    bssid = ap.bssid,
                    band = ap.band,
                    signal = ap.signal,
                    secured = secured,
                    encryption = type(enc) == "table" and enc.description or ""
                }
            end
        end
    end
    return { list = out }
end

function M.emp_join(args)
    if not authed(args) then return rpc.ERROR_CODE_ACCESS, "unauthorized" end
    args = args or {}

    if type(args.ssid) ~= "string" or #args.ssid == 0 or #args.ssid > 32 or not printable(args.ssid) then
        return rpc.ERROR_CODE_INVALID_PARAMS, "invalid_ssid"
    end

    local key = args.key
    if key ~= nil and type(key) ~= "string" then
        return rpc.ERROR_CODE_INVALID_PARAMS, "invalid_key"
    end
    if type(key) == "string" and (#key > 64 or (#key > 0 and not printable(key))) then
        return rpc.ERROR_CODE_INVALID_PARAMS, "invalid_key"
    end

    -- whitelist: only ssid/key/disguise reach the repeater. No advanced fields, ever.
    local connect_args = { ssid = args.ssid }
    if type(key) == "string" and #key > 0 then
        connect_args.key = key
    end
    if camouflage_supported() and get("camouflage_default", "1") == "1" then
        connect_args.disguise = 1
    end

    local res = rpc.call("repeater", "connect", connect_args)
    if type(res) == "number" then return res, "connect_failed" end
    return { ok = true }
end

function M.emp_status(args)
    if not authed(args) then return rpc.ERROR_CODE_ACCESS, "unauthorized" end

    local res = rpc.call("repeater", "get_status", {})
    if type(res) ~= "table" then return {} end

    -- repeater.get_status: state==2/state_s=="connected" when up; `connected` is an uptime
    -- string; ip is under ipv4.ip. Normalise to a clean boolean for the page.
    return {
        connected = res.state == 2 or res.state_s == "connected" or false,
        state = res.state_s or res.state,
        ssid = res.ssid,
        uptime = res.connected,
        signal = res.signal,
        ip = type(res.ipv4) == "table" and res.ipv4.ip or res.ip
    }
end

function M.emp_list(args)
    if not authed(args) then return rpc.ERROR_CODE_ACCESS, "unauthorized" end

    local out = {}
    uci.cursor():foreach("repeater", "network", function(s)
        if s.ssid then out[#out + 1] = { ssid = s.ssid } end
    end)
    return { list = out }
end

return M
