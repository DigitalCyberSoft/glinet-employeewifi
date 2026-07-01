-- empwifi: employee guest-wifi RPC backend for GL.iNet firmware 4.x
-- Admin methods (admin_*) require a logged-in admin session (root aclgroup), enforced by
-- the oui dispatcher. Employee methods (emp_*) are registered as no-auth (see postinst)
-- and enforce an employee password + short-lived token inside this module, because the
-- public /wifi page is unauthenticated and anyone on the LAN can reach /rpc.
--
-- WiFi work is delegated to the stock `repeater` RPC module; this module only gates access
-- and passes a whitelisted argument set, so employees can never reach advanced settings.

local rpc = require "oui.rpc"
local uci = require "uci"
local ubus = require "oui.ubus"

local M = {}

local CONFIG = "empwifi"
local TOKEN_FILE = "/tmp/empwifi.session"
local FAIL_FILE = "/tmp/empwifi.fail"
local TOKEN_TTL = 3600
local MAX_TOKENS = 20          -- cap concurrent employee sessions (bounds /tmp session file)
local FAIL_MAX = 5
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
    -- read EXACTLY n bytes; never f:read("*a") on /dev/urandom (it never EOFs -> OOM).
    -- Fail CLOSED: if the CSPRNG is unavailable, return nil so callers refuse to issue a
    -- token/salt rather than fall back to a time-seeded (predictable) value.
    local f = io.open("/dev/urandom", "rb")
    if not f then return nil end
    local b = f:read(n)
    f:close()
    if not b or #b < n then return nil end
    return tohex(b)
end

-- constant-time string equality (no early-exit byte compare). Token/hash are fixed length,
-- so leaking length via the #a ~= #b check is not sensitive.
local function consttime_eq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do
        if a:byte(i) ~= b:byte(i) then diff = diff + 1 end
    end
    return diff == 0
end

local function hash_pw(salt, pw)
    -- salted SHA-1 with light key-stretching (no external deps in the nginx Lua env);
    -- raises offline-cracking cost well above a single hash for this shared-gate use.
    local h = ngx.sha1_bin((salt or "") .. ":" .. (pw or ""))
    for _ = 1, 4096 do h = ngx.sha1_bin(h .. (pw or "")) end
    return tohex(h)
end

-- Reject NUL and control characters. This is the maximal input-layer filter we can apply
-- to ssid/key: it blocks the real injection vector (newline/CR breaking out into a new
-- UCI / wpa_supplicant config line). We deliberately do NOT charset-restrict beyond this:
-- legitimate SSIDs contain '&' ("AT&T WiFi"), "'" ("Joe's Coffee"), spaces, '('; legitimate
-- WPA passphrases contain '$ & ! @ #'. A shell-metachar whitelist would break exactly the
-- networks employees need to join. ssid/key are passed to repeater.connect as a Lua TABLE
-- (no shell in this module); shell-safety of those values is GL's repeater module's job,
-- which its own admin UI relies on identically. (Verify on-device: probe SSID `a$(id)b`.)
local function printable(s)
    return type(s) == "string" and s:find("%c") == nil
end

-- CSRF guard for the no-auth employee surface. A cross-origin attacker page can send a
-- "simple" POST (text/plain) to /rpc with no preflight, but CANNOT set a custom header
-- without triggering one. Requiring X-Empwifi on every emp_* call defeats that path; the
-- public /wifi page sets it. (curl callers must add `-H 'X-Empwifi: 1'`.)
local function csrf_ok()
    local h = ngx.req.get_headers()
    return type(h) == "table" and h["x-empwifi"] ~= nil
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

-- An auto-generated password is written as PLAINTEXT by postinst (the shell has no
-- ngx.sha1_bin to hash with). On the first RPC touch, hash it into emp_password/pw_salt so
-- login verifies normally. The plaintext is kept in emp_password_plain solely so the
-- admin-gated page can display it to hand out; no emp_* (no-auth) method ever returns it.
local function ensure_materialized()
    local plain = get("emp_password_plain", "")
    if plain ~= "" and get("emp_password", "") == "" then
        local salt = rand_hex(8)
        if not salt then return end
        local c = uci.cursor()
        c:set(CONFIG, "global", "pw_salt", salt)
        c:set(CONFIG, "global", "emp_password", hash_pw(salt, plain))
        c:commit(CONFIG)
    end
end

-- token handling -------------------------------------------------------------

-- The session file holds one "token expiry" line per active employee, so concurrent staff
-- do not evict each other. Reads prune expired lines; writes cap to MAX_TOKENS.
local function live_tokens()
    local now = os.time()
    local out = {}
    local data = read_file(TOKEN_FILE)
    if data then
        for tok, exp in data:gmatch("(%S+)%s+(%d+)") do
            if now <= (tonumber(exp) or 0) then out[#out + 1] = { tok = tok, exp = tonumber(exp) } end
        end
    end
    return out
end

local function write_tokens(list)
    local f = io.open(TOKEN_FILE, "w")
    if not f then return false end
    local first = math.max(1, #list - MAX_TOKENS + 1)
    for i = first, #list do
        f:write(list[i].tok .. " " .. tostring(list[i].exp) .. "\n")
    end
    f:close()
    chmod_600(TOKEN_FILE)
    return true
end

local function new_token()
    local tok = rand_hex(16)
    if not tok then return nil end          -- CSPRNG unavailable -> refuse to issue a token
    local list = live_tokens()
    list[#list + 1] = { tok = tok, exp = os.time() + TOKEN_TTL }
    if not write_tokens(list) then return nil end
    return tok
end

local function token_valid(tok)
    if get("no_password", "0") == "1" then return true end
    if type(tok) ~= "string" or #tok < 8 then return false end
    for _, e in ipairs(live_tokens()) do
        if consttime_eq(e.tok, tok) then return true end
    end
    return false
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

local function authed(args)
    return csrf_ok() and token_valid(args and args.token)
end

-- admin methods (admin session required by dispatcher) -----------------------

function M.admin_get_config()
    ensure_materialized()
    return {
        no_password = get("no_password", "0") == "1",
        has_password = get("emp_password", "") ~= "",
        -- non-empty only while an auto-generated password is in effect (cleared once the
        -- admin sets their own); admin-gated method, so safe to return for display.
        generated_password = get("emp_password_plain", ""),
        camouflage_default = get("camouflage_default", "1") == "1",
        camouflage_supported = camouflage_supported(),
        banner_text = get("banner_text", ""),
        banner_scope = get("banner_scope", "both")
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
        c:set(CONFIG, "global", "emp_password_plain", "")
    elseif type(args.emp_password) == "string" and #args.emp_password > 0 then
        if #args.emp_password < 8 then
            return rpc.ERROR_CODE_INVALID_PARAMS, "password_too_short"
        end
        if #args.emp_password > 128 then
            return rpc.ERROR_CODE_INVALID_PARAMS, "password_too_long"
        end
        local salt = rand_hex(8)
        if not salt then
            return rpc.ERROR_CODE_INTERNAL_ERROR, "rng_unavailable"
        end
        c:set(CONFIG, "global", "pw_salt", salt)
        c:set(CONFIG, "global", "emp_password", hash_pw(salt, args.emp_password))
        -- admin chose their own password -> stop displaying the auto-generated one
        c:set(CONFIG, "global", "emp_password_plain", "")
    end

    -- Admin-authored banner for the public /wifi page. Stored raw and rendered as
    -- textContent on that page (never innerHTML), so no HTML/script can execute; the
    -- printable() control-char filter additionally keeps it single-line. Length-capped.
    if type(args.banner_text) == "string" then
        if #args.banner_text > 280 then
            return rpc.ERROR_CODE_INVALID_PARAMS, "banner_too_long"
        end
        if args.banner_text ~= "" and not printable(args.banner_text) then
            return rpc.ERROR_CODE_INVALID_PARAMS, "banner_invalid"
        end
        c:set(CONFIG, "global", "banner_text", args.banner_text)
    end
    if type(args.banner_scope) == "string" then
        local sc = args.banner_scope
        if sc ~= "off" and sc ~= "unauth" and sc ~= "authed" and sc ~= "both" then
            return rpc.ERROR_CODE_INVALID_PARAMS, "banner_scope_invalid"
        end
        c:set(CONFIG, "global", "banner_scope", sc)
    end

    c:commit(CONFIG)
    return M.admin_get_config()
end

-- employee methods (no-auth at oui layer; gated here) ------------------------

function M.emp_login(args)
    if not csrf_ok() then return rpc.ERROR_CODE_ACCESS, "unauthorized" end
    args = args or {}
    ensure_materialized()   -- make an auto-generated password usable before first admin visit

    if get("no_password", "0") == "1" then
        local tok = new_token()
        if not tok then return rpc.ERROR_CODE_INTERNAL_ERROR, "token_failed" end
        return { token = tok, no_password = true }
    end

    if not fail_ok() then
        return rpc.ERROR_CODE_ACCESS, "locked_out"
    end

    local stored = get("emp_password", "")
    if stored == "" then
        return rpc.ERROR_CODE_ACCESS, "not_configured"
    end

    local salt = get("pw_salt", "")
    if type(args.password) ~= "string" or not consttime_eq(hash_pw(salt, args.password), stored) then
        -- Deliberately do NOT reset the failure counter on an interleaved success: a legit
        -- login must not wipe an attacker's in-progress brute-force budget. The window decay
        -- in fail_record() is the only thing that clears it.
        fail_record()
        return rpc.ERROR_CODE_ACCESS, "bad_password"
    end

    local tok = new_token()
    if not tok then return rpc.ERROR_CODE_INTERNAL_ERROR, "token_failed" end
    return { token = tok }
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

-- CPU temperature from thermal-zone sysfs (millidegrees C). Prefer a zone whose type names
-- "cpu"; else the first present zone. Returns an integer degC, or nil if unreadable.
local function cpu_temp()
    local zone
    for z = 0, 9 do
        local ty = read_file("/sys/class/thermal/thermal_zone" .. z .. "/type")
        if not ty then break end
        if zone == nil then zone = z end                            -- fallback: first zone
        if ty:lower():find("cpu", 1, true) then zone = z; break end -- prefer a cpu zone
    end
    if zone == nil then return nil end
    local raw = read_file("/sys/class/thermal/thermal_zone" .. zone .. "/temp")
    local n = raw and tonumber(raw:match("%-?%d+"))
    if not n then return nil end
    if n >= 1000 or n <= -1000 then n = n / 1000 end                -- millidegrees -> degrees
    return math.floor(n + 0.5)
end

-- No-auth device status + banner for the public /wifi page. CPU temp is a direct sysfs read;
-- battery comes from the MCU object directly (light, and the PSK-bearing system.get_status
-- blob is never touched). "mcu" is the GL battery MCU (e.g. gl-puli-mcu on the XE3000); if it
-- is absent or named differently on another battery model, fall back to the portable
-- system.get_status aggregate so the widget still works fleet-wide. Devices with no battery
-- (no mcu object, no system.mcu, e.g. GL-MT1300 Beryl) yield has_battery=false and the page
-- hides the battery widget. No token required (status/banner readable pre-login); CSRF header
-- still enforced for consistency with the rest of the emp_* surface.
function M.emp_health(args)
    if not csrf_ok() then return rpc.ERROR_CODE_ACCESS, "unauthorized" end
    args = args or {}
    local out = {}

    local ct = cpu_temp()
    if ct then out.cpu_temp = ct end

    local m = ubus.call("mcu", "status", {})
    if not (type(m) == "table" and type(m.charge_percent) == "number") then
        local s = rpc.call("system", "get_status", {})   -- fallback: portable aggregate
        m = (type(s) == "table" and type(s.system) == "table") and s.system.mcu or nil
    end
    if type(m) == "table" and type(m.charge_percent) == "number" then
        out.has_battery = true
        out.battery = m.charge_percent
        out.charging = (m.charging_status or 0) ~= 0
        if type(m.temperature) == "number" then out.mcu_temp = m.temperature end
    end

    -- 1-minute CPU load average (direct /proc read; cheaper than system.get_status).
    local la = read_file("/proc/loadavg")
    local one = la and la:match("^%s*([%d%.]+)")
    if one then out.load = tonumber(one) end

    -- Banner shown per admin scope (off|unauth|authed|both). "authed" == the caller holds a
    -- valid employee token (token_valid is also true in no-password mode: no gate to be
    -- behind). Gated here so a scope=authed banner never reaches an unauthenticated caller.
    local text = get("banner_text", "")
    local scope = get("banner_scope", "both")
    if text ~= "" and scope ~= "off" then
        local is_authed = token_valid(args.token)
        if scope == "both"
            or (scope == "unauth" and not is_authed)
            or (scope == "authed" and is_authed) then
            out.banner = text
        end
    end

    return out
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
