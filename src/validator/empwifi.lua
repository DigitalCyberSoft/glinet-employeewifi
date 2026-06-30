-- Per-method validation gate for the oui dispatcher.
-- All methods are set to `true` (skip framework arg validation) deliberately: the default
-- string pattern (^[%w%.%s%-_:#/]-$) would reject many valid WiFi passwords. empwifi.lua
-- validates every argument in-handler (type, length, allowed fields) instead.
return {
    admin_get_config = true,
    admin_set_config = true,
    emp_login = true,
    emp_scan = true,
    emp_join = true,
    emp_status = true,
    emp_list = true
}
