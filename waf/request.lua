local utils = require 'waf.utils'
local _M = {}

local function get_client_ip()
    local IP = ngx.var.remote_addr
    if IP == nil then
        IP = "unknown"
    end
    return IP
end

local function waf_white_ip(ip)
    return utils.match_ip(ip, arrIpWhiteList, arrIpPrefixWhiteList)
end

_M.waf_filter = function ()
    local client_ip = get_client_ip()
    if waf_white_ip(client_ip) then -- need to be dynamic
--    elseif waf_block_ip() then -- need to be dynamic
--    elseif waf_deny_cc() then -- need to be per domain ?
--    elseif ngx.var.http_Acunetix_Aspect then
--        ngx.exit(409)
--    elseif ngx.var.http_X_Scan_Memo then
--        ngx.exit(409)
--    elseif waf_white_url() then -- need to be per domain ?
--    elseif waf_check_ua() then
--    elseif waf_check_url() then
--    elseif waf_check_args() then
--    elseif waf_check_cookie() then
--    elseif waf_check_post() then
    else
        return
    end
end

return _M