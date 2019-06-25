local utils = require 'waf.utils'
local config = require 'waf.config'
local ngxmatch = ngx.re.find
local unescape = ngx.unescape_uri
local get_headers = ngx.req.get_headers
local _M = {}

local function get_client_ip()
    local IP = ngx.var.remote_addr
    if IP == nil then
        IP = "unknown"
    end
    return IP
end

local function waf_white_ip(ip)
    return utils.match_ip(ip, config.getWhiteIp(), config.getWhiteIpPrefix())
end

local function waf_black_ip(ip)
    return utils.match_ip(ip, config.getBlackIp(), config.getBlackIpPrefix())
end

local function waf_deny_cc(ip)
    if config.getCCCount() < 1 or config.getCCSeconds() < 1 then
        return false
    end
    local uri = ngx.var.uri
    local token = ip .. uri
    local limit = ngx.shared.limit
    local req, _ = limit:get(token)
    if req then
        if req >= config.getCCCount() then
            return true
        else
            limit:incr(token, 1)
        end
    else
        limit:set(token, 1, config.getCCSeconds())
    end
    return false
end

local function waf_check_ua()
    if config.getPatternUa() == nil then
        return false
    end
    local ua = ngx.var.http_user_agent
    if ua ~= nil and #ua > 0 then
        for _, rule in pairs(config.getPatternUa()) do
            if rule ~= "" and ngxmatch(ua, rule, "isjo") then
                -- TODO logging
                --waf_log('UA', ngx.var.request_uri, "-", rule) -- logging
                --say_html()
                return true
            end
        end
    end
    return false
end

local function waf_check_url()
    if config.getPatternUrl() == nil then
        return false
    end
    for _, rule in pairs(config.getPatternUrl()) do
        if rule ~= "" and ngxmatch(ngx.var.request_uri, rule, "isjo") then
            -- TODO logging
            -- waf_log('GET', ngx.var.request_uri, "-", rule)
            -- say_html()
            return true
        end
    end
    return false
end

local function waf_check_args()
    if config.getPatternArgs() == nil then
        return false
    end
    local args = ngx.req.get_uri_args()
    for _, rule in pairs(config.getPatternArgs()) do
        for _, val in pairs(args) do
            local data = val
            -- for list type
            if type(val) == 'table' then
                if val ~= false then
                    data = table.concat(val, " ")
                end
            end
            if data and type(data) ~= "boolean" and rule ~= "" and ngxmatch(unescape(data), rule, "isjo") then
                -- TODO logging
                -- waf_log('GET', ngx.var.request_uri, "-", rule)
                -- say_html()
                return true
            end
        end
    end
    return false
end

local function waf_check_cookie()
    if config.getPatternCookie() == nil then
        return false
    end
    local ck = ngx.var.http_cookie
    if ck then
        for _, rule in pairs(config.getPatternCookie()) do
            if rule ~= "" and ngxmatch(ck, rule, "isjo") then
                -- TODO logging
                -- waf_log('Cookie', ngx.var.request_uri, "-", rule)
                -- say_html()
                return true
            end
        end
    end
    return false
end

local function has_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return false
    end

    if type(header) == "table" then
        header = header[1]
    end
    
    if header == nil or #header < 1 then
        return false
    end

    local m = ngxmatch(header, ";\\s*boundary=\"([^\"]+)\"")
    if m then
        return true
    end

    m = ngxmatch(header, ";\\s*boundary=([^\",;]+)")
    if m then
        return true;
    end
    
    return false
end

local function check_file_ext(ext)
    ext = string.lower(ext)
    if ext then
        for rule in pairs(config.getBlackFileExts()) do
            if ngxmatch(ext, rule, "isjo") then
                -- waf_log('POST', ngx.var.request_uri, "-", "file attack with ext " .. ext)
                -- say_html()
                return true
            end
        end
    end
    return false
end

local function check_body(data)
    for _, rule in pairs(config.getPatternPost()) do
        if rule ~= nil and data ~= nil and #rule > 0 and #data > 0 and ngxmatch(unescape(data), rule, "isjo") then
        print(rule)
            -- TODO logging
            -- waf_log('POST', ngx.var.request_uri, data, rule)
            -- say_html()
            return true
        end
    end
    return false
end

local function waf_check_post()
    if config.getPatternPost() == nil then
        return false
    end
    local method = ngx.req.get_method()
    if method ~= "POST" then return false end
    local ret = has_boundary()
    if ret then
        -- multipart
        local len = string.len
        local sock, err = ngx.req.socket()
        if not sock then
            return
        end
        ngx.req.init_body(128 * 1024)
        sock:settimeout(0)
        local content_length = nil
        content_length = tonumber(get_headers()['content-length'])
        local chunk_size = 4096
        if content_length < chunk_size then
            chunk_size = content_length
        end
        local size = 0
        while size < content_length do
            local data, err, partial = sock:receive(chunk_size)
            data = data or partial
            if not data then
                return
            end
            ngx.req.append_body(data)
            if check_body(data) then
                return true
            end
            size = size + len(data)
            local m = ngx.re.match(data, "Content-Disposition: form-data;(.+)filename=\"(.+)\\.([^\".]*)\"", 'ijo')
            if m then
                if check_file_ext(m[3]) then
                    return true
                end
            else
                local filetranslate = true
                if ngxmatch(data, "Content-Disposition:", 'isjo') then
                    filetranslate = false
                end
                if filetranslate == false then
                    if check_body(data) then
                        return true
                    end
                end
            end
            local less = content_length - size
            if less < chunk_size then
                chunk_size = less
            end
        end
        ngx.req.finish_body()
    else
        -- form-encoded
        ngx.req.read_body()
        local args = ngx.req.get_post_args()
        if not args then
            return
        end
        for _, val in pairs(args) do
            local data = val
            if type(val) == "table" then
                if type(val[1]) == "boolean" then
                    return
                end
                data = table.concat(val, ", ")
            end
            if data and type(data) ~= "boolean" and check_body(data) then
                return true
            end
        end
    end
end

local function _filter()
    local client_ip = get_client_ip()
    if config.enableWhiteIp() and waf_white_ip(client_ip) then
        -- white ip, pass
    elseif config.enableBlackIp() and waf_black_ip(client_ip) then
        ngx.exit(403)
    elseif config.enableCc() and waf_deny_cc(client_ip) then -- need to be per domain ?
        ngx.exit(503)
    elseif ngx.var.http_Acunetix_Aspect ~= nil or ngx.var.http_X_Scan_Memo ~= nil then
        ngx.exit(409)
--    elseif waf_white_url() then -- need to be per domain ?
    elseif config.enableUa() and waf_check_ua() then
        -- TODO logging & json/html output
        ngx.exit(403)
    elseif config.enableUrl() and waf_check_url() then
        -- TODO logging & json/html output
        ngx.exit(403)
    elseif config.enableArgs() and waf_check_args() then
        -- TODO logging & json/html output
        ngx.exit(403)
    elseif config.enableCookie() and waf_check_cookie() then
        -- TODO logging & json/html output
        ngx.exit(403)
    elseif config.enablePost() and waf_check_post() then
        -- TODO logging & json/html output
        ngx.exit(403)
    else
        return
    end
end

_M.filter = function()
    if not config.enable() then
        return
    end
    _filter()
end

return _M