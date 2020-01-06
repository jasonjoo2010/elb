local utils = require 'waf.utils'
local config = require 'waf.config'
local rules = require 'elb.rules'
local ngxmatch = ngx.re.find
local unescape = ngx.unescape_uri
local get_headers = ngx.req.get_headers
local _M = {}

local deny_msg = {}
deny_msg[403] = 'forbidden';
deny_msg[503] = 'not avaliable';
deny_msg[499] = 'not supported';

local function waf_log(realIp, ruleType, rule, data)
    local ua = ngx.var.http_user_agent
    local servername = ngx.req.get_headers()["Host"]
    local method = ngx.req.get_method()
    local url = ngx.var.request_uri
    local line = {}
    table.insert(line, "waf_block_log: ")
    table.insert(line, ngx.time())
    table.insert(line, "\t\"")
    table.insert(line, realIp)
    table.insert(line, "\"\t\"")
    table.insert(line, servername)
    table.insert(line, "\"\t\"")
    table.insert(line, method)
    table.insert(line, "\"\t\"")
    table.insert(line, url)
    table.insert(line, "\"\t\"")
    table.insert(line, ua)
    table.insert(line, "\"\t\"")
    table.insert(line, ruleType)
    table.insert(line, "\"\t\"")
    table.insert(line, rule)
    table.insert(line, "\"\t\"")
    table.insert(line, data)
    table.insert(line, "\"")
    --local misc = ngx.shared.misc
    --misc:rpush("waf_logging", line)
    -- now use ngx.log
    ngx.log(ngx.ERR, table.concat(line))
end

local function get_client_ip()
    local IP = ngx.var.remote_addr
    if IP == nil then
        IP = "unknown"
    end
    return IP
end

local function waf_ip(ip, domain, list_name, prefix_list_name)
    local ipList, ipListDomain = config.getConfigList(domain, list_name)
    local ipListPrefix, ipListPrefixDomain = config.getConfigList(domain, prefix_list_name)
    
    if ipList == nil and ipListPrefix == nil then
        return false
    end
    if utils.match_ip(ip, ipList, ipListPrefix) then
        return true
    end
    
    -- check domain
    if ipListDomain == nil and ipListPrefixDomain == nil then
        return false
    end
    if utils.match_ip(ip, ipListDomain, ipListPrefixDomain) then
        return true
    end
    return false
end

local function waf_white_ip(ip, domain)
    return waf_ip(ip, domain, 'whiteIp', 'whiteIpPrefix')
end

local function waf_black_ip(ip, domain)
    return waf_ip(ip, domain, 'blackIp', 'blackIpPrefix')
end

local function waf_deny_cc(ip, domain)
    local ccCount, ccCountDomain = config.getConfigList(domain, 'ccCount');
    local ccSeconds, ccSecondsDomain = config.getConfigList(domain, 'ccSeconds');
    if ccCountDomain ~= nil and ccSecondsDomain ~= nil then
        ccCount = ccCountDomain
        ccSeconds = ccSecondsDomain
    end
    if ccCount < 1 or ccSeconds < 1 then
        return false
    end
    local uri = ngx.var.uri
    local token = ip .. uri
    local limit = ngx.shared.limit
    local req, _ = limit:get(token)
    if req then
        if req >= ccCount then
            return true
        else
            limit:incr(token, 1)
        end
    else
        limit:set(token, 1, ccSeconds)
    end
    return false
end

local function waf_match(str, list)
    if list ~= nil then
        for _, rule in pairs(list) do
            if rule ~= nil and rule ~= "" and ngxmatch(str, rule, "isjo") then
                return true, rule
            end
        end
    end
    return false, nil
end

local function waf_match_domain(str, list, listDomain)
    local ret, rule = waf_match(str, list)
    if ret then
        return true, rule
    end
    ret, rule = waf_match(str, listDomain)
    if ret then
        return true, rule
    end
    return false, nil
end

local function waf_check_ua(ip, domain)
    local ua = ngx.var.http_user_agent
    if ua ~= nil and #ua > 0 then
        local patternUa, patternUaDomain = config.getConfigList(domain, 'patternUa')
        local ret, rule = waf_match_domain(ua, patternUa, patternUaDomain)
        if ret then
            -- logging
            waf_log(ip, 'UA', rule, ua)
            return true
        end
    end
    return false
end

local function waf_check_url(ip, domain)
    local url = ngx.var.request_uri
    if url ~= nil and #url > 1 then
        local patternUrl, patternUrlDomain = config.getConfigList(domain, 'patternUrl')
        local ret, rule = waf_match_domain(url, patternUrl, patternUrlDomain)
        if ret then
            -- logging
            waf_log(ip, 'URL', rule, url)
            return true
        end
    end
    return false
end

local function waf_check_args(ip, domain)
    local args = ngx.req.get_uri_args()
    if args ~= nil then
        local patternArgs, patternArgsDomain = config.getConfigList(domain, 'patternArgs')
        for _, val in pairs(args) do
            local data = val
            -- for list type
            if type(val) == 'table' then
                if val ~= false then
                    data = table.concat(val, " ")
                end
            end
            if data and type(data) ~= "boolean" then
                local ret, rule = waf_match_domain(data, patternArgs, patternArgsDomain)
                if ret then
                    -- logging
                    waf_log(ip, 'ARGS', rule, data)
                    return true
                end
            end
        end
    end
    return false
end

local function waf_check_cookie(ip, domain)
    local cookie = ngx.var.http_cookie
    if cookie ~= nil and #cookie > 1 then
        local pattern, patternDomain = config.getConfigList(domain, 'patternCookie')
        local ret, rule = waf_match_domain(cookie, pattern, patternDomain)
        if ret then
            -- logging
            waf_log(ip, 'COOKIE', rule, cookie)
            return true
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
                -- logging
                waf_log(ip, 'POST', rule, "file attack with ext " .. ext)
                return true
            end
        end
    end
    return false
end

local function check_body(data, pattern, patternDomain)
    if data ~= nil and #data > 1 then
        local ret, rule = waf_match_domain(data, pattern, patternDomain)
        if ret then
            -- logging
            waf_log(ip, 'POST', rule, data)
            return true
        end
    end
    return false
end

local function waf_check_post(ip, domain)
    local pattern, patternDomain = config.getConfigList(domain, 'patternPost')
    if pattern == nil and patternDomain == nil then
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
            if check_body(data, pattern, patternDomain) then
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
                    if check_body(data, pattern, patternDomain) then
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
            if data and type(data) ~= "boolean" and check_body(data, pattern, patternDomain) then
                return true
            end
        end
    end
end

local function waf_deny(code)
    local accept = get_headers()['accept']
    if accept ~= nil and (
        string.find(accept, 'application/json') ~= nil 
        or string.find(accept, 'text/json') ~= nil
        ) then
        -- for json response
        ngx.header['Content-Type'] = 'application/json'
        local msg = deny_msg[code]
        if msg == nil then
            msg = 'forbidden'
        end
        ngx.say('{"errno":80001,"errdesc":"' .. deny_msg[code] .. '","timestamp":' .. os.time() .. '}')
        ngx.exit(ngx.OK)
    else
        ngx.exit(code)
    end
end

local function _filter()
    local client_ip = get_client_ip()
    local domain = rules.aliasMapping(ngx.var.http_host)
    if config.enableWhiteIp() and waf_white_ip(client_ip, domain) then
        -- white ip, pass
    elseif config.enableBlackIp() and waf_black_ip(client_ip, domain) then
        waf_deny(403)
    elseif config.enableCc() and waf_deny_cc(client_ip, domain) then
        waf_deny(503, true)
    elseif ngx.var.http_Acunetix_Aspect ~= nil or ngx.var.http_X_Scan_Memo ~= nil then
        waf_deny(409)
--    elseif waf_white_url() then -- need to be per domain ?
    elseif config.enableUa() and waf_check_ua(client_ip, domain) then
        waf_deny(403, true)
    elseif config.enableUrl() and waf_check_url(client_ip, domain) then
        waf_deny(403, true)
    elseif config.enableArgs() and waf_check_args(client_ip, domain) then
        waf_deny(403, true)
    elseif config.enableCookie() and waf_check_cookie(client_ip, domain) then
        waf_deny(403, true)
    elseif config.enablePost() and waf_check_post(client_ip, domain) then
        waf_deny(403, true)
    else
        return
    end
end

_M.filter = function(domain)
    if not config.enable() then
        return
    end
    _filter()
end

return _M