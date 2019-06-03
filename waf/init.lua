local waf_config = require 'waf.config'
local luabit = require "bit"

local ngxmatch = ngx.re.find
local unescape = ngx.unescape_uri
local get_headers = ngx.req.get_headers
local ModuleEnable = function(options) return options == "true" and true or false end
local logpath = configLogDir
local rulepath = configRulePath
local enableUrlCheck = ModuleEnable(configUrlDeny)
local enablePostCheck = ModuleEnable(configPost)
local enableCookieCheck = ModuleEnable(configCookieMatch)
local enableURLWhite = ModuleEnable(configURLWhite)
local PathInfoFix = ModuleEnable(PathInfoFix)
local attacklog = ModuleEnable(configAttackLog)
local enableCcDetect = ModuleEnable(configCcDetect)
local Redirect = ModuleEnable(configRedirect)
local ccCount = tonumber(string.match(configCcRate, '(.*)/'))
local ccSeconds = tonumber(string.match(configCcRate, '/(.*)'))
local blackFileExts = {}
for _, l in ipairs(configBlackFileExt) do blackFileExts[l] = true end

local arrIpWhiteList = {}
local arrIpPrefixWhiteList = {}
local arrIpBlackList = {}
local arrIpPrefixBlackList = {}
arrIpWhiteList, arrIpPrefixWhiteList = parseIpList(configIpWhiteList)
arrIpBlackList, arrIpPrefixBlackList = parseIpList(configIpBlockList)

local function waf_get_client_ip()
    local IP = ngx.var.remote_addr
    if IP == nil then
        IP = "unknown"
    end
    return IP
end
local function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end
local function waf_log(method, url, data, ruletag)
    if attacklog then
        local realIp = waf_get_client_ip()
        local ua = ngx.var.http_user_agent
        local servername = ngx.var.server_name
        local time = ngx.localtime()
        local line
        if ua  then
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
        end
        local filename = logpath .. '/' .. servername .. "_" .. ngx.today() .. "_sec.log"
        write(filename, line)
    end
end
------------------------------------load rules-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath .. '/' .. var, "r")
    if file == nil then
        ngx.log(ngx.ERR, "load " .. var .. " rules failed")
        return
    end
    local t = {}
    for line in file:lines() do
        table.insert(t, line)
    end
    file:close()
    ngx.log(ngx.INFO, var .. " rules " .. #t .. " loaded")
    return (t)
end

urlrules = read_rule('url')
argsrules = read_rule('args')
uarules = read_rule('user-agent')
wturlrules = read_rule('whiteurl')
postrules = read_rule('post')
ckrules = read_rule('cookie')


local function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(configCcHtml)
        ngx.exit(ngx.status)
    end
end

function waf_white_url()
    if enableURLWhite then
        if wturlrules ~= nil then
            for _, rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.uri, rule, "isjo") then
                    return true
                end
            end
        end
    end
    return false
end

local function fileExtCheck(ext)
    local items = blackFileExts
    ext = string.lower(ext)
    ngx.log(ngx.ERR, "ext: " .. ext)
    if ext then
        for rule in pairs(items) do
            -- TODO test here
            if ngxmatch(ext, rule, "isjo") then
                waf_log('POST', ngx.var.request_uri, "-", "file attack with ext " .. ext)
                say_html()
            end
        end
    end
    return false
end

function waf_check_args()
    for _, rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            local data = val
            if type(val) == 'table' then
                if val ~= false then
                    data = table.concat(val, " ")
                end
            end
            if data and type(data) ~= "boolean" and rule ~= "" and ngxmatch(unescape(data), rule, "isjo") then
                waf_log('GET', ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function waf_check_url()
    if enableUrlCheck then
        for _, rule in pairs(urlrules) do
            if rule ~= "" and ngxmatch(ngx.var.request_uri, rule, "isjo") then
                waf_log('GET', ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function waf_check_ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _, rule in pairs(uarules) do
            if rule ~= "" and ngxmatch(ua, rule, "isjo") then
                waf_log('UA', ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function waf_check_cookie()
    if not enableCookieCheck then return false end
    local ck = ngx.var.http_cookie
    if ck then
        for _, rule in pairs(ckrules) do
            if rule ~= "" and ngxmatch(ck, rule, "isjo") then
                waf_log('Cookie', ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function waf_deny_cc()
    if enableCcDetect then
        local uri = ngx.var.uri
        local token = waf_get_client_ip() .. uri
        local limit = ngx.shared.limit
        local req, _ = limit:get(token)
        if req then
            if req >= ccCount then
                ngx.exit(503)
                return true
            else
                limit:incr(token, 1)
            end
        else
            limit:set(token, 1, ccSeconds)
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

local function check_body(data)
    for _,rule in pairs(postrules) do
        if rule ~= "" and data ~="" and ngxmatch(unescape(data), rule, "isjo") then
            waf_log('POST', ngx.var.request_uri, data, rule)
            say_html()
            return true
        end
    end
    return false
end

function waf_block_ip()
    local client_ip = waf_get_client_ip()
    if (ipMatch(client_ip, arrIpBlackList, arrIpPrefixBlackList)) then
        ngx.exit(403)
        return true
    end
    return false
end

function waf_check_post()
    if not enablePostCheck then return false end
    local method = ngx.req.get_method()
    if method ~= "POST" then return false end
    local ret = has_boundary()
    if ret then
        local len = string.len
        local sock, err = ngx.req.socket()
        if not sock then
            return
        end
        ngx.req.init_body(128 * 1024)
        sock:settimeout(0)
        local content_length = nil
        content_length = tonumber(ngx.req.get_headers()['content-length'])
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
                fileExtCheck(m[3])
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
        ngx.req.read_body()
        local args = ngx.req.get_post_args()
        if not args then
            return
        end
        for key, val in pairs(args) do
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
