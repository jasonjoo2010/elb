-- load defaults from local files
local utils = require 'waf.utils'
local elb_config = require 'elb.config'
local resty_utils = require 'resty.utils'
local cjson = require 'cjson'

local _M = {}
local envConfig = {}
local etcdConfig = nil

-- defaults from file(env) will not change
-- configuration from etcd may change

local function read_from_file(var)
    file = io.open("/usr/local/nginx/lua/waf/wafconf/" .. var, "r")
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
    if #t > 0 then
        return t
    else
        return nil
    end
end

local function load_from_env()
    local blackFileExt = {"php", "jsp", "java"}
    envConfig.blackFileExts = {}
    for _, l in ipairs(blackFileExt) do envConfig.blackFileExts[l] = true end
    
    envConfig.enable = utils.get_boolean(os.getenv("WAF"), false)
    envConfig.enableCookie = utils.get_boolean(os.getenv("WAF_COOKIE"), false)
    envConfig.enableUa = utils.get_boolean(os.getenv("WAF_UA"), false)
    envConfig.enableUrl = utils.get_boolean(os.getenv("WAF_URL"), false)
    envConfig.enableArgs = utils.get_boolean(os.getenv("WAF_ARGS"), false)
    envConfig.enablePost = utils.get_boolean(os.getenv("WAF_POST"), false)
    envConfig.enableCc = utils.get_boolean(os.getenv("WAF_CC"), false)
    
    envConfig.enableLog = utils.get_boolean(os.getenv("WAF_LOG"), false)
    envConfig.enableRedirect = utils.get_boolean(os.getenv("WAF_REDIRECT"), false) -- TODO need to be customize and for application/json
    
    local rate = utils.get_string(os.getenv("WAF_CC_RATE"), "100/60")
    envConfig.ccCount = tonumber(string.match(rate, '(.*)/'))
    envConfig.ccSeconds = tonumber(string.match(rate, '/(.*)'))
    
    envConfig.configLogDir = "/var/logs/nginx/waf/"
    envConfig.configCcHtml = [[
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>请求出错</title>
<style>
p {
    line-height:20px;
}
ul{ list-style-type:none;}
li{ list-style-type:none;}
</style>
</head>
<body style=" padding:0; margin:0; font:14px/1.5 Microsoft Yahei, 宋体,sans-serif; color:#555;">
 <div style="margin: 0 auto; width:1000px; padding-top:70px; overflow:hidden;">
  <div style="width:600px; float:left;">
    <div style="border:1px dashed #cdcece; border-top:none; font-size:14px; background:#fff; color:#555; line-height:24px; height:220px; padding:20px 20px 0 20px; overflow-y:auto;background:#f3f7f9;">
      <p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600; color:#fc4f03;">请求出错，请稍后重试</span></p>
    </div>
  </div>
</div>
</body>
</html>
]]
    envConfig.configCcJson = [[{"errno":1,"errdesc":"请求失败，请稍后重试"}]]
    
    -- load initial patterns from file
    envConfig.patternUrl = read_from_file('url')
    envConfig.patternArgs = read_from_file('args')
    envConfig.patternUa = read_from_file('user-agent')
    envConfig.patternPost = read_from_file('post')
    envConfig.patternCookie = read_from_file('cookie')
    
    -- initial etcd config
    etcdConfig = utils.copy(envConfig)
    etcdConfig.enableWhiteIp = false
    etcdConfig.enableBlackIp = false
    etcdConfig.whiteIp = nil
    etcdConfig.whiteIpPrefix = nil
    etcdConfig.blackIp = nil
    etcdConfig.blackIpPrefix = nil
end

_M.reload = function()
    ngx.log(ngx.INFO, 'try load waf config from etcd')
    local c = elb_config.getWafRules()
    if c == nil or next(c) == nil then
        return
    end
    -- ngx.log(ngx.INFO, 'load: ', cjson.encode(c))
    etcdConfig.enable = utils.get_boolean(c['enable'], envConfig.enable)
    
    etcdConfig.enableCc = utils.get_boolean(c['cc_enable'], envConfig.enableCc)
    etcdConfig.enableUa = utils.get_boolean(c['ua_enable'], envConfig.enableUa)
    etcdConfig.enableCookie = utils.get_boolean(c['cookie_enable'], envConfig.enableCookie)
    etcdConfig.enableArgs = utils.get_boolean(c['args_enable'], envConfig.enableArgs)
    etcdConfig.enableUrl = utils.get_boolean(c['url_enable'], envConfig.enableUrl)
    etcdConfig.enablePost = utils.get_boolean(c['post_enable'], envConfig.enablePost)
    
    local arr = resty_utils.load_array_from_string(c['ip_white'])
    if arr == nil or #arr == 0 then
        etcdConfig.whiteIp = nil
        etcdConfig.whiteIpPrefix = nil
        etcdConfig.enableWhiteIp = false
    else
        etcdConfig.whiteIp = {}
        etcdConfig.whiteIpPrefix = {}
        etcdConfig.whiteIp, etcdConfig.whiteIpPrefix = utils.parse_ip_list(arr)
        etcdConfig.enableWhiteIp = next(etcdConfig.whiteIp) ~= nil or next(etcdConfig.whiteIpPrefix) ~= nil
    end
    
    arr = resty_utils.load_array_from_string(c['ip_black'])
    if arr == nil or #arr == 0 then
        etcdConfig.blackIp = nil
        etcdConfig.blackIpPrefix = nil
        etcdConfig.enableBlackIp = false
    else
        etcdConfig.blackIp = {}
        etcdConfig.blackIpPrefix = {}
        etcdConfig.blackIp, etcdConfig.blackIpPrefix = utils.parse_ip_list(arr)
        etcdConfig.enableBlackIp = next(etcdConfig.blackIp) ~= nil or next(etcdConfig.blackIpPrefix) ~= nil
    end
    
    if c['cc_rate'] == nil or #c['cc_rate'] < 1 then
        etcdConfig.ccCount = envConfig.ccCount
        etcdConfig.ccSeconds = envConfig.ccSeconds
    else
        etcdConfig.ccCount = tonumber(string.match(c['cc_rate'], '(.*)/'))
        etcdConfig.ccSeconds = tonumber(string.match(c['cc_rate'], '/(.*)'))
        if etcdConfig.ccCount < 1 or etcdConfig.ccSeconds < 1 then
            etcdConfig.ccCount = envConfig.ccCount
            etcdConfig.ccSeconds = envConfig.ccSeconds
        end
    end
    
    etcdConfig.patternUa = utils.list_append(resty_utils.load_array_from_string(c['ua']), envConfig.patternUa)
    etcdConfig.patternUrl = utils.list_append(resty_utils.load_array_from_string(c['url']), envConfig.patternUrl)
    etcdConfig.patternArgs = utils.list_append(resty_utils.load_array_from_string(c['args']), envConfig.patternArgs)
    etcdConfig.patternCookie = utils.list_append(resty_utils.load_array_from_string(c['cookie']), envConfig.patternCookie)
    etcdConfig.patternPost = utils.list_append(resty_utils.load_array_from_string(c['post']), envConfig.patternPost)
    
    ngx.log(ngx.INFO, 'successfully loaded config from etcd')
end

load_from_env()
ngx.log(ngx.INFO, "load base configuration of WAF")

-- switches
_M.enable = function()
    return etcdConfig.enable
end

_M.enableWhiteIp = function()
    return etcdConfig.enableWhiteIp
end

_M.enableBlackIp = function()
    return etcdConfig.enableBlackIp
end

_M.enableCc = function()
    return etcdConfig.enableCc
end

_M.enableUa = function()
    return etcdConfig.enableUa
end

_M.enableCookie = function()
    return etcdConfig.enableCookie
end

_M.enableArgs = function()
    return etcdConfig.enableArgs
end

_M.enableUrl = function()
    return etcdConfig.enableUrl
end

_M.enablePost = function()
    return etcdConfig.enablePost
end

-- values
_M.getWhiteIp = function()
    return etcdConfig.whiteIp
end

_M.getWhiteIpPrefix = function()
    return etcdConfig.whiteIpPrefix
end

_M.getBlackIp = function()
    return etcdConfig.blackIp
end

_M.getBlackIpPrefix = function()
    return etcdConfig.blackIpPrefix
end

_M.getCCCount = function()
    return etcdConfig.ccCount
end

_M.getCCSeconds = function()
    return etcdConfig.ccSeconds
end

_M.getPatternUa = function()
    return etcdConfig.patternUa
end

_M.getPatternUrl = function()
    return etcdConfig.patternUrl
end

_M.getPatternArgs = function()
    return etcdConfig.patternArgs
end

_M.getPatternCookie = function()
    return etcdConfig.patternCookie
end

_M.getPatternPost = function()
    return etcdConfig.patternPost
end

_M.getBlackFileExts = function()
    return envConfig.blackFileExts
end

return _M