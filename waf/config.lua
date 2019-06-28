-- load defaults from local files
local utils = require 'waf.utils'
local elb_config = require 'elb.config'
local resty_utils = require 'resty.utils'
local cjson = require 'cjson'

local _M = {}
local envConfig = {}
local etcdConfig = nil
local domainConfig = {}

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

local function load_global_switches(config, src)
    config.enable = utils.get_boolean(src['enable'], envConfig.enable)
    
    config.enableCc = utils.get_boolean(src['cc_enable'], envConfig.enableCc)
    config.enableUa = utils.get_boolean(src['ua_enable'], envConfig.enableUa)
    config.enableCookie = utils.get_boolean(src['cookie_enable'], envConfig.enableCookie)
    config.enableArgs = utils.get_boolean(src['args_enable'], envConfig.enableArgs)
    config.enableUrl = utils.get_boolean(src['url_enable'], envConfig.enableUrl)
    config.enablePost = utils.get_boolean(src['post_enable'], envConfig.enablePost)
    config.enableWhiteIp = utils.get_boolean(src['ip_white_enable'], false)
    config.enableBlackIp = utils.get_boolean(src['ip_black_enable'], false)
end

local function load_general(config, src)
    local arr = resty_utils.load_array_from_string(src['ip_white'])
    if arr ~= nil and #arr > 0 then
        config.whiteIp, config.whiteIpPrefix = utils.parse_ip_list(arr)
        if next(config.whiteIp) == nil then
            config.whiteIp = nil
        end
        if next(config.whiteIpPrefix) == nil then
            config.whiteIpPrefix = nil
        end
    end
    arr = resty_utils.load_array_from_string(src['ip_black'])
    if arr ~= nil and #arr > 0 then
        config.blackIp, config.blackIpPrefix = utils.parse_ip_list(arr)
        if next(config.blackIp) == nil then
            config.blackIp = nil
        end
        if next(config.blackIpPrefix) == nil then
            config.blackIpPrefix = nil
        end
    end
    arr = resty_utils.load_array_from_string(src['ua'])
    if arr ~= nil and #arr > 0 then
        config.patternUa = arr
    end
    arr = resty_utils.load_array_from_string(src['url'])
    if arr ~= nil and #arr > 0 then
        config.patternUrl = arr
    end
    arr = resty_utils.load_array_from_string(src['args'])
    if arr ~= nil and #arr > 0 then
        config.patternArgs = arr
    end
    arr = resty_utils.load_array_from_string(src['cookie'])
    if arr ~= nil and #arr > 0 then
        config.patternCookie = arr
    end
    arr = resty_utils.load_array_from_string(src['post'])
    if arr ~= nil and #arr > 0 then
        config.patternPost = arr
    end
    -- cc_rate
    if src['cc_rate'] ~= nil and #src['cc_rate'] > 0 then
        config.ccCount = tonumber(string.match(src['cc_rate'], '(.*)/'))
        config.ccSeconds = tonumber(string.match(src['cc_rate'], '/(.*)'))
        if config.ccCount < 1 or config.ccSeconds < 1 then
            config.ccCount = nil
            config.ccSeconds = nil
        end
    end
end

_M.reload = function()
    ngx.log(ngx.INFO, 'try load waf config from etcd')
    local c = elb_config.getWafRules()
    if c == nil or next(c) == nil then
        return
    end
    -- ngx.log(ngx.INFO, 'load: ', cjson.encode(c))
    local new_config = {}
    local new_domain_config = {}
    load_global_switches(new_config, c)
    load_general(new_config, c)
    
    -- append envConfig
    new_config.patternUa = utils.list_append(new_config.patternUa, envConfig.patternUa);
    new_config.patternUrl = utils.list_append(new_config.patternUrl, envConfig.patternUrl);
    new_config.patternArgs = utils.list_append(new_config.patternArgs, envConfig.patternArgs);
    new_config.patternCookie = utils.list_append(new_config.patternCookie, envConfig.patternCookie);
    new_config.patternPost = utils.list_append(new_config.patternPost, envConfig.patternPost);
    
    -- global cc_rate
    if new_config.ccCount == nil or new_config.ccSeconds == nil then
        new_config.ccCount = envConfig.ccCount
        new_config.ccSeconds = envConfig.ccSeconds
    end
    
    -- per domain
    if c['domains'] ~= nil then
        for domain, dc in pairs(c['domains']) do
            local item = {}
            load_general(item, dc)
            if next(item) ~= nil then
                new_domain_config[domain] = item
            end
        end
    end
    
    etcdConfig = new_config
    domainConfig = new_domain_config
    
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

local config_name_list_type = {}
config_name_list_type['whiteIp'] = 1
config_name_list_type['whiteIpPrefix'] = 1
config_name_list_type['blackIp'] = 1
config_name_list_type['blackIpPrefix'] = 1
config_name_list_type['ccCount'] = 1
config_name_list_type['ccSeconds'] = 1
config_name_list_type['patternUa'] = 1
config_name_list_type['patternUrl'] = 1
config_name_list_type['patternArgs'] = 1
config_name_list_type['patternCookie'] = 1
config_name_list_type['patternPost'] = 1

-- values
_M.getConfigList = function(domain, config_name)
    if config_name_list_type[config_name] == nil then
        return nil, nil
    end
    local c = domainConfig[domain]
    if c == nil then
        return etcdConfig[config_name], nil
    else
        return etcdConfig[config_name], c[config_name]
    end
end

_M.getBlackFileExts = function()
    return envConfig.blackFileExts
end

return _M