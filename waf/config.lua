-- load defaults from local files
local elb_config = require 'elb.config'
local lock = require 'resty.lock'
local _M = {}

-- defaults from file will not change
-- configuration from etcd may change

local function get_env_boolean(name, default)
    local val = os.getenv(name)
    if val == nil then
        return default
    end
    val = string.lower(val)
    if val == 'true' then
        return true
    elseif val == 'false' then
        return false
    end
    return default
end

local function get_env_string(name, default)
    local val = os.getenv(name)
    if val == nil or val == '' then
        return default
    end
    return val
end

local function load_from_file()
    _M.configRedirect = get_env_boolean("WAF_REDIRECT", false) -- TODO need to be customize and for application/json
    _M.configEnableUrlWhite = get_env_boolean("WAF_URL_WHITE", false)
    _M.configEnableCookieCheck = get_env_boolean("WAF_COOKIE", true)
    _M.configEnablePostCheck = get_env_boolean("WAF_POST", false)
    _M.configEnableUrlCheck = get_env_boolean("WAF_URL", true)
    _M.configEnableCcCheck = get_env_boolean("WAF_CC", false)
    _M.configEnableLog = get_env_boolean("WAF_LOG", false)
    _M.configCcRate = get_env_string("WAF_CC_RATE", "100/60")
    _M.configLogDir = "/var/logs/nginx/waf/"
    _M.configRulePath = "/usr/local/nginx/lua/waf/wafconf/"
    _M.configCcHtml = [[
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
    _M.configCcJson = [[{"errno":1,"errdesc":"请求失败，请稍后重试"}]]
end

local function load_from_etcd()
    ngx.log(ngx.INFO, 'try load waf config from etcd')
    local mutex = lock:new('locks', {timeout = 0})
    local elapsed, err = mutex:lock('load_waf_config')
    if not elapsed then
        ngx.log(ngx.NOTICE, 'load waf config in another worker')
        return
    elseif err then
        ngx.log(ngx.ERR, err)
        return
    end
    mutex:unlock()
    ngx.log(ngx.INFO, 'load config')
end

local configBlackFileExt = {"php", "jsp", "java"} -- TODO
local configIpWhiteList = {"127.0.0.1", "172.17.0.2"} -- TODO
local configIpBlockList = {"1.0.0.1", "172.17.0.2"} -- TODO

-- reload from etcd overrides
_M.reload = function ()
    load_from_etcd()
end

load_from_file()
load_from_etcd()

return _M