local utils = require 'resty.utils'
local waf_config = require 'waf.config'
local elb_config = require 'elb.config'

local locks = ngx.shared.locks

if ngx.var.request_method == 'GET' then
    local ver = tonumber(locks:get(elb_config.VERSION_KEY))
    if ver == nil then
        ver = 0
    end
    locks:set(elb_config.VERSION_KEY, ver + 1)
    utils.say_msg_and_exit(ngx.HTTP_OK, 'OK')
else
    utils.say_msg_and_exit(ngx.HTTP_FORBIDDEN, '')
end
