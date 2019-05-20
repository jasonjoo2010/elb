local utils = require 'resty.utils'
local rules_loader = require 'elb.rules'

if ngx.var.request_method == 'GET' then
    rules_loader.load()
    utils.say_msg_and_exit(ngx.HTTP_OK, 'OK')
else
    utils.say_msg_and_exit(ngx.HTTP_FORBIDDEN, '')
end
