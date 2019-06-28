local string = require 'string'
local cjson = require 'cjson'
local request = require 'waf.request'

request.filter()

local elb_config = require 'elb.config'
local processor = require 'elb.processor'
local rules = require 'elb.rules'

-- get rules
local rules = rules.getRules(ngx.var.http_host)
if rules == nil then
    ngx.exit(ngx.HTTP_NOT_FOUND)
end

--[[
rule: {
    "init": "r1",
    "rules": {
        "r5": {
            "args": {
                "path": "/tmp/statics",
                "expires": "30d",
                "servername": "127.0.0.1:7070"
            },
            "type": "backend"
        },
        "r1": {
            "args": {
                "fail": "r3",
                "pattern": "httpie(\\\\S+)$",
                "succ": "r4"
            },
            "type": "ua"
        },
        "r2": {
            "args": {
                "servername": "127.0.0.1:8088"
            },
            "type": "backend"
        },
        "r3": {
            "args": {
                "servername": "127.0.0.1:8089"
            },
            "type": "backend"
        },
        "r4": {
            "args": {
                "regex": true,
                "pattern": "^\\\\/blog\\\\/(\\\\S+)$",
                "succ": "r2",
                "fail": "r3",
                "rewrite": true
            },
            "type": "path"
        }
    }
}
-- ]]

local typ, args, err_code = processor.process(rules)
if err_code ~= nil then
    ngx.exit(err_code)
end

-- ATTENSION: variables must be *READONLY* or we must copy them first
if typ == 'response' then
    if args['code'] ~= nil then
        ngx.status = args['code']
        local body = args['body']
        -- headers
        for k, v in pairs(args) do
            if k ~= 'code' and k ~= 'body' then
                ngx.header[k] = v
            end
        end
        if body ~= nil then
            ngx.say(body)
        end
        ngx.exit(ngx.OK)
    else
        ngx.exit(ngx.HTTP_NOT_FOUND)
    end
else
    if args["servername"] ~= nil then
        ngx.var.backend = args["servername"]
        for k, v in pairs(args) do
            if k ~= 'servername' then
                ngx.req.set_header(k, v)
            end
        end
    else
        ngx.exit(ngx.HTTP_NOT_FOUND)
    end
end
