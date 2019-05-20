local string = require 'string'
local etcd = require 'resty.etcd'
local lock = require 'resty.lock'
local utils = require 'resty.utils'
local config = require 'elb.config'

local etcd_client = etcd:new(config.ETCD)
local rules = ngx.shared.rules

function load_data()
    ngx.log(ngx.INFO, 'try load config')
    local mutex = lock:new('locks', {timeout = 0})
    local es, err = mutex:lock('load_data')
    if not es then
        ngx.log(ngx.NOTICE, 'load data in another worker')
        return
    elseif err then
        ngx.log(ngx.ERR, err)
        return
    end

    local rules_key = string.format(config.RULES_KEY, config.NAME)
    local data = utils.load_data(etcd_client:get(rules_key))
    local keys_valid = {}
    if not data then
        ngx.log(ngx.ERR, 'no domain data')
        mutex:unlock()
        return
    end
    for i = 1, #data do
        local value = data[i]['value']
        local key = data[i]['key']
        ngx.log(ngx.INFO, 'set ' .. key)
        rules:set(key, value)
        keys_valid[key] = 1
    end
    
    -- remove keys not valid any more
    local rule_keys = rules:get_keys(0)
    for _, k in ipairs(rule_keys) do
        if keys_valid[k] == nil then
            ngx.log(ngx.INFO, 'remove ' .. k)
            rules:delete(k)
        end
    end

    local upstreams_key = string.format(config.UPSTREAMS_KEY, config.NAME)
    data = utils.load_data(etcd_client:get(upstreams_key))
    if not data then
        ngx.log(ngx.ERR, 'no upstreams data')
        mutex:unlock()
        return
    end
    for i = 1, #data do
        local servers = data[i]['nodes']
        local backend_name = utils.real_key(data[i]['key'])
        local servers_str = utils.servers_str(servers)
        if not utils.set_upstream(backend_name, servers_str) then
            ngx.log(ngx.ERR, 'load upstream failed ', err)
        end
    end

    mutex:unlock()
    ngx.log(ngx.INFO, 'load config')
end

return {
    load = load_data
}
