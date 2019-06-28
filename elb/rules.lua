local lock = require 'resty.lock'
local config = require 'elb.config'
local dyups = require 'ngx.dyups'
local dict_locks = ngx.shared.locks

local data_rules = {}
local data_alias = {}
local data_certs_binding = {}
local data_certs = {}

local _M = {}

_M.loadUpstreams = function(version)
    local upstreams = config.getUpstreams()
    -- we just need it to be operated once
    local mutex = lock:new('locks', {timeout = 0})
    local es, err = mutex:lock('sync_upstreams')
    if not es then
        return
    elseif err then
        ngx.log(ngx.ERR, err)
        return
    end
    local cur_version = dict_locks:get(config.VERSION_UPSTREAME_KEY)
    if cur_version == version then
        mutex:unlock()
        ngx.log(ngx.INFO, 'Already loaded, skip')
        return
    end
    dict_locks:set(config.VERSION_UPSTREAME_KEY, version)
    if upstreams == nil then
        ngx.log(ngx.WARN, "No upstream loaded")
    else
        for up_name, servers in pairs(upstreams) do
            local servers_str = ''
            for addr, settings in pairs(servers) do
                local line = string.format("server %s %s;", addr, settings)
                if #servers_str > 0 then
                    servers_str = servers_str .. '\n' .. line
                else
                    servers_str = line
                end
            end
            local status, err = dyups.update(up_name, servers_str)
            if status ~= ngx.HTTP_OK then
                ngx.log(ngx.ERR, 'Set upstream ', up_name, ' error')
            else
                ngx.log(ngx.INFO, 'Upstream ', up_name, ' loaded: ', servers_str)
            end
        end
    end
    mutex:unlock()
end

_M.loadExceptUpstreams = function()
    ngx.log(ngx.INFO, "start to load configuration from etcd")
    local binds, certs = config.getCerts()
    local alias = config.getAlias()
    local rules = config.getRules()
    
    if rules == nil then
        ngx.log(ngx.WARN, "No rules loaded")
        data_rules = {}
    else
        data_rules = rules
    end
    
    if alias == nil then
        ngx.log(ngx.WARN, "No alias loaded")
        data_alias = {}
    else
        data_alias = alias
    end
    
    if binds == nil then
        ngx.log(ngx.WARN, "No certificate binding loaded")
        data_certs_binding = {}
    else
        data_certs_binding = binds
    end
    
    if certs == nil then
        ngx.log(ngx.WARN, "No certificate loaded")
        data_certs = {}
    else
        data_certs = certs
    end
    
    ngx.log(ngx.INFO, "Configuration are loaded")
end

_M.getCertificate = function(server_name)
    local cert_name = data_certs_binding[server_name]
    if cert_name == nil then
        -- try widecard
        local widecard = nil
        local offset = string.find(server_name, '%.', 1)
        if offset and offset > 0 then
            widecard = '*' .. server_name.sub(server_name, offset)
        end
        if widecard ~= nil then
            cert_name = data_certs_binding[widecard]
        end
    end
    if cert_name == nil then
        return nil, nil
    end
    local data = data_certs[cert_name]
    if data == nil then
        return nil, nil
    end
    return data['key'], data['cert']
end

_M.getRules = function(http_host)
    local rules = data_rules[http_host]
    if rules == nil then
        -- try alias
        local alias = data_alias[http_host]
        if alias ~= nil then
            rules = data_rules[alias]
        end
    end
    return rules
end

-- convert hostname in http request into domain which binds rules
-- nil for not found
_M.aliasMapping = function(host)
    local rules = data_rules[host]
    if data_rules[host] ~= nil then
        return host
    end
    return data_alias[host]
end

return _M
