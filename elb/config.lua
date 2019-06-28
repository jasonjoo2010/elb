local utils = require 'resty.utils'
local etcd = require 'resty.etcd'
local cjson = require 'cjson'
local aes = require "resty.aes"

local _M = {}

local function get_etcd()
    local etcd_url = os.getenv("ETCD_URL") or os.getenv("ETCD")
    if etcd_url == nil then
        local etcd_host = os.getenv("ETCD_HOST") or "127.0.0.1"
        local etcd_port = os.getenv("ETCD_PORT") or "2379"
        return "http://"..etcd_host..":"..etcd_port
    end
    return etcd_url
end

_M.VERSION_KEY = 'version_key'
_M.VERSION_UPSTREAME_KEY = 'upstreams_version'

local client = etcd:new(get_etcd())
local elb_name = os.getenv("ELBNAME") or 'ELB'
local cert_password = os.getenv('CERT_PASSWORD') or ''

_M.STATSD = os.getenv("STATSD")
_M.STATSD_FORMAT = elb_name .. '.%s.%s'

local function decrypt_cert(cert_name, str)
    local pw = cert_password .. 'elbSalt:' .. elb_name .. ':' .. cert_name
    local aes_cryptor = aes:new(pw, nil, aes.cipher(128, "ecb"), aes.hash.sha1, 1)
    local data = utils.from_hex(str)
    return aes_cryptor:decrypt(data)
end

_M.getEtcdClient = function()
    return client
end

_M.getRules = function()
    local data = utils.load_table_from_etcd(client:get(string.format('/%s/rules?recursive=true', elb_name)))
    if data == nil then
        return nil
    end
    local rules = {}
    for domain, val in pairs(data) do
        rules[domain] = cjson.decode(val)
    end
    return rules
end

_M.getAlias = function()
    local data = utils.load_table_from_etcd(client:get(string.format('/%s/alias?recursive=true', elb_name)))
    if data == nil then
        return nil
    end
    return data
end

_M.getCerts = function()
    local data = utils.load_table_from_etcd(client:get(string.format('/%s/certs?recursive=true', elb_name)))
    if data == nil then
        return nil, nil
    end
    local binds = data['binding']
    local certs = data['store']
    -- decrypt certs
    for name, cert in pairs(certs) do
        local key = decrypt_cert(name, cert['key'])
        local crt = decrypt_cert(name, cert['cert'])
        certs[name]['key'] = key
        certs[name]['cert'] = crt
    end
    return binds, certs
end

_M.getUpstreams = function()
    local data = utils.load_table_from_etcd(client:get(string.format('/%s/upstreams?recursive=true', elb_name)))
    if data == nil then
        return nil
    end
    return data
end

_M.getWafRules = function()
    local data = utils.load_table_from_etcd(client:get(string.format('/%s/waf?recursive=true', elb_name)))
    if data == nil then
        return nil
    end
    return data
end

return _M
