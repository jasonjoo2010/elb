local config = require 'elb.config'
local ssl = require "ngx.ssl"
local utils = require "resty.utils"
local rules = ngx.shared.rules
ssl.clear_certs()
local server_name = ssl.server_name()
if server_name ~= nil then
    local server_name_path = string.format(config.CERTS_BINDING_KEY, config.NAME, server_name)
    local domain = rules:get(server_name_path)
    if domain == nil then
        -- try widecard
        local widecard = nil
        local offset = string.find(server_name, '%.', 1)
        if offset and offset > 0 then
            widecard = '*' .. server_name.sub(server_name, offset)
        end
        if widecard ~= nil then
            server_name_path = string.format(config.CERTS_BINDING_KEY, config.NAME, widecard)
            domain = rules:get(server_name_path)
        end
    end
    if domain == nil then
        return ngx.exit(ngx.ERROR)
    end
    local cert_path = string.format(config.CERT_KEY, config.NAME, domain)
    local cert_pem = rules:get(cert_path .. '/cert')
    local key_pem = rules:get(cert_path .. '/key')
    ngx.log(ngx.INFO, key_pem)
    local der_priv_key, err = ssl.priv_key_pem_to_der(key_pem)
    ngx.log(ngx.INFO, err)
    local der_cert_chain, err = ssl.cert_pem_to_der(cert_pem)
    ssl.set_der_cert(der_cert_chain)
    ssl.set_der_priv_key(der_priv_key)
end
