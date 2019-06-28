local rules = require 'elb.rules'
local ssl = require "ngx.ssl"

ssl.clear_certs()

local server_name = ssl.server_name()

if server_name ~= nil then
    local key_pem, cert_pem = rules.getCertificate(server_name)
    if key_pem == nil then
        return ngx.exit(ngx.ERROR)
    end
    local der_priv_key, err = ssl.priv_key_pem_to_der(key_pem)
    local der_cert_chain, err = ssl.cert_pem_to_der(cert_pem)
    ssl.set_der_cert(der_cert_chain)
    ssl.set_der_priv_key(der_priv_key)
else
    return ngx.exit(ngx.ERROR)
end
