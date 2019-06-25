local _M = {}
local string = require 'string'

function _M.process(params)
    local ua, pattern = ngx.var.http_user_agent, params['pattern']
    if not ua then
        return false, nil
    end
    local ua = string.lower(ua)
    local from, to, err = ngx.re.find(ua, pattern)
    if not from then
        return false, err
    end
    return true, nil
end

return _M