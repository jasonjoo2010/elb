local luabit = require 'bit'

local _M = {}

local function ip2int(ip)
    local o1, o2, o3, o4, p = string.match(ip, "(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)/?(%d?%d?)")
    local iplong = 2^24 * o1 + 2^16 * o2 + 2^8 * o3 + o4
    if p == "" then
        p = 0
    end
    return iplong + 0, p + 0
end

_M.match_ip = function(ip, ipList, prefixList)
    if ip == nil or #ip < 1 then
        return false
    end
    if ipList[ip] then
        return true
    end
    local iplong = ip2int(ip)
    for prefix, mask in pairs(prefixList) do
        if luabit.band(iplong, mask) == prefix then
            return true
        end
    end
    return false
end

-- parse ip list like ["192.168.123.2", "192.168.40.1/24"] into to list: ip_list, prefix_list
_M.parse_ip_list = function(arr)
    local ipList = {}
    local prefixList = {}
    if arr then
        local prefixCount = 1
        for _, ip in pairs(arr) do
            local iplong, p = ip2int(ip)
            if p > 0 then
                local right = 32 - p
                local prefix = luabit.lshift(luabit.rshift(iplong, right), right)
                local mask = luabit.lshift(luabit.rshift(0xffffffff, right), right)
                prefixList[prefix] = mask
                prefixCount = prefixCount + 1
            else
                ipList[ip] = 1
            end
        end
    end
    return ipList, prefixList
end

_M.get_boolean = function(val, def)
    if val == nil then
        return def
    end
    val = string.lower(val)
    if val == 'true' then
        return true
    elseif val == 'false' then
        return false
    end
    return def
end

_M.get_string = function(val, def)
    if val == nil or val == '' then
        return def
    end
    return val
end

_M.copy = function(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        copy = {}
        for orig_key, orig_value in pairs(orig) do
            copy[orig_key] = orig_value
        end
    else -- number, string, boolean, etc
        copy = orig
    end
    return copy
end

_M.list_append = function(dst, src)
    if dst == nil then
        dst = {}
    end
    if src ~= nil then
        for _, ua in pairs(src) do
            table.insert(dst, ua)
        end
    end
    if #dst > 0 then
        return dst
    else
        return nil
    end
end

_M.merge = function(dst, src)
    if src ~= nil then
        for k, v in pairs(src) do
            dst[k] = v
        end
    end
    return dst
end

_M.waf_get_client_ip = function()
    local IP = ngx.var.remote_addr
    if IP == nil then
        IP = "unknown"
    end
    return IP
end

return _M