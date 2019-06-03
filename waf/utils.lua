local _M = {}

local function ip2int(ip)
    local o1, o2, o3, o4, p = ip:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)/?(%d?%d?)")
    local iplong = 2^24 * o1 + 2^16 * o2 + 2^8 * o3 + o4
    if p == "" then
        p = 0
    end
    return iplong + 0, p + 0
end

_M.match_ip = function(ip, ipList, prefixList)
    if ipList[ip] then
        return true
    end
    local iplong = ip2int(ip)
    for prefix, mask in pairs(prefixList) do
        ngx.log(ngx.ERR, "judge: " .. ip .. " => " .. luabit.band(iplong, mask) .. " : " .. prefix)
        if luabit.band(iplong, mask) == prefix then
            ngx.log(ngx.ERR, "match: " .. ip)
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

return _M