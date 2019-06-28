local _M = {}
local cjson = require 'cjson'
local dyups = require 'ngx.dyups'

-- deprecated
function _M.set_upstream(backend_name, servers_str)
    local status, err = dyups.update(backend_name, servers_str)
    if status ~= ngx.HTTP_OK then
        return false
    end
    return true
end

-- deprecated
function _M.servers_str(servers)
    local server_pattern = "server %s %s;"
    local data = {}
    for i = 1, #servers do
        local backend = _M.real_key(servers[i]['key'])
        local addition = servers[i]['value']
        table.insert(data, string.format(server_pattern, backend, addition))
    end
    return table.concat(data, '\n')
end

-- deprecated
function _M.load_data(data)
    if not data or not data['node'] or not data['node']['nodes'] then
        return nil
    end
    return data['node']['nodes']
end

function _M.split(str, separator, max, regex)
    assert(separator ~= '')
    assert(max == nil or max >= 1)

    local record = {}

    if str:len() > 0 then
        local plain = not regex
        max = max or -1

        local field=1
        local start=1
        local first, last = str:find(separator, start, plain)
        while first and max ~= 0 do
            record[field] = str:sub(start, first - 1)
            field = field + 1
            start = last + 1
            first, last = str:find(separator, start, plain)
            max = max - 1
        end
        record[field] = str:sub(start)
    end

    return record
end

function _M.real_key(key)
    if key == nil or #key == 0 then
        return nil
    end
    local t = string.reverse(key)
    local pos = string.find(t, '/')
    if pos == nil or pos < 1 then
        return nil
    end
    return string.reverse(string.sub(t, 0, pos - 1))
end

local function load_recursive(nodes)
    local t = {}
    for i = 1, #nodes do
        local name = _M.real_key(nodes[i]['key'])
        if (nodes[i]['dir']) then
            if nodes[i]['nodes'] ~= nil then
                t[name] = load_recursive(nodes[i]['nodes'])
            end
        else
            t[name] = nodes[i]['value']
        end
    end
    return t
end

function _M.load_table_from_etcd(data)
    if data == nil or data['node'] == nil or data['node']['nodes'] == nil then
        return {}
    end
    return load_recursive(data['node']['nodes'])
end

function _M.load_array_from_string(data)
    if data == nil or data == '' then
        return nil
    else
        return cjson.decode(data)
    end
end

function _M.read_data()
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if not data then
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    end
    return data
end

function _M.from_hex(str)
    return (str:gsub("(..)", function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function _M.say_msg_and_exit(status, message)
    if status == ngx.HTTP_OK then
        if type(message) == 'table' then
            ngx.say(cjson.encode(message))
        else
            ngx.say(cjson.encode({msg=message}))
        end
    end
    ngx.exit(status)
end

return _M
