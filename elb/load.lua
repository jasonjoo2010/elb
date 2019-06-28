local elb_config = require 'elb.config'
local rules_loader = require 'elb.rules'
local waf_config = require 'waf.config'

local locks = ngx.shared.locks
local cur_version = -1

-- polling the update version number to decide whether should reload
local function reload_thread()
    -- do check whether need reload
    local remote_version = tonumber(locks:get(elb_config.VERSION_KEY))
    if remote_version == nil then
        remote_version = 0
    end
    if remote_version > cur_version then
        cur_version = remote_version
        rules_loader.loadExceptUpstreams()
        rules_loader.loadUpstreams(cur_version)
        waf_config.reload()
    end
    ngx.timer.at(5, reload_thread)
end

ngx.timer.at(0, reload_thread)