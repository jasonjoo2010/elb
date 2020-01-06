-- now use ngx.log, refer to request.lua
local waf_config = require 'waf.config'

local logging_fd = io.open(waf_config.wafLogFile(), "ab")
ngx.log(ngx.NOTICE, "open waf logging file")

local function init()
    if logging_fd ~= nil then
        logging_fd:close()
        logging_fd = nil
        ngx.log(ngx.NOTICE, "close waf logging file")
    end
    logging_fd = io.open(waf_config.wafLogFile(), "ab")
    ngx.log(ngx.NOTICE, "open waf logging file")
end

local function logging_flush()
    if logging_fd ~= nil then 
        logging_fd:flush() 
    end
end

-- logging
local function logging_thread()
    local misc = ngx.shared.misc
    local lasttime = 0
    local counter = 0
    while true do
        local line, err = misc:lpop("waf_logging")
        if line == nil then
            if counter > 0 then
                counter = 0
                logging_flush()
            end
            ngx.sleep(1)
        else
            local pos, _ = string.find(line, "\t")
            if pos ~= nil then
                local ts = tonumber(line.sub(0, pos - 1))
                if lasttime ~= ts then
                    lasttime = ts
                    counter = 0
                    logging_flush()
                end
                counter = counter + 1
                if counter < 80 and logging_fd ~= nil then
                    -- write file with rate limiting 80 lines/s
                    logging_fd:write(line)
                    logging_fd:write("\n")
                    if counter % 10 == 9 then 
                        logging_flush()
                    end
                end
            end
        end
    end
end

ngx.timer.at(0, logging_thread)