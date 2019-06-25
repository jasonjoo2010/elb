local rules_loader = require 'elb.rules'
local waf_worker_init = require 'waf.worker_init'

function load_data()
    rules_loader.load()
end

ngx.timer.at(0, load_data)
