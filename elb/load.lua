local rules_loader = require 'elb.rules'

function load_data()
    rules_loader.load()
end

ngx.timer.at(0, load_data)
