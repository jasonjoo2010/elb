local function waf_filter()
    if waf_white_ip() then -- need to be dynamic
    elseif waf_block_ip() then -- need to be dynamic
    elseif waf_deny_cc() then -- need to be per domain ?
    elseif ngx.var.http_Acunetix_Aspect then
        ngx.exit(409)
    elseif ngx.var.http_X_Scan_Memo then
        ngx.exit(409)
    elseif waf_white_url() then -- need to be per domain ?
    elseif waf_check_ua() then
    elseif waf_check_url() then
    elseif waf_check_args() then
    elseif waf_check_cookie() then
    elseif waf_check_post() then
    else
        return
    end
end

return {
    filter = waf_filter
}