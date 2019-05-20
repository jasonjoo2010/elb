local function waf_filter()
    if waf_white_ip() then
    elseif waf_block_ip() then
    elseif waf_deny_cc() then
    elseif ngx.var.http_Acunetix_Aspect then
        ngx.exit(444)
    elseif ngx.var.http_X_Scan_Memo then
        ngx.exit(444)
    elseif whiteurl() then
    elseif ua() then
    elseif url() then
    elseif args() then
    elseif cookie() then
    elseif post_check() then
    else
        return
    end
end

return {
    filter = waf_filter
}