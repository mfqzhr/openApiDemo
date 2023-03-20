--
-- Desc: 擎天接入神盾API服务
-- User: mufanqiang
-- Date: 2023-02-09 21:12:49
--
local exceptionUtil = require "common.exceptionUtil"
local httpUtil = require "common.httpUtil"
local util = require "common.util"
local redirectUtil = require "common.redirectUtil"
local cjson = require "cjson"
local ump = require "common.ump"
local userVerifyService = require "service.UserVerifyService"
local config_new = ngx.shared.config_new
local config = ngx.shared.config
local getUmpKey = ump.getUmpKey
local umpLog2 = ump.log2
local functionPcall = exceptionUtil.functionTryCatch

local _M = {}

local function getIp(ip)
    if ip == nil then
        return ""
    end
    local ip_tbl = util.split(ip,",")
    if ip_tbl and #ip_tbl>1 then
        return ip_tbl[1]
    else
        return ip
    end
end

local function buildRequestUrl(args, functionId)

    local ua = util.urlDecode(args.agent)
    if util.isBlank(args.agent) then
        ua = util.isBlank(util.real_user_agent()) and "-1" or util.real_user_agent()
    end
    local visitkey = util.checkParamsOrDefault(ngx.var.cookie_visitkey, "-1")
    local request_url = util.checkParamsOrDefault(config_new:get(functionId .. "_SD.request_url"), "http://shield.jd.local/assessRisk")
    local headers = {
        ["Content-Type"] = "application/json"
    }
    local uuid = util.checkParams(args.uuid)
    if args.client == "apple" or args.client == "iPad" then
        uuid = util.checkParams(args.openudid)
    end

    if util.isBlank(uuid) then
        uuid = util.isBlank(util.get_uuid()) and "-1" or util.get_uuid()
    end

    local timestampStr = tostring(ngx.now() * 1000)
    local fpb = (ngx.var.cookie_shshshfpb == nil) and "-1" or ngx.var.cookie_shshshfpb
    local fpa = (ngx.var.cookie_shshshfpa == nil) and "-1" or ngx.var.cookie_shshshfpa
    local jda = (ngx.var.cookie___jda == nil) and "-1" or ngx.var.cookie___jda
    local fpx = "-1"
    if util.isNotBlank(ngx.var.arg_shshshfpx) then
        fpx = ngx.var.arg_shshshfpx
    elseif util.isNotBlank(ngx.var.cookie_shshshfpx) then
        fpx = ngx.var.cookie_shshshfpx
    end
    local trafficType = util.checkParamsOrDefault(config_new:get(functionId .. "_SD.trafficType"), 1)
    local source = util.checkParamsOrDefault(config_new:get(functionId .. "_SD.source"),"hold")
    local appKey = util.checkParamsOrDefault(config:get("appName"), "")
    local businessUniKey = ""
    if trafficType == 1 then
        businessUniKey = source .. "_" .. util.checkParamsOrDefault(config_new:get(functionId .. "_SD.apiKey"), "")
    elseif trafficType == 2 then
        businessUniKey = source .. "_"
                .. util.checkParamsOrDefault(config_new:get(functionId .. "_SD.apiKey"), "") .. "_"
                .. appKey
    end
    local busParams = {
        requestId = util.checkParams(uuid) .. "_" .. timestampStr,
        timestamp = timestampStr,
        referer = util.checkParamsOrDefault(ngx.req.get_headers()["referer"], "-1"),
        userAgent = ua,
        osVersion = util.checkParams(args.osVersion),
        platform = util.checkParams(args.platform),
        clientVersion = util.checkParams(args.clientVersion),
        client = util.checkParams(config:get("client")),
        clientType = util.checkParams(config:get("client")),
        uuid = uuid,
        visitkey = visitkey,
        dataHash = tostring( ngx.crc32_long( util.checkParamsOrDefault( args.ip,"-1" ) ) ),
        forcebot = util.checkParamsOrDefault(config_new:get(functionId .. "_SD.forcebot"), "0"),
        screenResolution = args.screen,
        url = args.url,
        urlQStr = args.urlQStr,
        language = args.lang,
        fpb = fpb,
        fpa = fpa,
        fpx = fpx,
        jda = jda,
        appPackage = util.checkParamsOrDefault(ngx.req.get_headers()["X-Referer-Package"], "-1"),
        --appPackage = util.checkParamsOrDefault(ngx.req.get_headers()["X-Referer-Package"], "com.jingdong.app.mall"),
        rpVerifyContent = util.checkParamsOrDefault(ngx.req.get_headers()["X-Rp-Ext"], "-1")
    }
    local host = ngx.var.host
    if ngx.var.redefineHost and ngx.var.redefineHost ~= "" then
        host = ngx.var.redefineHost
    end
    local requestUrl = ngx.var.scheme .. "://" .. host .. ngx.var.request_uri
    busParams["refererPage"] = util.checkParamsOrDefault(requestUrl, "-1")
    --busParams["X-Rp-Client"] = util.checkParamsOrDefault(ngx.req.get_headers()["X-Rp-Client"], "android_1.0.0")
    busParams["X-Rp-Client"] = util.checkParamsOrDefault(ngx.req.get_headers()["X-Rp-Client"], "h5_1.0.0")
    busParams["x-rp-evtoken"] = util.checkParamsOrDefault(ngx.req.get_headers()["x-rp-evtoken"], "-1")
    local reqParams = {
        apiKey = util.checkParamsOrDefault(config_new:get(functionId .. "_SD.apiKey"), ""),
        appKey = appKey,
        pin = util.checkParams(args.pin),
        ip = getIp(args.ip),
        source = source,
        channel = util.checkParamsOrDefault(config_new:get(functionId .. "_SD.channel"), ""),
        trafficType = trafficType,
        businessUniKey = businessUniKey,
        busParams = busParams
    }
    reqParams["J-Forwarded-For"] = util.checkParamsOrDefault(ngx.req.get_headers()["J-Forwarded-For"], "-1")
    reqParams["X-Forwarded-For"] = util.checkParamsOrDefault(ngx.req.get_headers()["X-Forwarded-For"], "-1")
    reqParams["A-Forwarded-For"] = util.checkParamsOrDefault(ngx.req.get_headers()["A-Forwarded-For"], "-1")
    reqParams["X-TLS-Version"] = util.checkParamsOrDefault(ngx.req.get_headers()["X-TLS-Version"], "-1")
    reqParams["X-SSL-Cipher"] = util.checkParamsOrDefault(ngx.req.get_headers()["X-SSL-Cipher"], "-1")
    reqParams["X-SSL-Ciphers"] = util.checkParamsOrDefault(ngx.req.get_headers()["X-SSL-Ciphers"], "-1")
    reqParams["X-SSL-Curves"] = util.checkParamsOrDefault(ngx.req.get_headers()["X-SSL-Curves"], "-1")

    -- 反爬组件集合
    local antiCrawler
    if util.checkParamsOrDefault(config_new:get(functionId .. "_SD.isOpenAntiCrawler"), 0) == 1 then
        antiCrawler = {
            components = { 5 },
            switch = { (config_new:get(functionId .. "_SD.isOpenIntercept") == 1) and 5 or -1 }
        }
    end

    -- 小号组件
    local riskAccount
    if util.checkParamsOrDefault(config_new:get(functionId .. "_SD.isOpenRiskAccount"), 0) == 1 then
        riskAccount = {
            on = 1,
            switch = config_new:get(functionId .. "_SD.isOpenIntercept")
        }
    end

    -- 风控组件
    local riskControl
    if util.checkParamsOrDefault(config_new:get(functionId .. "_SD.isOpenRiskControl"), 0) == 1 then
        riskControl = {
            on = 1,
            switch = config_new:get(functionId .. "_SD.isOpenIntercept")
        }
    end

    -- 拦截策略
    local strategies = {
        antiCrawler = antiCrawler,
        riskAccount = riskAccount,
        riskControl = riskControl
    }

    local reqParamsStr, _ = functionPcall(cjson.encode, "cjson.encode", reqParams)
    local strategiesStr, _ = functionPcall(cjson.encode, "cjson.encode", strategies)

    request_url = request_url .. "?reqParams=" .. util.urlEncode(reqParamsStr)
            .. "&strategies=" .. util.urlEncode(strategiesStr)
    ngx.log(ngx.DEBUG, "[assessRisk] ====> 最终构造请求url = ", request_url)
    return headers, request_url
end

local function handleHttpRequest(args, functionId)
    local method = "GET"
    local timeBegin = ngx.now() * 1000
    ---- 最终构造请求url
    local headers, request_url = buildRequestUrl(args, functionId)
    local timeout = util.checkParamsOrDefault(tonumber(config_new:get(functionId .. "_SD.request_timeout")), 30)
    local is_keepalive = true
    local result, _ = httpUtil.execute(request_url, method, headers, timeout, is_keepalive, nil)
    local timeEnd = ngx.now() * 1000
    local callTime = timeEnd - timeBegin;
    result = util.checkParamsOrDefault(result, {})
    return result, callTime

end



-- 设置风险染色
local function setHeader(res)

    -- 如果反爬 小号 风控都没有结果返回 不设置header
    if res == nil then
        return false;
    end

    for k, v in ipairs(res) do
        ngx.req.set_header(k, v)
    end
    return true
end

-- 记录ump日志
local function recordUmpLog(result, functionId, callTime, isGray)
    ---- 调用神盾的入口总量 (on = 1 就会记录)
    functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency"), 0, callTime)
    ---- 调用神盾的入口量按接口 (on = 1 就会记录)
    functionPcall(umpLog2, "umpLog2", getUmpKey( ".fluxProtectionService.frequency." .. functionId), 0, callTime)
    local res = util.checkParamsOrDefault(result.data, {})

    ---- WAAP反爬风险流量标识
    if res.antiCrawler and res.antiCrawler.code then
        functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.antiCrawler.code." .. res.antiCrawler.code), 0, 1)
        functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.antiCrawler.code." .. res.antiCrawler.code .."." .. functionId), 0, 1)
    end

    ---- 小号
    if res.riskAccount and res.riskAccount.code then
        functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.riskAccount.code." .. res.riskAccount.code), 0, 1)
        functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.riskAccount.code." .. res.riskAccount.code .."." .. functionId), 0, 1)
    end

    ---- 风控
    if res.riskControl and res.riskControl.code then
        functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.riskControl.code." .. res.riskControl.code), 0, 1)
        functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.riskControl.code." .. res.riskControl.code .. "." .. functionId), 0, 1)
    end

    if isGray ~= true or res.hit ~= true then
        return
    end

    ---- 执行请求并且拦截,返回响应类型：跳转url
    ---- 执行补充登录拦截 data.evContent.evType == 3
    ---- 执行验证码拦截 data.evContent.evType == 2
    if res.extraVerify == true and res.evContent then
        if res.evContent.evType == 3 then
            functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.verify.login"), 0, 1)
            functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.verify.login" .. functionId), 0, 1)
        elseif res.evContent.evType == 2 then
            functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.verify.code"), 0, 1)
            functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.verify.code" .. functionId), 0, 1)
        end
    end

    if util.checkParamsOrDefault(config_new:get(functionId .. "_SD.isOpenIntercept"), 0) == 1 or res.intercept == true then
        ----擎天灰度命中实际拦截的总量(grayInfo 有配置灰度策略)
        functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.actual"), 0, 1)
        ----擎天灰度命中实际拦截的总量,按接口记录(grayInfo 有配置灰度策略)
        functionPcall(umpLog2, "umpLog2", getUmpKey(".fluxProtectionService.frequency.intercept.actual." .. functionId), 0, 1)
    end

end

-- 执行请求后拦截策略
-- https://joyspace.jd.com/pages/tpYtw5DBkrHWklPFSVr3 神盾文档(这个文档是真的乱)
local function handleInterceptStrategy(result, functionId,args)

    local data = util.checkParamsOrDefault(result.data, {})

    ---- 调用神盾无风险
    if data.hit ~= true then
        return
    end
    local logon = util.isLogOn()
    if logon then
        local resultStr, _ = functionPcall(cjson.encode, "cjson.encode", result)
        ngx.log(ngx.ERR,"handleInterceptStrategy:result=" ..resultStr ..",pin=".. util.checkParams(args.pin) ..",functionId=" .. functionId .. ",ip=" .. util.checkParams(args.ip) .. ",uuid=".. util.checkParams(util.get_uuid()) )
    end
    ---- 风险染色,不拦截,继续向下透传
    ---- 风险染色透传header 和网关保持一致: https://joyspace.jd.com/pages/RnOC935XwzkhBvL2TevM
    ---- 如果actionType=4是风险染色
    ---- 如果actionType=8是毒丸子,需要透传
    if (data.actionType == 4 or data.actionType == 8) and setHeader(data.backendHeader) then
        return
    end

    ---- 神盾明确拦截,使用神盾拦截
    if data.intercept == true then
        if data.actionType == 0 and data.interceptContent and data.interceptContent.text then
            ----返回拦截文案
            local interceptContent = util.isBlank(data.interceptContent.text) and config_new:get(functionId .. "_SD.interceptContent") or data.interceptContent.text
            ngx.say(interceptContent)
            ngx.exit(ngx.HTTP_OK)
        elseif data.evContent  then
            local evContent = functionPcall(cjson.decode, "cjson.decode", data.evContent)
            if evContent ~= nil and evContent['evType'] == '3' and data.actionType == 6 then
                ----补充登录
                local redirectUrl_login = util.isBlank(evContent['evUrl']) and config_new:get(functionId .. "_SD.redirectUrl_login") or evContent['evUrl']
                local params = "evtype=3&evurl=" .. redirectUrl_login .. "&rpid=" .. util.checkParamsOrDefault(data.rpId, "-1")
                ngx.log(ngx.DEBUG, "[assessRisk] ====> redirectUrl_login = ", redirectUrl_login)
                redirectUtil.redirectTo(redirectUrl_login, true, functionId .. "_SD",params)
            elseif evContent ~= nil and evContent['evType'] == '2' and data.actionType == 5 then
                ----补充验证
                local redirectUrl_verify_code = util.isBlank(evContent['evUrl']) and config_new:get(functionId .. "_SD.redirectUrl_code") or evContent['evUrl']
                local params = "evtype=2&evurl=" .. redirectUrl_verify_code .. "&rpid=" .. util.checkParamsOrDefault(data.rpId, "-1")
                ngx.log(ngx.DEBUG, "[assessRisk] ====> redirectUrl_code = ", redirectUrl_verify_code)
                redirectUtil.redirectTo(redirectUrl_verify_code, false, functionId .. "_SD", params)
            end
        end
    end

    ---- 神盾不拦截,仅返回风险,擎天拦截 hit = true intercept = false isOpenIntercept = 1
    if util.checkParamsOrDefault(config_new:get(functionId .. "_SD.isOpenIntercept"), 0) == 1 then
        local responseType = util.checkParamsOrDefault(config_new:get(functionId .. "_SD.responseType"), 1)
        ---- 执行请求并且拦截,返回响应类型：json吐出
        if responseType == 1 then
            ngx.say(util.checkParams(config_new:get(functionId .. "_SD.denyMsg")))
            ngx.exit(ngx.HTTP_OK)
            ---- 执行请求并且拦截,返回响应类型：跳转url
        elseif responseType == 2  then
            ngx.redirect(config_new:get(functionId .. "_SD.redirectUrl_custom"), ngx.HTTP_MOVED_TEMPORARILY);
        end
    end


end

-- 登录态校验
local function verifyUserLogin(args)

    if args.pin ~= nil then
        return
    end

    local host = ngx.var.host
    if ngx.var.redefineHost and ngx.var.redefineHost ~= "" then
        host = ngx.var.redefineHost
    end

    local isJDCOMHost = ngx.re.find(host, "\\.jd\\.com", "jo") ~= nil

    -- 获取新指纹名称
    local fingerprint = ngx.var.arg_shshshfpx
    if not isJDCOMHost and util.isNotBlank(fingerprint) then
        local hostArray = util.split(host, ".")
        local domainSize = table.getn(hostArray)
        local topDomain = "." .. hostArray[domainSize - 1] .. "." .. hostArray[domainSize]
        ngx.header["Set-Cookie"] = "shshshfpx=" .. fingerprint .. ";Domain=" .. topDomain .."; path=/"
    end

    local result = userVerifyService.verify(args)
    if result and result.pin then
        args.pin = result.pin
    end
end


-- 调用神盾api
function _M.assessRisk(args, functionId)

    ---- 神盾是否开启
    local isSdOpen = util.checkParamsOrDefault(config_new:get(functionId .. "_SD.on"), 0)
    if tonumber(isSdOpen) ~= 1 then
        return
    end
    ---- 登录态校验
    verifyUserLogin(args)
    ---- 请求神盾api
    local result, callTime = handleHttpRequest(args, functionId)
    ---- 没有请求成功全部放过
    if result == nil or result.success ~= true or result.data == nil then
        return
    end
    ---- 是否命中灰度
    local isGray = util.isGray(functionId, util.checkUrlParams(args.pin))
    ---- 记录ump日志
    recordUmpLog(result, functionId, callTime, isGray)
    if isGray == false then
        return
    end
    ---- 执行请求后续处理
    handleInterceptStrategy(result, functionId,args)

end

return exceptionUtil.tableTryCatch(_M)
