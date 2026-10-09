local mac = require "resty.openssl.mac"
local digest = require "resty.openssl.digest"
local redis_client = require "resty.redis"
local sha256 = require "kong.tools.sha256"
local resty_string = require "resty.string"
local to_hex = resty_string.to_hex
local bit = require "bit"
local cjson = require "cjson.safe"
local lfs = require "lfs"

local Handler = {
  VERSION = "1.0.0",
  PRIORITY = 1000,
}

local public_paths = {
  ["/api/v1/auth/signup"] = true,
  ["/api/v1/auth/signin"] = true,
  ["/api/v1/auth/login"] = true,
  ["/api/v1/auth/google"] = true,
  ["/api/v1/auth/refresh"] = true,
  ["/api/v1/auth/set-password"] = true,
  ["/api/v1/auth/biometric/authenticate"] = true,
  ["/api/v1/forgot-password/verify"] = true,
  ["/api/v1/forgot-password/reset"] = true,
  ["/api/v1/subscriptions/plans"] = true,
  ["/health"] = true,
  ["/livez"] = true,
  ["/readyz"] = true,
  ["/metrics"] = true,
}

local appkey_exempt = {
  ["/health"] = true,
  ["/livez"] = true,
  ["/readyz"] = true,
  ["/metrics"] = true,
}
local secret_cache = {}

local function starts_with(value, prefix)
  return value:sub(1, #prefix) == prefix
end

local function contains(value, part)
  return value:find(part, 1, true) ~= nil
end

local function is_streaming_path(path)
  path = path:lower()
  return contains(path, "/upload") or contains(path, "/download") or contains(path, "/thumbnail")
end

local function is_public(path)
  return public_paths[path]
    or starts_with(path, "/api/v1/forgot-password/")
    or starts_with(path, "/api/v1/app/")
end

local function is_auth_route(path)
  return starts_with(path, "/api/v1/auth/")
end

local function is_upload_rate_route(path)
  return starts_with(path, "/api/v1/drive/upload")
end

local function skips_rate_limit(path)
  if starts_with(path, "/api/v1/upload/") then
    return true
  end
  if not starts_with(path, "/api/v1/storage/") then
    return false
  end
  return not (starts_with(path, "/api/v1/storage/folders/share")
    or starts_with(path, "/api/v1/storage/shares")
    or starts_with(path, "/api/v1/storage/shared"))
end

local function error_response(status, code, message)
  return kong.response.exit(status, {
    response_code = code,
    response_desc = message,
    response_data = cjson.null,
  }, { ["Content-Type"] = "application/json" })
end

local function read_secret(name)
  if secret_cache[name] ~= nil then
    return secret_cache[name] or nil
  end
  local file, err = io.open("/run/secrets/gateway/" .. name, "r")
  if not file then
    secret_cache[name] = false
    return nil, err
  end
  local value = file:read("*a")
  file:close()
  value = value and value:gsub("%s+$", "") or nil
  secret_cache[name] = value or false
  return value
end

local function safe_equal(a, b)
  if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
    return false
  end
  local diff = 0
  for i = 1, #a do
    diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
  end
  return diff == 0
end

local function verify_app_key(path, method, conf)
  if appkey_exempt[path] then
    return true
  end

  local secret, secret_err = read_secret("APP_SECRET_KEY")
  if not secret or secret == "" then
    kong.log.err("AppKey secret unavailable: ", secret_err or "empty secret")
    return nil, 503, "53", "Authentication temporarily unavailable. Please try again."
  end

  local timestamp = kong.request.get_header("X-App-Timestamp")
  local signature = kong.request.get_header("X-App-Signature")
  if not timestamp or not signature then
    return nil, 403, "03", "Access denied. Missing application credentials."
  end

  local request_ts = tonumber(timestamp)
  if not request_ts or not timestamp:match("^%-?%d+$") then
    return nil, 403, "03", "Access denied. Invalid timestamp."
  end
  local tolerance = tonumber(read_secret("APP_KEY_TOLERANCE_SECONDS")) or 30
  if math.abs(ngx.time() - request_ts) > tolerance then
    return nil, 403, "03", "Access denied. Request expired."
  end

  local body_hash = sha256.sha256_hex("")
  if not is_streaming_path(path) then
    local body_limit = conf.default_body_limit
    if starts_with(path, "/api/v1/drive/") or starts_with(path, "/api/v1/storage/") then
      body_limit = conf.upload_body_limit
    end
    local length = tonumber(kong.request.get_header("Content-Length"))
    if length and length > body_limit then
      return nil, 413, "13", "Request body too large."
    end
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local body_file = ngx.req.get_body_file()
    local body_size = body and #body or 0
    if body_file then
      local attrs = lfs.attributes(body_file)
      body_size = attrs and attrs.size or nil
    end
    if body_size == nil then
      return nil, 400, "40", "Access denied. Invalid request body."
    end
    if body_size > body_limit then
      return nil, 413, "13", "Request body too large."
    end
    if body_size > 0 then
      local ctx, err = digest.new("sha256")
      if not ctx then
        kong.log.err("request body hash unavailable: ", err or "unknown error")
        return nil, 503, "53", "Authentication temporarily unavailable. Please try again."
      end
      if body then
        local updated, update_err = ctx:update(body)
        if not updated then
          kong.log.err("request body hash failed: ", update_err or "unknown error")
          return nil, 503, "53", "Authentication temporarily unavailable. Please try again."
        end
      elseif body_file then
        local file, file_err = io.open(body_file, "rb")
        if not file then
          kong.log.err("request body file unavailable: ", file_err or "unknown error")
          return nil, 400, "40", "Access denied. Invalid request body."
        end
        while true do
          local chunk = file:read(65536)
          if not chunk then
            break
          end
          local updated, update_err = ctx:update(chunk)
          if not updated then
            file:close()
            kong.log.err("request body hash failed: ", update_err or "unknown error")
            return nil, 503, "53", "Authentication temporarily unavailable. Please try again."
          end
        end
        file:close()
      end
      local body_digest, digest_err = ctx:final()
      if not body_digest then
        kong.log.err("request body hash failed: ", digest_err or "unknown error")
        return nil, 503, "53", "Authentication temporarily unavailable. Please try again."
      end
      body_hash = to_hex(body_digest)
    end
  else
    local length = tonumber(kong.request.get_header("Content-Length"))
    if length and length > conf.upload_body_limit then
      return nil, 413, "13", "Request body too large."
    end
  end

  local payload = method .. ":" .. path .. ":" .. timestamp .. ":" .. body_hash
  local hmac_ctx, err = mac.new(secret, "HMAC", nil, "sha256")
  if not hmac_ctx then
    kong.log.err("AppKey HMAC failed: ", err or "unknown error")
    return nil, 503, "53", "Authentication temporarily unavailable. Please try again."
  end
  local mac_digest, mac_err = hmac_ctx:final(payload)
  if not mac_digest then
    kong.log.err("AppKey HMAC failed: ", mac_err or "unknown error")
    return nil, 503, "53", "Authentication temporarily unavailable. Please try again."
  end
  if not safe_equal(to_hex(mac_digest), signature) then
    return nil, 403, "03", "Access denied. Invalid signature."
  end
  return true
end

local function percent_decode(value)
  return (value:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

local function parse_redis_url(url)
  if type(url) ~= "string" then
    return nil, "invalid Redis URL"
  end
  local scheme, rest = url:match("^(rediss?)://(.+)$")
  if not scheme then
    return nil, "invalid Redis URL"
  end
  local auth, authority_path = rest:match("^(.*)@([^@]+)$")
  if not authority_path then
    authority_path = rest
  end
  local authority, path = authority_path:match("^([^/]+)(/.*)$")
  if not authority then
    authority, path = authority_path, ""
  end
  path = path:match("^([^?]*)") or ""

  local host, port
  if authority:sub(1, 1) == "[" then
    host, port = authority:match("^%[([^%]]+)%]:?(%d*)$")
  else
    host, port = authority:match("^([^:]+):?(%d*)$")
  end
  if not host or host == "" then
    return nil, "invalid Redis host"
  end

  local username, password
  if auth and auth ~= "" then
    local user, pass = auth:match("^([^:]*):(.*)$")
    if user then
      username = percent_decode(user)
      password = percent_decode(pass)
      if username == "" then
        username = nil
      end
    else
      password = percent_decode(auth)
    end
  end
  local db = tonumber(path:match("^/(%d+)$") or "0")
  return {
    host = host,
    port = tonumber(port) or 6379,
    username = username,
    password = password,
    db = db,
    tls = scheme == "rediss",
  }
end

local function connect_redis()
  local raw_url, err = read_secret("REDIS_URL")
  if not raw_url then
    return nil, err or "Redis URL unavailable"
  end
  local conf, parse_err = parse_redis_url(raw_url)
  if not conf then
    return nil, parse_err
  end
  local red = redis_client:new()
  red:set_timeouts(1000, 1000, 1000)
  local options = {
    pool = "ceriku-redis-" .. conf.host .. ":" .. conf.port,
    pool_size = 100,
  }
  if conf.tls then
    options.ssl = true
    options.ssl_verify = true
    options.ssl_server_name = conf.host
  end
  local ok, connect_err = red:connect(conf.host, conf.port, options)
  if not ok then
    return nil, connect_err
  end
  if conf.password then
    local auth_ok, auth_err
    if conf.username then
      auth_ok, auth_err = red:auth(conf.username, conf.password)
    else
      auth_ok, auth_err = red:auth(conf.password)
    end
    if not auth_ok then
      red:close()
      return nil, auth_err
    end
  end
  if conf.db ~= 0 then
    local select_ok, select_err = red:select(conf.db)
    if not select_ok then
      red:close()
      return nil, select_err
    end
  end
  return red
end

local function keepalive(red)
  if red then
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
      kong.log.debug("Redis connection not pooled: ", err or "unknown error")
      red:close()
    end
  end
end

local session_rate_script = [[
local user_id = redis.call("GET", KEYS[1])
if not user_id then return {"", 0} end
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local request_id = ARGV[4]
local key = ARGV[5] .. user_id
redis.call("ZREMRANGEBYSCORE", key, "-inf", now - window)
local count = redis.call("ZCARD", key)
if count < limit then
  redis.call("ZADD", key, now, request_id)
  redis.call("PEXPIRE", key, window)
end
return {user_id, count + 1}
]]

local public_rate_script = [[
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local request_id = ARGV[4]
local key = KEYS[1]
redis.call("ZREMRANGEBYSCORE", key, "-inf", now - window)
local count = redis.call("ZCARD", key)
if count < limit then
  redis.call("ZADD", key, now, request_id)
  redis.call("PEXPIRE", key, window)
end
return count + 1
]]

local function request_id()
  return ngx.var.request_id or (ngx.worker.pid() .. ":" .. tostring(ngx.now()))
end

local function client_ip()
  return kong.client.get_ip() or "unknown"
end

local function rate_limit_ip(path, conf, limit)
  if skips_rate_limit(path) then
    return true
  end
  local key = "rl:ip:" .. client_ip()
  if is_auth_route(path) then
    limit = conf.auth_route_rate_limit
    key = "rl:route:" .. path .. ":ip:" .. client_ip()
  elseif starts_with(path, "/api/v1/forgot-password/") then
    limit = conf.forgot_password_rate_limit
    key = "rl:route:" .. path .. ":ip:" .. client_ip()
  end
  local red, err = connect_redis()
  if not red then
    kong.log.warn("IP rate limit unavailable: ", err or "unknown error")
    return true
  end
  local count, rate_err = red:eval(public_rate_script, 1, key,
    ngx.now() * 1000, conf.window_ms, limit, request_id())
  keepalive(red)
  if not count then
    kong.log.warn("IP rate limit unavailable: ", rate_err or "unknown error")
    return true
  end
  return tonumber(count) <= limit
end

local function get_user_id(red, token, conf, path)
  local token_hash, err = sha256.sha256_hex(token)
  if not token_hash then
    return nil, err
  end
  local key = "session:" .. token_hash
  local skip_rate = skips_rate_limit(path)
  local custom_limit
  local prefix
  if is_auth_route(path) then
    custom_limit = conf.auth_route_rate_limit
    prefix = "rl:route:" .. path .. ":ip:" .. client_ip()
  elseif starts_with(path, "/api/v1/forgot-password/") then
    custom_limit = conf.forgot_password_rate_limit
    prefix = "rl:route:" .. path .. ":ip:" .. client_ip()
  elseif is_upload_rate_route(path) then
    custom_limit = conf.upload_rate_limit
  end

  if skip_rate then
    local user_id, err = red:get(key)
    if user_id == ngx.null then
      return nil, "invalid"
    end
    if not user_id then
      return nil, err or "Redis session lookup failed"
    end
    return user_id
  end

  if custom_limit then
    local count, err = red:eval(public_rate_script, 1, prefix, ngx.now() * 1000,
      conf.window_ms, custom_limit, request_id())
    if not count then
      return nil, err
    end
    if tonumber(count) > custom_limit then
      return nil, "rate_limited"
    end
  end

  local key_prefix = is_upload_rate_route(path) and "rl:upload:" or "rl:user:"
  local limit = is_upload_rate_route(path) and conf.upload_rate_limit or conf.authenticated_rate_limit
  local result, err = red:eval(session_rate_script, 1, key, ngx.now() * 1000,
    conf.window_ms, limit, request_id(), key_prefix)
  if not result then
    return nil, err
  end
  if not result[1] or result[1] == "" then
    return nil, "invalid"
  end
  if tonumber(result[2]) > limit then
    return nil, "rate_limited"
  end
  return result[1]
end

local function sign_identity(user_id)
  local secret, err = read_secret("INTERNAL_SIGNING_SECRET")
  if not secret or secret == "" then
    return nil, err or "identity signing secret unavailable"
  end
  local timestamp = tostring(ngx.time())
  local hmac_ctx, mac_err = mac.new(secret, "HMAC", nil, "sha256")
  if not hmac_ctx then
    return nil, mac_err
  end
  local signature, sign_err = hmac_ctx:final(user_id .. ":" .. timestamp)
  if not signature then
    return nil, sign_err
  end
  return timestamp, to_hex(signature)
end

function Handler:access(conf)
  local path = kong.request.get_path()
  local method = kong.request.get_method()
  local route = kong.router.get_route()
  kong.ctx.shared.ceriku_started = ngx.now()
  kong.ctx.shared.ceriku_route = path
  kong.ctx.shared.ceriku_method = method
  kong.ctx.shared.ceriku_unmatched = route and route.name == "unmatched"

  for _, header in ipairs({ "X-User-ID", "X-Identity-Timestamp", "X-Identity-Signature" }) do
    kong.service.request.clear_header(header)
  end
  kong.service.request.set_header("X-Gateway-Version", "kong-3.9.3-ceriku")
  kong.service.request.set_header("X-Request-ID", ngx.var.request_id)

  local ok, status, code, message = verify_app_key(path, method, conf)
  if not ok then
    return error_response(status, code, message)
  end

  if method == "OPTIONS" then
    return kong.response.exit(204)
  end

  if route and route.name == "gateway-health" then
    kong.service.request.set_path("/status/ready")
  end

  if is_public(path) then
    local auth_header = kong.request.get_header("Authorization") or ""
    local has_bearer = auth_header:match("^[Bb]earer ") ~= nil
    if is_auth_route(path) or starts_with(path, "/api/v1/forgot-password/") or not has_bearer then
      if not rate_limit_ip(path, conf, conf.public_rate_limit) then
        return error_response(429, "29", "Too many requests. Please try again later.")
      end
    end
    if kong.ctx.shared.ceriku_unmatched then
      return error_response(404, "04", "Not found.")
    end
    return
  end

  local auth_header = kong.request.get_header("Authorization")
  local token = auth_header and auth_header:match("^[Bb]earer (.*)$")
  if not token then
    if not rate_limit_ip(path, conf, conf.public_rate_limit) then
      return error_response(429, "29", "Too many requests. Please try again later.")
    end
    return error_response(401, "01", auth_header and "Invalid authorization header format. Expected: Bearer <token>" or "Missing authorization header.")
  end

  local red, err = connect_redis()
  if not red then
    kong.log.err("Redis session backend unavailable: ", err or "unknown error")
    return error_response(503, "53", "Authentication temporarily unavailable. Please try again.")
  end
  local user_id, auth_err = get_user_id(red, token, conf, path)
  keepalive(red)
  if auth_err == "invalid" then
    return error_response(401, "01", "Invalid or expired token.")
  elseif auth_err == "rate_limited" then
    return error_response(429, "29", "Too many requests. Please try again later.")
  elseif not user_id then
    kong.log.err("Redis session backend unavailable: ", auth_err or "unknown error")
    return error_response(503, "53", "Authentication temporarily unavailable. Please try again.")
  end

  local timestamp, signature = sign_identity(user_id)
  if not timestamp then
    kong.log.err("identity signing unavailable: ", signature or "unknown error")
    return error_response(503, "53", "Authentication temporarily unavailable. Please try again.")
  end
  kong.service.request.set_header("X-User-ID", user_id)
  kong.service.request.set_header("X-Identity-Timestamp", timestamp)
  kong.service.request.set_header("X-Identity-Signature", signature)
  if kong.ctx.shared.ceriku_unmatched then
    return error_response(404, "04", "Not found.")
  end
end

function Handler:header_filter()
  kong.response.clear_header("X-Powered-By")
  kong.response.set_header("Access-Control-Allow-Origin", "*")
  kong.response.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
  kong.response.set_header("Access-Control-Allow-Headers", "*")
  kong.response.set_header("Access-Control-Expose-Headers", "Content-Length, Content-Type, Authorization")
  kong.response.set_header("Access-Control-Max-Age", "3600")
  kong.response.set_header("X-Content-Type-Options", "nosniff")
  kong.response.set_header("X-Frame-Options", "DENY")
  kong.response.set_header("Strict-Transport-Security", "max-age=31536000")
end

function Handler:log()
  local started = kong.ctx.shared.ceriku_started or ngx.now()
  local duration = math.floor((ngx.now() - started) * 1000)
  local route = kong.ctx.shared.ceriku_route or "unmatched"
  local now = ngx.now()
  local seconds = math.floor(now)
  local milliseconds = math.floor((now - seconds) * 1000)
  kong.log.info(cjson.encode({
    level = "info",
    timestamp = os.date("!%Y-%m-%dT%H:%M:%S", seconds) .. string.format(".%03dZ", milliseconds),
    service = "ceriku-kong",
    msg = "request completed",
    requestId = ngx.var.request_id,
    route = route,
    method = kong.ctx.shared.ceriku_method or "UNKNOWN",
    status = kong.response.get_status(),
    durationMs = duration,
  }))
end

return Handler
