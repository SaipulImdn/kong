local kong = kong
local fmt  = string.format
local CONTENT_TYPE = "Content-Type"
local cjson = require "cjson.safe"


local BODIES = {
  [400] = "Bad request",
  [401] = "Unauthorized",
  [403] = "Forbidden",
  [404] = "Not found",
  [405] = "Method not allowed",
  [408] = "Request timeout",
  [411] = "Length required",
  [412] = "Precondition failed",
  [413] = "Payload too large",
  [414] = "URI too long",
  [417] = "Expectation failed",
  [429] = "Too many requests. Please try again later.",
  [494] = "Request header or cookie too large",
  [500] = "An unexpected error occurred",
  [502] = "An invalid response was received from the upstream server",
  [503] = "The upstream server is currently unavailable",
  [504] = "The upstream server is timing out",
}

local RESPONSE_CODES = {
  [400] = "40",
  [401] = "01",
  [403] = "03",
  [404] = "04",
  [405] = "40",
  [408] = "54",
  [411] = "40",
  [412] = "40",
  [413] = "13",
  [414] = "40",
  [417] = "40",
  [429] = "29",
  [494] = "40",
  [500] = "50",
  [502] = "52",
  [503] = "53",
  [504] = "54",
}


local get_body
do
  local DEFAULT_FMT = "Request failed with HTTP status %d"

  get_body = function(status)
    local body = BODIES[status]

    if body then
      return body
    end

    body = fmt(DEFAULT_FMT, status)
    BODIES[status] = body

    return body
  end
end


return function(ctx)
  local status = kong.response.get_status()
  local message = get_body(status)

  -- Nginx 494 status code is used internally when the client sends
  -- too large or invalid HTTP headers. Kong is obliged to convert
  -- it back to `400 Bad Request`.
  if status == 494 then
    status = 400
  end

  local response_code = RESPONSE_CODES[status]
    or (status >= 500 and "50" or "40")
  local body = {
    response_code = response_code,
    response_desc = message,
    response_data = cjson.null,
  }

  -- Reset relevant context values
  ctx.buffered_proxying = nil
  ctx.response_body = nil

  if ctx then
    ctx.delay_response = nil
    ctx.delayed_response = nil
    ctx.delayed_response_callback = nil
  end

  return kong.response.exit(status, body, { [CONTENT_TYPE] = "application/json" })
end
