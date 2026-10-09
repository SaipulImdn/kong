local typedefs = require "kong.db.schema.typedefs"

return {
  name = "ceriku-auth",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { default_body_limit = { type = "integer", default = 1048576, between = { 1, 104857600 } } },
          { upload_body_limit = { type = "integer", default = 104857600, between = { 1, 1073741824 } } },
          { public_rate_limit = { type = "integer", default = 60, between = { 1, 1000000 } } },
          { authenticated_rate_limit = { type = "integer", default = 600, between = { 1, 1000000 } } },
          { upload_rate_limit = { type = "integer", default = 30, between = { 1, 1000000 } } },
          { auth_route_rate_limit = { type = "integer", default = 30, between = { 1, 1000000 } } },
          { forgot_password_rate_limit = { type = "integer", default = 10, between = { 1, 1000000 } } },
          { window_ms = { type = "integer", default = 60000, between = { 1000, 3600000 } } },
        },
      },
    },
  },
}
