local jwt = require "resty.jwt"

ngx.log(ngx.ERR, "[JWT] Start verifying...")

local token = ngx.var.http_authorization
if not token then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Missing Authorization header")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local _, _, jwt_token = string.find(token, "Bearer%s+(.+)")
if not jwt_token then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Invalid Authorization header format")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local jwt_obj = jwt:verify("super_secret_for_my_app", jwt_token)
if not jwt_obj.verified then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("JWT verification failed: ", jwt_obj.reason)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

ngx.req.set_header("X-User-Id", jwt_obj.payload.username or "")
ngx.req.set_header("X-User-Role", jwt_obj.payload.role or "")

local method = ngx.req.get_method()
local uri = ngx.var.uri

ngx.log(ngx.ERR, "[JWT] Requested URI: ", uri)
ngx.log(ngx.ERR, "[JWT] Method: ", method)

-- /api/apply/getAll need admin
if method == "GET" and uri == "/api/apply/getAll" then
    if jwt_obj.payload.role ~= "admin" then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say("Permission denied: admin only")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end
