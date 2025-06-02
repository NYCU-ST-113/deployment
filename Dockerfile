FROM openresty/openresty:alpine

RUN apk add --no-cache perl curl
RUN opm install SkyLothar/lua-resty-jwt


COPY conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/jwt_checker.lua /etc/openresty/jwt_checker.lua
