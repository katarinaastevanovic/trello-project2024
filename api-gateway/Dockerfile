FROM nginx:latest

COPY ./server.crt /etc/nginx/ssl/server.crt
COPY ./server.key /etc/nginx/ssl/server.key

COPY ./api_gateway.conf /etc/nginx/conf.d/api_gateway.conf
RUN rm /etc/nginx/conf.d/default.conf
