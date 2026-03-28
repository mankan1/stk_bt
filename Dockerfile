FROM nginx:alpine

# Copy dashboard
COPY index.html /usr/share/nginx/html/index.html

# nginx config that reads Railway's $PORT at runtime
# nginx:alpine includes envsubst support via /etc/nginx/templates/
RUN printf 'server {\n    listen ${PORT};\n    root /usr/share/nginx/html;\n    index index.html;\n    location / { try_files $uri $uri/ /index.html; }\n}\n' > /etc/nginx/templates/default.conf.template

ENV PORT=8080
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
