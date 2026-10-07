# Website: build with Node, then serve the static files with nginx.
#   docker build --build-arg VITE_API_URL=https://api.example.com -t securesphere-frontend .
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:1.27-alpine
# nginx fills ${API_URL} in the template when the container starts (used in the CSP header).
ENV API_URL=http://localhost:8000
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
