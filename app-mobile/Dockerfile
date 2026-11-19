FROM node:20-alpine AS builder
WORKDIR /app
ARG VITE_API_BASE_URL=https://vscreens-api.inverpave.com
ARG VITE_TV_URL=https://vscreens-tv.inverpave.com
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_TV_URL=$VITE_TV_URL
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY . .
RUN npx vite build --base=/mobile/

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html/mobile
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
