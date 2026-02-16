FROM node:18-alpine AS builder
WORKDIR /app
ARG VITE_API_BASE_URL
ARG VITE_TV_URL
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_TV_URL=$VITE_TV_URL
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

# Stage 2: Serve
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
