# Attack Observatory — web image.
# Build context is the REPOSITORY ROOT (docker-compose.yml: build.context: .);
# all COPY paths below are relative to the repo root.
#
# MULTI-STAGE: the React bundle is built in a throwaway node stage, so a fresh
# clone builds without a pre-existing frontend/dist/ (gitignored). The node
# stage's build cache is the disk cost (~700 MB) — run `docker builder prune`
# if the 10GB disk fills; the final nginx image stays small.
FROM node:22-alpine AS build
# 512MB VPS + 2G swap: cap the Node heap so the rollup build cannot OOM the box.
ENV NODE_OPTIONS=--max-old-space-size=1024
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginx:alpine
COPY infra/nginx/observatory.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
