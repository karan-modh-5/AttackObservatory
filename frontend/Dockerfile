# Attack Observatory — web image.
# Build context is the REPOSITORY ROOT (docker-compose.yml: build.context: .);
# all COPY paths below are relative to the repo root.
#
# STATIC IMAGE: the React bundle is built OFF the VPS (`cd frontend && npm run
# build`, ~10s locally) and the dist/ output is shipped to
# /opt/observatory/frontend/dist/ (tar over ssh). npm never runs here — the
# 1-vCPU/10GB box could not fit node_modules (repeated ENOSPC build failures).
FROM nginx:alpine
COPY infra/nginx/observatory.conf /etc/nginx/conf.d/default.conf
COPY frontend/dist/ /usr/share/nginx/html
EXPOSE 80
