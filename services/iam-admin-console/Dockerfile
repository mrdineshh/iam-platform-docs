FROM node:22-slim AS build
WORKDIR /workspace/iam-admin-console
COPY iam-admin-console/package.json iam-admin-console/package-lock.json* ./
RUN npm install
COPY iam-admin-console/ ./
# Vite bakes import.meta.env.VITE_* in at build time, not runtime -- the
# checked-in config.ts defaults (http://localhost:8xxx) only work when the
# browser loading this SPA is on the same machine as the backend services,
# which isn't true for a real deployed demo. Build args let each deploy
# target point at its own reachable service URLs without editing source.
ARG VITE_AUTH_SVC_URL
ARG VITE_TENANT_SVC_URL
ARG VITE_POLICY_SVC_URL
ARG VITE_ROOT_DOMAIN
ARG VITE_OIDC_ISSUER_URL
ARG VITE_LOGIN_PORTAL_URL
ENV VITE_AUTH_SVC_URL=$VITE_AUTH_SVC_URL
ENV VITE_TENANT_SVC_URL=$VITE_TENANT_SVC_URL
ENV VITE_POLICY_SVC_URL=$VITE_POLICY_SVC_URL
ENV VITE_ROOT_DOMAIN=$VITE_ROOT_DOMAIN
ENV VITE_OIDC_ISSUER_URL=$VITE_OIDC_ISSUER_URL
ENV VITE_LOGIN_PORTAL_URL=$VITE_LOGIN_PORTAL_URL
RUN npm run build

# Pure static SPA -- no server-side runtime needed (BUILD_PLAN.md's tech
# choice for this service). nginx serves the built assets with an SPA
# fallback so client-side routing (react-router) works on a hard refresh.
FROM nginx:alpine
COPY --from=build /workspace/iam-admin-console/dist /usr/share/nginx/html
# Rendered at container start (nginx image's envsubst step) so the Content-
# Security-Policy can name this deployment's backend hosts.
ENV CSP_CONNECT_SRC=""
COPY iam-admin-console/nginx.conf.template /etc/nginx/templates/default.conf.template
EXPOSE 80
