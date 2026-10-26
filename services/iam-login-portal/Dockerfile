FROM node:22-slim AS build
WORKDIR /workspace/iam-login-portal
COPY iam-login-portal/package.json iam-login-portal/package-lock.json* ./
RUN npm install
COPY iam-login-portal/ ./
RUN npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /workspace/iam-login-portal/package.json ./package.json
COPY --from=build /workspace/iam-login-portal/node_modules ./node_modules
COPY --from=build /workspace/iam-login-portal/.next ./.next
COPY --from=build /workspace/iam-login-portal/public ./public
COPY --from=build /workspace/iam-login-portal/server.js ./server.js
EXPOSE 3000
ENTRYPOINT ["node", "server.js"]
