FROM node:20.11 AS build-service
ARG APP_HOME=/home/node/app
ARG SERVICE

WORKDIR /home/node/app

RUN corepack enable

COPY package.json yarn.lock ./

RUN yarn install --frozen-lockfile

COPY . .

RUN yarn build

FROM node:20.11-slim AS final

ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

WORKDIR /home/node/app
CMD ["node", "dist/server.js"]

COPY --from=build-service --chown=node:node /home/node/app/dist ./dist
COPY --from=build-service --chown=node:node /home/node/app/node_modules ./node_modules
COPY --from=build-service --chown=node:node /home/node/app/package.json .

# Cut unnecessary stuff from package.json. Only leave name, version, description and module type
RUN node -e "\
  const { name, description, version, type } = JSON.parse(fs.readFileSync('./package.json', 'utf-8'));\
  fs.writeFileSync('./package.json', JSON.stringify({ name, version, description, type }, null, 2));\
"

ENV PORT 3000

ENV RESOLVER_URL CHANGE
ENV SIGNER_SIGN_URL CHANGE

EXPOSE 3000

USER node

