
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg python3 make g++ \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
COPY client/package.json ./client/package.json
COPY server/package.json ./server/package.json

RUN npm install

COPY . .

RUN npm run build

ENV NODE_ENV=production

CMD ["npm", "start"]