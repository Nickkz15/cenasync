FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg python3 make g++ \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./package.json
RUN npm install --omit=dev
COPY src ./src

ENV NODE_ENV=production
EXPOSE 4000
CMD ["npm", "start"]
