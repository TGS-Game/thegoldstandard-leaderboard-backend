FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY src ./src
COPY public ./public

ENV PORT=8787
EXPOSE 8787

CMD ["npm", "start"]
