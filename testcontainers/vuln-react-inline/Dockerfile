FROM node:20-alpine

WORKDIR /app
COPY package.json server.js /app/
RUN npm install --omit=dev

EXPOSE 8086
CMD ["node", "/app/server.js"]
