FROM node:20-alpine
WORKDIR /app
COPY package.json server.js index.html ./
ENV DATA_DIR=/var/data
RUN mkdir -p /var/data
EXPOSE 3000
CMD ["node", "server.js"]
