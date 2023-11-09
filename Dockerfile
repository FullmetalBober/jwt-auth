FROM node:21.1-slim
WORKDIR /app
COPY . /app
RUN npm install
EXPOSE 3000
CMD npm start
