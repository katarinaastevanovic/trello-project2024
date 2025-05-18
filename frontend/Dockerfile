FROM node:20-alpine

# Postavljanje radnog direktorijuma unutar kontejnera
WORKDIR /app

COPY package*.json ./
# Instaliranje zavisnosti
RUN npm install

# Kopiranje svih fajlova iz projekta
COPY . .
EXPOSE 4200

CMD ["npm", "run", "start", "--", "--host", "0.0.0.0", "--port", "4200"]

