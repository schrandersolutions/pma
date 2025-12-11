FROM node:18-alpine

WORKDIR /app

# Install dependencies only
COPY package.json package-lock.json* ./
RUN npm install

# Copy source code
COPY . .

EXPOSE 3000

# Run dev server (not production build)
CMD ["npm", "run", "dev"]
