
# Step 1: Choose base image
FROM node:20-alpine

# Step 2: Create working directory inside container
WORKDIR /app

# Step 3: Copy package files first
COPY package*.json ./

# Step 4: Install dependencies
RUN npm install
RUN npm install nodemon --save-dev

# Step 5: Copy remaining source code
COPY . .

# Step 6: Expose port (same as your app)
EXPOSE 8080

# Step 7: Start application
CMD ["npm", "run", "dev"]
