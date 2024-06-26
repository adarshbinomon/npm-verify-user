# npm-verify-user

## Overview

npm-verify-user is a simple JWT authenticator package designed to verify user authentication tokens in Node.js applications using Express. This middleware checks whether the provided access token is valid, and if it's expired but a refresh token is available, it generates a new access token.

## Installation

To install npm-verify-user, run the following command in your Node.js project directory:

```bash
npm install npm-verify-user
```

## Usage

1. **Import the Package**:

   Import the package in your Express application file (`app.ts` or `app.js`):

   ```typescript
   import { verifyUser } from 'npm-verify-user';
   ```

2. **Add Middleware**:

   Use the `verifyUser` middleware in the router section of your Express application to authenticate and verify users:

   ```typescript
   app.use('/api', verifyUser, yourRouter);
   ```

3. **Environment Variables**:

   Ensure you have the following environment variables set in your `.env` file:

   - `ACCESS_SECRET_KEY`: Secret key for generating and verifying access tokens.
   - `ACCESS_TOKEN_EXPIRY`: Expiry time for access tokens (e.g., '15m' for 15 minutes).
   - `REFRESH_SECRET_KEY`: Secret key for generating and verifying refresh tokens.
   - `REFRESH_TOKEN_EXPIRY`: Expiry time for refresh tokens (e.g., '7d' for 7 days).

4. **Handling Errors**:

   If the authentication fails due to an invalid or expired token, the middleware will return a 401 Unauthorized response with an appropriate message.

## Example

Here's an example of how you can use `npm-verify-user` middleware in your Express application:

```typescript
import express from 'express';
import { verifyUser } from 'npm-verify-user';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Add middleware
app.use(express.json());
app.use('/api', verifyUser, yourRouter);

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
```

## Contributing

Contributions to npm-verify-user are welcome! Feel free to open issues or submit pull requests on the GitHub repository.

