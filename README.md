# JWT Authentication Project

This project implements a JWT (JSON Web Token) based authentication system using Spring Boot. It provides secure endpoints for user registration, login, refresh token mechanism, logout functionality, and a test endpoint to verify authentication.

## Features

1. User Registration
2. User Login
3. JWT-based Authentication
4. Refresh Token Mechanism
5. Secure Endpoints
6. Logout Functionality
7. Global Exception Handling

## API Endpoints

### 1. Register User
- **Endpoint:** `/register`
- **Method:** POST
- **Description:** Register a new user
- **Request Body:**
  ```json
  {
    "username": "string",
    "password": "string",
    "fullName": "string"
  }
  ```
- **Response:** Returns JWT and refresh tokens upon successful registration
- **Error:** Returns 409 CONFLICT if username already exists

### 2. Login
- **Endpoint:** `/login`
- **Method:** POST
- **Description:** Authenticate a user and receive tokens
- **Request Body:**
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **Response:** Returns JWT and refresh tokens upon successful authentication

### 3. Refresh Token
- **Endpoint:** `/refresh`
- **Method:** POST
- **Description:** Get new tokens using existing refresh token
- **Request Body:**
  ```json
  {
    "jwtToken": "string",
    "refreshToken": "string"
  }
  ```
- **Response:** Returns new JWT and refresh tokens

### 4. Logout
- **Endpoint:** `/logout`
- **Method:** POST
- **Description:** Invalidates the refresh token
- **Authentication:** Requires valid JWT token
- **Response:** Success message upon logout

### 5. Test Authentication
- **Endpoint:** `/test`
- **Method:** GET
- **Description:** A simple protected endpoint for users having ADMIN or USER role
- **Authentication:** Requires valid JWT token
- **Response:** Returns "Successful" if authenticated

## Authentication Flow

1. **Registration:**
   - User sends a POST request to `/register` with username, password, and full name
   - System validates if username is unique
   - Creates a new user in the database with an encoded password
   - Generates and returns both JWT and refresh tokens

2. **Login:**
   - User sends a POST request to `/login` with credentials
   - System authenticates the user
   - Generates and returns both JWT and refresh tokens

3. **Token Refresh:**
   - User sends both JWT and refresh tokens to `/refresh`
   - If JWT is still valid, returns the same tokens
   - If JWT expired but refresh token is valid, generates new tokens
   - If refresh token expired, user must login again

4. **Logout:**
   - User sends POST request to `/logout`
   - System invalidates the refresh token
   - User must login again to access protected resources

5. **Accessing Protected Resources:**
   - User includes JWT token in Authorization header
   - `JwtAuthenticationFilter` validates the token
   - Access granted if token is valid

## Security Configuration

- CSRF protection is disabled for this project
- Session management is set to stateless
- The `/login` and `/register` endpoints are publicly accessible
- The `/test` endpoint requires either 'ADMIN' or 'USER' role
- Custom `JwtAuthenticationFilter` in security filter chain

## Key Components

1. `TestController`: Handles registration, login, refresh, logout, and test endpoints
2. `AuthenticationService`: Manages user authentication operations
3. `RefreshTokenService`: Handles refresh token operations
4. `SecurityConfig`: Configures security settings
5. `JwtAuthenticationFilter`: Custom JWT validation filter
6. `JwtService`: Manages JWT operations
7. `TestControllerAdvice`: Global exception handling

## Notes

- The project uses a hardcoded secret key for JWT signing. In a production environment, this should be securely managed and not hard-coded
- JWT token expiration is set to 20 minutes by default
- Refresh token expiration is configurable (default in days)
- The project is configured to use H2 in-memory database, which is suitable for development but should be replaced with a persistent database for production use
- The JWT secret key uses a 256-bit secret which is the minimum for JWT and is represented in hexadecimal format for better readability. Spring auto selects the best algorithm to use according to the size of secret (HMAC with SHA-256 for me). Use bigger keys for better security
- Refresh Token used is a random String. Best practices would include jwt to make it completely stateless if logout features are not needed.