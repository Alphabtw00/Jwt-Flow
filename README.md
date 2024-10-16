# JWT Authentication Project

This project implements a JWT (JSON Web Token) based authentication system using Spring Boot. It provides secure endpoints for user registration, login, and a test endpoint to verify authentication.

## Features

1. User Registration
2. User Login
3. JWT-based Authentication
4. Secure Endpoints

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
- **Response:** Returns a JWT token upon successful registration

### 2. Login
- **Endpoint:** `/login`
- **Method:** POST
- **Description:** Authenticate a user and receive a JWT token
- **Request Body:**
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **Response:** Returns a JWT token upon successful authentication

### 3. Test Authentication
- **Endpoint:** `/test`
- **Method:** GET
- **Description:** A protected endpoint to test if the user is authenticated
- **Authentication:** Requires a valid JWT token in the Authorization header
- **Response:** Returns "Successful" if authenticated

## Authentication Flow

1. **Registration:**
    - User sends a POST request to `/register` with username, password, and full name.
    - System creates a new user in the database with an encoded password.
    - A JWT token is generated and returned to the user.

2. **Login:**
    - User sends a POST request to `/login` with username and password.
    - System authenticates the user against the stored credentials.
    - If successful, a new JWT token is generated and returned to the user.

3. **Accessing Protected Resources:**
    - User includes the JWT token in the Authorization header of the request.
    - The `JwtAuthenticationFilter` intercepts the request and validates the token.
    - If the token is valid, the user is granted access to the protected resource.

## Security Configuration

- CSRF protection is disabled for this project.
- Session management is set to stateless.
- The `/login` endpoint is publicly accessible.
- The `/test` endpoint requires either 'ADMIN' or 'USER' role.
- A custom `JwtAuthenticationFilter` is added to the security filter chain.

## Key Components

1. `TestController`: Handles registration, login, and test endpoints.
2. `AuthenticationService`: Manages user registration and authentication logic.
3. `SecurityConfig`: Configures security settings and filter chain.
4. `JwtAuthenticationFilter`: Custom filter for JWT-based authentication.
5. `JwtService`: Handles JWT token generation, validation, and parsing.

## Notes

- The project uses a hardcoded secret key for JWT signing. In a production environment, this should be securely managed and not hard-coded.
- Token expiration is set to 20 minutes by default.
- The project is configured to use H2 in-memory database, which is suitable for development but should be replaced with a persistent database for production use.
- The JWT secret key uses a 256-bit secret which is the minimum for Jwt and its represented in hexadecimal format for better readability. Spring auto selects the best algorithm to use according to the size of secret (HMAC with SHA-256 for me). Use bigger keys for better security. 