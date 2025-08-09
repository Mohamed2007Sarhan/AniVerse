# AniVerse - Secure Authentication System

A modern anime-themed web application with secure authentication using PHP backend and Next.js frontend.

## Features

- 🔐 **Secure Authentication** with CSRF protection
- 🛡️ **High Security** with encryption, rate limiting, and input validation
- 🌐 **Multi-language Support** (English & Arabic)
- 🎨 **Modern UI** with beautiful animations
- 📱 **Responsive Design** for all devices

## Security Features

### Backend Security
- **CSRF Protection**: All forms protected with CSRF tokens
- **Password Encryption**: Double-layer encryption using AES-256-CBC and AES-256-GCM
- **Rate Limiting**: Maximum 5 login attempts per 15 minutes
- **Input Validation**: Comprehensive validation for all inputs
- **SQL Injection Protection**: Prepared statements throughout
- **Secure Cookies**: HttpOnly, Secure, SameSite cookies
- **Session Management**: Secure session handling

### Frontend Security
- **CSRF Token Management**: Automatic token handling
- **Secure Storage**: Encrypted local storage
- **Input Sanitization**: Client-side validation
- **XSS Protection**: Content Security Policy ready

## Prerequisites

- PHP 8.0 or higher
- MySQL 5.7 or higher
- Node.js 18 or higher
- XAMPP/WAMP/LAMP stack

## Installation

### 1. Backend Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd AnimeProject
   ```

2. **Database Setup**
   - Start your MySQL server
   - Create a database named `aniverse`
   - Import the database schema:
   ```bash
   mysql -u root -p aniverse < backend/database_schema.sql
   ```

3. **Configure Database Connection**
   - Edit `backend/db-con.php` with your database credentials:
   ```php
   $host = 'localhost';
   $dbname = 'aniverse';
   $username = 'your_username';
   $password = 'your_password';
   ```

4. **Set up PHP Environment**
   - Ensure PHP has the following extensions enabled:
     - `openssl`
     - `pdo_mysql`
     - `session`
   - Configure your web server to point to the `backend` directory

### 2. Frontend Setup

1. **Install Dependencies**
   ```bash
   cd frontend
   npm install
   # or
   yarn install
   # or
   pnpm install
   ```

2. **Environment Configuration**
   - Create `.env.local` file in the frontend directory:
   ```env
   NEXT_PUBLIC_API_URL=http://localhost/AnimeProject/backend/api
   ```

3. **Start Development Server**
   ```bash
   npm run dev
   # or
   yarn dev
   # or
   pnpm dev
   ```

## API Endpoints

### Authentication Endpoints

#### 1. Get CSRF Token
```
GET /backend/api/csrf-token.php
```
Returns a CSRF token for form protection.

#### 2. User Registration
```
POST /backend/api/register.php
Headers: {
  "Content-Type": "application/json",
  "X-CSRF-Token": "<csrf_token>"
}
Body: {
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "+1234567890",
  "password": "SecurePass123!"
}
```

#### 3. User Login
```
POST /backend/api/login.php
Headers: {
  "Content-Type": "application/json",
  "X-CSRF-Token": "<csrf_token>"
}
Body: {
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### 4. User Logout
```
POST /backend/api/logout.php
Headers: {
  "Content-Type": "application/json",
  "X-CSRF-Token": "<csrf_token>"
}
```

## Database Schema

The application uses the following main tables:

### Users Table
- `id`: Primary key
- `name`: User's full name
- `email`: Unique email address
- `phone`: Phone number
- `password`: Encrypted password
- `username`: Unique username
- `created_at`: Account creation timestamp
- `last_login`: Last login timestamp
- `login_attempts`: Failed login attempts counter
- `last_login_attempt`: Last failed login timestamp

### User Profiles Table
- Additional user information and preferences

### User Sessions Table
- Session management and tracking

### Login Attempts Table
- Security monitoring and rate limiting

## Security Best Practices

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (@$!%*?&)

### Rate Limiting
- Maximum 5 login attempts per 15 minutes
- Automatic lockout after exceeding limit
- Automatic reset after timeout

### Data Protection
- All sensitive data encrypted at rest
- Secure transmission using HTTPS
- Regular security audits recommended

## Development

### Backend Development
- All API endpoints return JSON responses
- Consistent error handling
- Comprehensive logging
- Input validation and sanitization

### Frontend Development
- TypeScript for type safety
- React hooks for state management
- Responsive design with Tailwind CSS
- Accessibility compliant

## Deployment

### Production Checklist
- [ ] Enable HTTPS
- [ ] Configure proper CORS headers
- [ ] Set up environment variables
- [ ] Configure database backups
- [ ] Set up monitoring and logging
- [ ] Test all security features
- [ ] Performance optimization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue on GitHub or contact the development team.


## Steps 

1 - interface start (Finished)
2 - Login (Finished)
3 - complelet profile (Panding)
4 - interface Dashboard (Working)
5 - Ai Analyces (Not Start)
6 - If Finish Front End Start Back end
7 - {
   make ai get state 
   make community 
   make location
} Not Make

لسا كتير معملناش غير جزء من الفروند

Total =  41.66%