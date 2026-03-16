# SpaceChild Auth

Standalone authentication and authorization service for the SpaceChild ecosystem.

## Features

🔐 **Secure Authentication**
- Password-based authentication with bcrypt
- Zero-Knowledge Proof (ZKP) authentication using Poseidon hashing
- JWT access and refresh tokens with rotation
- Email verification and password reset flows

🛡️ **Multi-Factor Authentication (MFA)**
- TOTP (Time-based One-Time Password) support via authenticator apps
- Backup codes for account recovery
- WebAuthn/Passkey support (basic implementation)

🌐 **Single Sign-On (SSO)**
- Authorization code flow with PKCE support
- Cross-subdomain authentication
- Trusted domain validation
- OAuth2-compatible endpoints

🏗️ **Enterprise Ready**
- Rate limiting and abuse protection
- Role-based access control (RBAC)
- Audit logging through events
- Graceful shutdown and error handling

## Tech Stack

- **Runtime:** Node.js 20+ with TypeScript
- **Framework:** Express.js with security middleware
- **Database:** Dolt (MySQL-compatible) with raw SQL queries
- **Authentication:** JWT, bcryptjs, circomlibjs for ZKP
- **Email:** Nodemailer with SMTP support
- **Security:** Helmet, CORS, rate limiting

## Quick Start

1. **Clone and install dependencies:**
```bash
cd spacechild-auth
npm install
```

2. **Set up environment:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Start Dolt database:**
```bash
# Install Dolt (https://github.com/dolthub/dolt)
mkdir spacechild-auth-db && cd spacechild-auth-db
dolt init
dolt sql-server -H 127.0.0.1 -P 3306 --data-dir=.
```

4. **Run in development:**
```bash
npm run dev
```

5. **Build for production:**
```bash
npm run build
npm start
```

## Environment Variables

### Required

- `SESSION_SECRET` - JWT signing secret (min 32 characters)

### Database

- `DB_HOST` - Database host (default: 127.0.0.1)
- `DB_PORT` - Database port (default: 3306)  
- `DB_USER` - Database username (default: root)
- `DB_PASSWORD` - Database password (default: empty)
- `DB_NAME` - Database name (default: spacechild_auth)

### Server

- `PORT` - Server port (default: 3100)
- `NODE_ENV` - Environment (development/production)
- `CORS_ORIGINS` - Comma-separated allowed origins

### Email (Optional)

- `SMTP_HOST` - SMTP server hostname
- `SMTP_PORT` - SMTP server port (default: 587)
- `SMTP_USER` - SMTP username
- `SMTP_PASS` - SMTP password  
- `FROM_EMAIL` - From email address
- `APP_URL` - Base URL for email links

### WebAuthn (Optional)

- `WEBAUTHN_RP_ID` - Relying party ID (your domain)
- `WEBAUTHN_ORIGIN` - Full origin URL for WebAuthn

## API Endpoints

### Authentication

- `POST /auth/register` - Create new account
- `POST /auth/login` - Login with email/password
- `POST /auth/logout` - Logout and revoke tokens
- `POST /auth/refresh` - Refresh access token

### Email Verification

- `POST /auth/verify-email` - Verify email address
- `POST /auth/resend-verification` - Resend verification email

### Password Reset

- `POST /auth/forgot-password` - Request password reset
- `POST /auth/reset-password` - Reset password with token

### Multi-Factor Authentication

- `GET /auth/mfa/status` - Get MFA status for user
- `POST /auth/mfa/verify` - Complete MFA challenge
- `POST /auth/mfa/totp/setup` - Setup TOTP authenticator
- `POST /auth/mfa/totp/verify` - Verify TOTP setup
- `DELETE /auth/mfa/totp` - Disable TOTP

### Zero-Knowledge Proofs

- `POST /auth/zk/request` - Request ZKP challenge
- `POST /auth/zk/verify` - Verify ZKP response

### Single Sign-On

- `GET /auth/sso/authorize` - OAuth2 authorization endpoint  
- `POST /auth/sso/token` - Token exchange endpoint
- `POST /auth/sso/verify` - Token verification endpoint

### User Management

- `GET /auth/user` - Get current user info
- `GET /auth/credentials` - Get user's ZK credentials
- `GET /auth/notification-preferences` - Get notification settings
- `PUT /auth/notification-preferences` - Update notification settings

### Admin (Requires admin role)

- `GET /auth/admin/users` - List all users
- `POST /auth/admin/users/:id/revoke-tokens` - Revoke user tokens

### System

- `GET /health` - Health check endpoint
- `GET /auth/.well-known/jwks.json` - JWT public keys

## Database Schema

The service automatically creates these tables:

- `users` - User accounts and profiles
- `zk_credentials` - Zero-knowledge proof credentials  
- `proof_sessions` - ZKP challenge sessions
- `refresh_tokens` - JWT refresh token storage
- `subdomain_access` - SSO domain access tracking
- `email_verification_tokens` - Email verification flows
- `password_reset_tokens` - Password reset flows
- `mfa_methods` - Multi-factor authentication methods
- `totp_secrets` - TOTP authenticator secrets
- `webauthn_credentials` - WebAuthn/Passkey credentials
- `mfa_challenges` - MFA challenge sessions
- `mfa_pending_logins` - Incomplete MFA login sessions

## Security Features

### Rate Limiting

- Login attempts: 5 per 15 minutes per IP/email
- ZKP verification: 5 per 15 minutes per IP
- Password reset: Built-in token expiry (15 minutes)

### Token Security

- Access tokens: 15 minute expiry
- Refresh tokens: 7 day expiry with rotation
- Session tokens: Cryptographically secure

### Password Security

- bcrypt with 12 salt rounds
- Minimum 8 character requirement
- Optional complexity requirements

### CORS Security

- Configurable allowed origins
- Credentials support for cross-origin auth
- Preflight caching for performance

## Deployment

### Manual Deployment

1. **Build the application:**
```bash
npm run build
```

2. **Set up production database:**
```bash
# On your server
dolt init
dolt sql-server -H 127.0.0.1 -P 3306 --data-dir=./spacechild-auth-db &
```

3. **Configure environment:**
```bash
# Create production .env file
export SESSION_SECRET="your-super-secure-secret-key"
export DB_HOST="127.0.0.1"
export NODE_ENV="production"
# ... other variables
```

4. **Start the service:**
```bash
npm start
```

### Process Management

Use PM2 for production process management:

```bash
npm install -g pm2
pm2 start dist/index.js --name spacechild-auth
pm2 save
pm2 startup
```

### Reverse Proxy

Example nginx configuration:

```nginx
server {
    listen 80;
    server_name auth.spacechild.love;
    
    location / {
        proxy_pass http://127.0.0.1:3100;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Add SSL with Let's Encrypt:
```bash
sudo certbot --nginx -d auth.spacechild.love
```

## Development

### Running Tests

```bash
npm test
npm run test:watch
```

### Code Style

The project uses TypeScript strict mode with:
- ES2022 target
- NodeNext module resolution  
- Strict type checking
- No unchecked indexed access

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure `npm run build` passes
5. Submit a pull request

## Troubleshooting

### Common Issues

**Database Connection Fails**
- Ensure Dolt is running on the configured port
- Check DB_* environment variables
- Verify network connectivity

**CORS Errors**  
- Add your domain to CORS_ORIGINS environment variable
- Check that origin headers match exactly

**Email Not Sending**
- Verify SMTP_* configuration
- Check SMTP server connectivity
- Ensure FROM_EMAIL is configured

**ZKP Features Not Working**
- circomlibjs may not build on ARM systems
- ZKP features will be disabled with warnings
- Consider using x64 architecture for full functionality

### Logs

- Application logs go to stdout/stderr
- Enable debug logging with `LOG_LEVEL=debug`
- Check database connection with `/health` endpoint

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- GitHub Issues: [Create an issue](https://github.com/spacechild/auth/issues)
- Documentation: [See the wiki](https://github.com/spacechild/auth/wiki)
- Community: [Join our Discord](https://discord.gg/spacechild)