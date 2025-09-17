# Choose Rich 🎮

A high-performance Rust-based gaming API server featuring two exciting casino-style games: **Mines** and **Apex**. Built with Axum web framework and PostgreSQL for robust, scalable gaming experiences.

## 🚀 Features

### 🎯 Games

- **Mines Game**: Classic mine-sweeping game with customizable grid sizes and mine counts
- **Apex Game**: Number prediction game with High/Low/Equal choices and Blinder mode

### 🔐 Authentication & Security

- JWT-based authentication system
- Automatic private key generation for users
- Support for both Bitcoin (P2PKH) and Ethereum addresses
- Password hashing with SHA256
- CORS-enabled for web integration

### 🏗️ Architecture

- **Framework**: Axum (async Rust web framework)
- **Database**: PostgreSQL with SQLx for type-safe queries
- **Caching**: Moka for high-performance session caching
- **Error Handling**: Comprehensive error handling with `eyre` and `thiserror`
- **Testing**: Extensive test coverage for all modules

## 📋 Prerequisites

- **Rust** (latest stable version)
- **PostgreSQL** (version 12 or higher)
- **Git**

## 🛠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd choose-rich
```

### 2. Database Setup

Start PostgreSQL and create a database:

```bash
# Start PostgreSQL service
sudo systemctl start postgresql  # Linux
# or
brew services start postgresql   # macOS

# Create database
createdb postgres
```

### 3. Environment Configuration

The application uses default PostgreSQL connection settings:

- **Host**: localhost
- **Port**: 5432
- **Database**: postgres
- **Username**: postgres
- **Password**: postgres

To customize, modify the connection string in `src/main.rs`:

```rust
let pg_default = "postgresql://username:password@host:port/database";
```

### 4. Build and Run

```bash
# Build the project
cargo build --release

# Run the server
cargo run
```

The server will start on `http://0.0.0.0:5433`

### 5. Verify Installation

```bash
curl http://localhost:5433/
# Expected response: "Choose Rich API is running!"
```

## 🎮 Game APIs

### Authentication Endpoints

#### Register User

```http
POST /register
Content-Type: application/json

{
  "username": "player1",
  "pass": "securepassword"
}
```

**Response:**

```json
{
  "result": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "error": null
}
```

#### Login User

```http
POST /login
Content-Type: application/json

{
  "username": "player1",
  "pass": "securepassword"
}
```

### Mines Game

#### Start Mines Game

```http
POST /mines/start
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "amount": 1000,
  "blocks": 25,
  "mines": 5
}
```

**Response:**

```json
{
  "result": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "amount": 1000,
    "blocks": 25,
    "mines": 5,
    "session_status": "Active"
  },
  "error": null
}
```

#### Make Move

```http
POST /mines/move
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "block": 12
}
```

**Response:**

```json
{
  "result": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "actions": {
      "move_1": {
        "block": 12,
        "multiplier": 1.2375,
        "safe": true
      }
    },
    "current_multiplier": 1.2375,
    "potential_payout": 1237,
    "final_payout": null,
    "bomb_blocks": null,
    "session_status": "Active"
  },
  "error": null
}
```

#### Cashout

```http
POST /mines/cashout
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Apex Game

#### Start Apex Game (Non-Blinder Mode)

```http
POST /start
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "amount": 500,
  "option": "NonBlinder"
}
```

**Response:**

```json
{
  "result": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "amount": 500,
    "option": "NonBlinder",
    "system_number": 7,
    "user_number": null,
    "payout_high": 0.33,
    "probability_high": 0.2,
    "payout_low": 1.32,
    "probability_low": 0.7,
    "payout_equal": 9.9,
    "probability_equal": 0.1,
    "payout_percentage": null,
    "blinder_suit": null,
    "session_status": "Active"
  },
  "error": null
}
```

#### Start Apex Game (Blinder Mode)

```http
POST /start
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "amount": 500,
  "option": "Blinder"
}
```

#### Make Choice (Non-Blinder Only)

```http
POST /choose
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "choice": "High"
}
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test mines::router::tests
cargo test auth::auth::tests
cargo test store::db_store::tests
```

### Test Coverage

- **Authentication**: User registration, login, JWT token generation
- **Mines Game**: Game session creation, move validation, cashout logic
- **Apex Game**: Both Blinder and Non-Blinder modes
- **Database**: CRUD operations, migrations, constraints
- **Crypto**: Private key generation, address derivation

## 🏗️ Project Structure

```
src/
├── main.rs              # Application entry point
├── server.rs            # Application state and configuration
├── primitives.rs        # Utility functions and cache helpers
├── auth/                # Authentication module
│   ├── auth.rs         # User registration, login, JWT handling
│   ├── middleware.rs   # Authentication middleware
│   └── mod.rs          # Module exports
├── mines/               # Mines game implementation
│   ├── mod.rs          # Game logic and data structures
│   └── router.rs       # HTTP handlers and routing
├── apex/                # Apex game implementation
│   ├── apex.rs         # Game logic and HTTP handlers
│   └── mod.rs          # Module exports
└── store/               # Database layer
    ├── db_store.rs     # PostgreSQL operations
    └── mod.rs          # Data models and exports
```

## 🔧 Configuration

### Environment Variables

- `JWT_SECRET`: Secret key for JWT token signing (default: "JWT_SECRET")
- `X-SERVER-SECRET`: Server authentication secret (default: "X-Server-secret")

### Database Configuration

- Connection pool size: 2000 connections
- Session TTL: 30 minutes
- Auto-migration on startup

### Game Configuration

- **Mines**: Supports perfect square grid sizes (4, 9, 16, 25, etc.)
- **House Edge**: 1% applied to all games
- **Session Management**: Automatic cleanup after 30 minutes

## 🚀 Performance Features

- **Async/Await**: Full async implementation for high concurrency
- **Connection Pooling**: Efficient database connection management
- **Caching**: In-memory session caching with TTL
- **Type Safety**: Rust's type system ensures runtime safety
- **Zero-Copy**: Efficient memory usage with minimal allocations

## 🔒 Security Features

- **JWT Authentication**: Secure token-based authentication
- **Password Hashing**: SHA256 password hashing
- **Input Validation**: Comprehensive request validation
- **CORS Support**: Configurable cross-origin resource sharing
- **Private Key Management**: Secure key generation and storage

## 📊 Monitoring & Logging

The application includes structured logging using the `tracing` crate:

```bash
# Run with debug logging
RUST_LOG=debug cargo run

# Run with info logging (default)
RUST_LOG=info cargo run
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:

- Create an issue in the repository
- Check the test files for usage examples
- Review the API documentation above

## 🔮 Future Enhancements

- [ ] WebSocket support for real-time gaming
- [ ] Additional game modes
- [ ] Admin dashboard
- [ ] Payment integration
- [ ] Mobile app support
- [ ] Advanced analytics and reporting

---

**Built with ❤️ in Rust** 🦀
