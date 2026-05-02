# Inventory System with Security

## Objective
Design and implement a robust, secure, and scalable inventory management application with strong cryptographic controls, modular architecture, and OWASP-aligned protections.

## 1) Authentication & Identity Management

### Registration Module
**Required user fields**
- `first_name`
- `middle_name` (optional)
- `last_name`
- `email`
- `password`
- `confirm_password` (request-time validation only; never stored)

**Security rules**
- **PII encryption at rest** (names, contact details) using **AES-256-GCM**.
- **Email** must be RFC-compliant and unique.
- **Password** and **confirm_password** must match before persistence.
- **Password hashing** via **bcrypt** with cost factor **12** minimum.
- **Verification tokens** (if email verification is enabled) generated from CSPRNG bytes and stored as **SHA-256 hash**.

**Suggested registration flow**
1. Validate payload shape and input length.
2. Normalize email (trim + lowercase).
3. Check email uniqueness.
4. Encrypt PII fields with AES-256-GCM before DB write.
5. Hash password with bcrypt cost 12+.
6. Generate optional email verification token (`raw_token` to user, `sha256(raw_token)` to DB).
7. Store audit metadata (`created_by`, `created_at`).

### Login Module
- **Mechanism:** email + password.
- **Rate limiting / throttling:**
  - Example: 5 failed attempts per 15 minutes per IP/email tuple.
  - Optional stepped lockout (e.g., 15 min, then 1 hour on repeated abuse).
- **Session management:**
  - Option A: JWT (short-lived access token + rotating refresh token).
  - Option B: server-side session with **HttpOnly + Secure + SameSite=Strict** cookie.
- **Post-login controls:**
  - Record failed/successful login attempts.
  - Trigger alerts on suspicious behavior (geo/IP anomalies).

---

## 2) Inventory Core Modules

The domain model uses relational normalization with explicit foreign keys.

### A. Products Module
**Attributes**
- `name`
- `sku` (unique)
- `description`
- `unit_price`
- `quantity_on_hand`

**Required behaviors**
- CRUD endpoints.
- Stock mutation audit logs capturing:
  - who changed stock,
  - previous quantity,
  - new quantity,
  - timestamp,
  - reason.

### B. Supplier Module
**Attributes**
- `name`
- `contact_person`
- `phone`
- `address`

**Relationship requirement**
- Many-to-many mapping between suppliers and products to support multi-source procurement.

### C. Category Module
**Attributes**
- `name`
- `parent_category_id` (self-reference for hierarchy)

**Functional requirement**
- Category tree for filtering, grouping, and reporting.

---

## 3) Technical Constraints & Architecture

### Security Baseline (OWASP Top 10 alignment)
- **A03 Injection:** parameterized queries / ORM prepared statements only.
- **A03 / XSS:** output encoding, HTML sanitization, strict Content Security Policy where web UI is used.
- **A01 Broken Access Control:** role-based authorization middleware and resource-level ownership checks.
- CSRF protection for cookie-based auth.
- Strong input validation and centralized error handling.

### Cryptography Standards
- **Passwords:** bcrypt (cost >= 12).
- **Token / checksum hashing:** SHA-256.
- **At-rest encryption:** AES-256-GCM for PII (names/contact details).
- Per-record random IV/nonce (12 bytes for GCM), never reused with same key.
- Managed key rotation policy (versioned key IDs in encrypted payload metadata).

### Clean Architecture (Service-Repository pattern)
- **Controller/API layer:** transport concerns (HTTP validation, status codes).
- **Service layer:** business rules and orchestration.
- **Repository layer:** persistence abstractions and SQL/ORM implementation.
- **Middleware:** authentication, authorization, rate limiting, and request tracing.

All inventory and user-management endpoints must be protected by authentication middleware (except registration/login/verification endpoints).

---

## 4) Expected Deliverables

## A. Normalized SQL Schema (PostgreSQL-style)

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'staff',
  is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE user_profiles (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  first_name_enc TEXT NOT NULL,
  middle_name_enc TEXT,
  last_name_enc TEXT NOT NULL,
  phone_enc TEXT,
  address_enc TEXT,
  encryption_key_version INT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE email_verification_tokens (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_sha256 CHAR(64) NOT NULL UNIQUE,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE categories (
  id UUID PRIMARY KEY,
  name VARCHAR(150) NOT NULL,
  parent_category_id UUID REFERENCES categories(id) ON DELETE SET NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(name, parent_category_id)
);

CREATE TABLE suppliers (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  contact_person_enc TEXT,
  phone_enc TEXT,
  address_enc TEXT,
  encryption_key_version INT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE products (
  id UUID PRIMARY KEY,
  category_id UUID REFERENCES categories(id) ON DELETE SET NULL,
  name VARCHAR(255) NOT NULL,
  sku VARCHAR(100) NOT NULL UNIQUE,
  description TEXT,
  unit_price NUMERIC(12,2) NOT NULL CHECK (unit_price >= 0),
  quantity_on_hand INT NOT NULL DEFAULT 0 CHECK (quantity_on_hand >= 0),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE product_suppliers (
  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  supplier_id UUID NOT NULL REFERENCES suppliers(id) ON DELETE CASCADE,
  supplier_sku VARCHAR(100),
  is_primary BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  PRIMARY KEY (product_id, supplier_id)
);

CREATE TABLE inventory_audit_logs (
  id UUID PRIMARY KEY,
  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  changed_by_user_id UUID NOT NULL REFERENCES users(id),
  action_type VARCHAR(50) NOT NULL,
  previous_quantity INT,
  new_quantity INT,
  delta INT,
  reason TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

## B. API Documentation (v1)

### Auth Endpoints
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/verify-email`

### Product Endpoints
- `GET /api/v1/products`
- `GET /api/v1/products/{id}`
- `POST /api/v1/products`
- `PATCH /api/v1/products/{id}`
- `DELETE /api/v1/products/{id}`
- `POST /api/v1/products/{id}/stock-adjustments`

### Supplier Endpoints
- `GET /api/v1/suppliers`
- `POST /api/v1/suppliers`
- `PATCH /api/v1/suppliers/{id}`
- `DELETE /api/v1/suppliers/{id}`
- `POST /api/v1/suppliers/{id}/products/{productId}`

### Category Endpoints
- `GET /api/v1/categories`
- `POST /api/v1/categories`
- `PATCH /api/v1/categories/{id}`
- `DELETE /api/v1/categories/{id}`

> All endpoints (except register/login/verify/refresh as applicable) require auth middleware.

## C. Security Documentation (minimum operational standard)
- **bcrypt cost factor:** `12` (recommended review threshold: `13+` where latency budget allows).
- **bcrypt salt:** auto-generated per-password by bcrypt.
- **SHA-256 usage:** verification tokens and integrity hashes only (not password storage).
- **AES mode:** AES-256-GCM with random per-record nonce.
- **Key management:** environment-backed master keys via KMS/HSM, versioned key IDs, scheduled rotation, and re-encryption policy.
- **Logging:** never log raw secrets, passwords, raw tokens, or decrypted PII.
