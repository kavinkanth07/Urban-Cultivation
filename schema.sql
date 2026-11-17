-- Urban Cultivation: database setup and schema (MySQL 8+ or MariaDB 10.4+)
--
-- Run once as the MySQL root user:
--     mysql -u root -p < schema.sql
-- Before running, change 'change-this-password' below to your own password,
-- and don't commit the changed file.
--
-- The program also creates the tables automatically on first run; they are
-- listed here so the design is easy to read.
--
-- Upgrading from the older version (plain-text Aadhaar/PAN)? Delete the old
-- tables first:
--     DROP TABLE lease, land, farmer, landowner;

CREATE DATABASE IF NOT EXISTS urban_cultivation;

-- A dedicated user that can only touch this one database (not root).
CREATE USER IF NOT EXISTS 'urban_app'@'localhost' IDENTIFIED BY 'change-this-password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, REFERENCES
    ON urban_cultivation.* TO 'urban_app'@'localhost';
FLUSH PRIVILEGES;

USE urban_cultivation;

-- Aadhaar and PAN are never stored. Only a keyed one-way fingerprint
-- (HMAC-SHA256) is kept to block duplicate accounts, plus the last 4 Aadhaar
-- digits for display. Passwords are stored as salted PBKDF2-SHA256 hashes.
CREATE TABLE IF NOT EXISTS farmer (
    farmer_id      INT AUTO_INCREMENT PRIMARY KEY,
    name           VARCHAR(60)  NOT NULL,
    aadhaar_hash   CHAR(64)     NOT NULL UNIQUE,
    aadhaar_last4  CHAR(4)      NOT NULL,
    pan_hash       CHAR(64)     NOT NULL UNIQUE,
    contact        CHAR(10)     NOT NULL,
    password_hash  VARCHAR(160) NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS landowner (
    landowner_id   INT AUTO_INCREMENT PRIMARY KEY,
    name           VARCHAR(60)  NOT NULL,
    aadhaar_hash   CHAR(64)     NOT NULL UNIQUE,
    aadhaar_last4  CHAR(4)      NOT NULL,
    pan_hash       CHAR(64)     NOT NULL UNIQUE,
    contact        CHAR(10)     NOT NULL,
    password_hash  VARCHAR(160) NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Lands that landowners offer for cultivation. Removing a land only hides it
-- (is_listed = FALSE), so the lease history stays intact.
CREATE TABLE IF NOT EXISTS land (
    land_id       INT AUTO_INCREMENT PRIMARY KEY,
    landowner_id  INT          NOT NULL,
    name          VARCHAR(60)  NOT NULL,
    contact       CHAR(10)     NOT NULL,
    location      VARCHAR(100) NOT NULL,
    size_acres    DECIMAL(6, 2) NOT NULL CHECK (size_acres > 0),
    monthly_rent  INT UNSIGNED NOT NULL CHECK (monthly_rent > 0),
    is_listed     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (landowner_id) REFERENCES landowner(landowner_id)
);

-- Every lease request. A land is "available" when it is listed and has no
-- 'approved' lease. Approved leases become 'ended' after end_date.
CREATE TABLE IF NOT EXISTS lease (
    lease_id      INT AUTO_INCREMENT PRIMARY KEY,
    farmer_id     INT NOT NULL,
    land_id       INT NOT NULL,
    months        TINYINT UNSIGNED NOT NULL CHECK (months BETWEEN 1 AND 120),
    monthly_rent  INT UNSIGNED NOT NULL,          -- rent agreed at request time
    status        ENUM('pending', 'approved', 'rejected', 'cancelled', 'ended')
                  NOT NULL DEFAULT 'pending',
    requested_on  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    start_date    DATE NULL,
    end_date      DATE NULL,
    FOREIGN KEY (farmer_id) REFERENCES farmer(farmer_id),
    FOREIGN KEY (land_id)   REFERENCES land(land_id)
);
