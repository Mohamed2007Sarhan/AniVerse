-- Database schema for AniVerse project

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS aniverse CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE aniverse;

-- Users table with enhanced security features and profile fields
CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(255) NULL,
    nickname VARCHAR(255) NULL,
    avatar TEXT NULL,
    body_analysis TEXT NULL,
    targets TEXT NULL,
    hobbies TEXT NULL,
    policy_accepted TINYINT(1) NOT NULL DEFAULT 0,
    email_verified_at TIMESTAMP NULL,
    password VARCHAR(255) NOT NULL,
    ip_address VARCHAR(255) NULL,
    remember_token VARCHAR(100) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    login_attempts INT DEFAULT 0,
    last_login_attempt TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    email_verification_token VARCHAR(255) NULL,
    reset_password_token VARCHAR(255) NULL,
    reset_password_expires TIMESTAMP NULL,
    INDEX idx_email (email),
    INDEX idx_nickname (nickname),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User profiles table (for additional user information)
CREATE TABLE IF NOT EXISTS user_profiles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    avatar_url VARCHAR(500) NULL,
    bio TEXT NULL,
    birth_date DATE NULL,
    gender ENUM('male', 'female', 'other', 'prefer_not_to_say') NULL,
    location VARCHAR(255) NULL,
    website VARCHAR(255) NULL,
    social_links JSON NULL,
    preferences JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User sessions table (for session management)
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_session_token (session_token),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Login attempts log (for security monitoring)
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    success BOOLEAN DEFAULT FALSE,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_ip_address (ip_address),
    INDEX idx_attempt_time (attempt_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_token (token),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
