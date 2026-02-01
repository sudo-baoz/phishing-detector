-- MySQL Database Schema for Phishing URL Detection API
-- Database: phishing_detector

-- Drop tables if they exist (for clean setup)
DROP TABLE IF EXISTS scan_history;
DROP TABLE IF EXISTS users;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Scan history table
CREATE TABLE scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url TEXT NOT NULL,
    is_phishing BOOLEAN NOT NULL,
    confidence_score DECIMAL(5, 2) NOT NULL COMMENT 'Confidence score between 0.00 and 100.00',
    threat_type VARCHAR(50) DEFAULT NULL COMMENT 'Type of threat: phishing, malware, suspicious, etc.',
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INT DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_scanned_at (scanned_at),
    INDEX idx_user_id (user_id),
    INDEX idx_is_phishing (is_phishing)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert sample data (optional)
-- INSERT INTO users (username, password_hash) VALUES 
--     ('admin', '$2b$12$example_hash_here'),
--     ('testuser', '$2b$12$example_hash_here');
