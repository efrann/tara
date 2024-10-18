CREATE DATABASE IF NOT EXISTS auth_db;
USE auth_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE
);

-- Örnek kullanıcılar (gerçek uygulamada şifreleri hash'lemelisiniz)
INSERT INTO users (username, password, is_admin) VALUES 
('admin', 'admin123', TRUE),
('user', 'user123', FALSE);
