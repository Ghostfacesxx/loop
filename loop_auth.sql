-- Criação do banco de dados
CREATE DATABASE IF NOT EXISTS loop_auth;
USE loop_auth;

-- Tabela de usuários
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(100) UNIQUE NOT NULL,
  username VARCHAR(100) NOT NULL,
  password VARCHAR(255) NOT NULL,
  is_admin BOOLEAN DEFAULT FALSE
);

-- Usuário Admin (senha: Syntax@123)
INSERT INTO users (email, username, password, is_admin)
VALUES (
  'syntaxsouls@admin.duo',
  'Admin',
  '$2b$10$K3OMaX4FTv1MVl0qSq5cNeiJ08jRbjWv2BjZ2IHOw8ynv4f6A.q1O',
  true
);

-- Tabela de conteúdo
CREATE TABLE IF NOT EXISTS conteudo (
  id INT AUTO_INCREMENT PRIMARY KEY,
  capa TEXT NOT NULL,
  nome VARCHAR(255) NOT NULL,
  data_lancamento VARCHAR(20),
  duracao VARCHAR(20),
  tipo ENUM('filme', 'serie') NOT NULL,
);

ALTER TABLE conteudo ADD COLUMN description VARCHAR(1000) NOT NULL;



