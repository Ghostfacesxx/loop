const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

// Conexão com MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // Coloque sua senha do MySQL aqui, se houver
  database: 'loop_auth'
});

db.connect(err => {
  if (err) throw err;
  console.log('Conectado ao MySQL!');
});

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'chave-secreta',
  resave: false,
  saveUninitialized: false
}));

// Função de validação de senha forte
function senhaEhForte(senha) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%!&*])[A-Za-z\d@#$%!&*]{8,}$/;
  return regex.test(senha);
}

// Rota de cadastro
app.post('/cadastro', async (req, res) => {
  const { email, username, password } = req.body;

  if (!senhaEhForte(password)) {
    return res.json({
      success: false,
      message: 'A senha deve conter no mínimo 8 caracteres, uma letra maiúscula, minúscula, número e símbolo.'
    });
  }

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.json({ success: false, message: 'Erro ao verificar e-mail.' });

    if (results.length > 0) {
      return res.json({ success: false, message: 'E-mail já cadastrado.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.query('INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
      [email, username, hashedPassword],
      (err) => {
        if (err) return res.json({ success: false, message: 'Erro ao cadastrar.' });

        req.session.username = username;
        req.session.isAdmin = false;
        res.json({ success: true });
      });
  });
});

// Rota de login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ? OR email = ?', [username, username], async (err, results) => {
    if (err || results.length === 0) {
      return res.json({ success: false, message: 'Usuário ou e-mail não encontrado.' });
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.json({ success: false, message: 'Senha incorreta.' });
    }

    req.session.username = user.username;
    req.session.isAdmin = !!user.is_admin;

    res.json({
      success: true,
      redirect: user.is_admin ? '/admin.html' : '/index.html'
    });
  });
});

// Sessão
app.get('/session-info', (req, res) => {
  res.json({
    loggedIn: !!req.session.username,
    username: req.session.username,
    isAdmin: req.session.isAdmin
  });
});

// Adicionar conteúdo
app.post('/add-conteudo', (req, res) => {
  const { cover, title, release, duration, type, description } = req.body;
  const nomeCompleto = `${title} (${release})`;

  db.query('INSERT INTO conteudo (capa, nome, data_lancamento, duracao, tipo, description) VALUES (?, ?, ?, ?, ?, ?)',
    [cover, nomeCompleto, release, duration, type, description],
    (err) => {
      if (err) {
        console.error(err);
        return res.json({ success: false, message: 'Erro ao adicionar conteúdo.' });
      }
      res.json({ success: true });
    });
});

// Editar conteúdo
app.post('/edit-conteudo/:id', (req, res) => {
  const id = req.params.id;
  const { cover, title, release, duration, type, description } = req.body;
  console.log(req.body)
  const nomeCompleto = `${title} (${release})`;

  db.query('UPDATE conteudo SET capa = ?, nome = ?, data_lancamento = ?, duracao = ?, tipo = ?, description = ? WHERE id = ?',
    [cover, nomeCompleto, release, duration, type, description, id],
    (err) => {
      if (err) {
        console.error(err);
        return res.json({ success: false, message: 'Erro ao editar conteúdo.' });
      }
      res.json({ success: true });
    });
});

// Obter conteúdo por ID
app.get('/conteudo/:id', (req, res) => {
  const id = req.params.id;
  db.query('SELECT * FROM conteudo WHERE id = ?', [id], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: 'Conteúdo não encontrado.' });
    }
    res.json(results[0]);
  });
});

// Listar conteúdo
app.get('/conteudo', (req, res) => {
  db.query('SELECT * FROM conteudo', (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao buscar conteúdo.' });
    }
    res.json(results);
  });
});

// Deletar conteúdo
app.delete('/delete-conteudo/:id', (req, res) => {
  const id = req.params.id;
  db.query('DELETE FROM conteudo WHERE id = ?', [id], (err) => {
    if (err) {
      console.error(err);
      return res.json({ success: false, message: 'Erro ao apagar conteúdo.' });
    }
    res.json({ success: true });
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
