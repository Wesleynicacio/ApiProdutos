const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const express = require('express');

const saltRounds = 10;
const secretKey = 'seu-segredo-aqui';

const app = express();
app.use(express.json());

// Função auxiliar para ler o arquivo JSON
function getUsers() {
  try {
    const data = fs.readFileSync('users.json');
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
}

// Função auxiliar para salvar os usuários no arquivo JSON
function saveUsers(users) {
  fs.writeFileSync('users.json', JSON.stringify(users));
}

// Rota para registrar um novo usuário
app.post('/register', (req, res) => {
  try {
    const { username, password } = req.body;
    const users = getUsers();

    // Verifica se o usuário já existe
    if (users.find(user => user.username === username)) {
      throw new Error('Usuário já registrado');
    }

    // Criptografa a senha
    bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
      if (err) {
        throw new Error('Erro ao criptografar a senha');
      }

      // Adiciona o novo usuário à lista
      users.push({ username, password: hashedPassword });

      // Salva os usuários atualizados no arquivo JSON
      saveUsers(users);

      res.status(200).json({ message: 'Usuário registrado com sucesso' });
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Rota para autenticar o usuário e gerar um token JWT
app.post('/login', (req, res) => {
  try {
    const { username, password } = req.body;
    const users = getUsers();

    // Encontra o usuário pelo nome de usuário
    const user = users.find(user => user.username === username);

    // Verifica se o usuário existe e a senha está correta
    if (!user) {
      throw new Error('Credenciais inválidas');
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        throw new Error('Credenciais inválidas');
      }

      // Gera um token JWT válido por 24 horas
      const token = jwt.sign({ username }, secretKey, { expiresIn: '24h' });

      res.status(200).json({ token });
    });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// Rota para obter detalhes do usuário
app.get('/user', (req, res) => {
  try {
    const { token } = req.headers;

    // Verifica a autenticidade do token
    jwt.verify(token, secretKey, (err, decodedToken) => {
      if (err) {
        throw new Error('Token inválido');
      }

      const users = getUsers();

      // Encontra o usuário pelo nome de usuário
      const user = users.find(user => user.username === decodedToken.username);

      if (!user) {
        throw new Error('Usuário não encontrado');
      }

      res.status(200).json({ username: user.username });
    });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// Função auxiliar para ler o arquivo JSON
function getProducts() {
  try {
    const data = fs.readFileSync('products.json');
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
}

// Função auxiliar para salvar os produtos no arquivo JSON
function saveProducts(products) {
  fs.writeFileSync('products.json', JSON.stringify(products));
}

// Rota para criar um novo produto
app.post('/products', (req, res) => {
  try {
    const { token, name, price } = req.body;

    // Verifica a autenticidade do token
    jwt.verify(token, secretKey, (err, decodedToken) => {
      if (err) {
        throw new Error('Token inválido');
      }

      const products = getProducts();

      // Verifica se o produto já existe
      if (products.find(product => product.name === name)) {
        throw new Error('Produto já existe');
      }

      // Adiciona o novo produto à lista
      products.push({ name, price });

      // Salva os produtos atualizados no arquivo JSON
      saveProducts(products);

      res.status(200).json({ message: 'Produto criado com sucesso' });
    });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// Rota para atualizar um produto existente
app.put('/products/:name', (req, res) => {
  try {
    const { token } = req.headers;
    const { name } = req.params;
    const { price } = req.body;

    // Verifica a autenticidade do token
    jwt.verify(token, secretKey, (err, decodedToken) => {
      if (err) {
        throw new Error('Token inválido');
      }

      const products = getProducts();

      // Encontra o produto pelo nome
      const product = products.find(product => product.name === name);

      // Verifica se o produto existe
      if (!product) {
        throw new Error('Produto não encontrado');
      }

      // Atualiza o preço do produto
      product.price = price;

      // Salva os produtos atualizados no arquivo JSON
      saveProducts(products);

      res.status(200).json({ message: 'Produto atualizado com sucesso' });
    });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// Rota para excluir um produto
app.delete('/products/:name', (req, res) => {
  try {
    const { token } = req.headers;
    const { name } = req.params;

    // Verifica a autenticidade do token
    jwt.verify(token, secretKey, (err, decodedToken) => {
      if (err) {
        throw new Error('Token inválido');
      }

      const products = getProducts();

      // Encontra o produto pelo nome
      const index = products.findIndex(product => product.name === name);

      // Verifica se o produto existe
      if (index === -1) {
        throw new Error('Produto não encontrado');
      }

      // Remove o produto da lista
      products.splice(index, 1);

      // Salva os produtos atualizados no arquivo JSON
      saveProducts(products);

      res.status(200).json({ message: 'Produto excluído com sucesso' });
    });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// Rota para obter a lista de produtos
app.get('/products', (req, res) => {
  try {
    const products = getProducts();
    res.status(200).json(products);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao obter a lista de produtos' });
  }
});

app.listen(3000, () => {
  console.log('Servidor rodando em http://localhost:3000');
});