require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ←←←←← ВАЖНЫЕ МИДЛВАРЫ
app.use(cors());
app.use(express.json());                    // без этого регистрация НЕ РАБОТАЕТ
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));  // ← папка public

// MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB подключён'))
  .catch(err => console.log('MongoDB ошибка:', err));

// Модель юзера
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  subscription: { type: String, default: 'free' },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Регистрация
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    console.log('Регистрация:', req.body); // ← смотри в консоль сервера

    if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });
    if (!username && !req.body.username) username = email.split('@')[0]; // автогенерим если не передан

    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists) return res.status(400).json({ error: 'Email или юзернейм уже занят' });

    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ username: username || email.split('@')[0], email, password: hashed });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, message: 'Аккаунт создан!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Логин
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { username: user.username, subscription: user.subscription } });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Проверка токена
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Токен недействителен' });
    req.userId = decoded.userId;
    next();
  });
};

app.get('/api/user', auth, async (req, res) => {
  const user = await User.findById(req.userId).select('-password');
  res.json({ user });
});

app.post('/api/payment', auth, async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{ price_data: { currency: 'rub', product_data: { name: 'BananSense — 1 месяц' }, unit_amount: 149000 }, quantity: 1 }],
    mode: 'payment',
    success_url: `${req.headers.origin}/success.html`,
    cancel_url: `${req.headers.origin}/`,
    metadata: { userId: req.userId.toString() }
  });
  res.json({ id: session.id });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Сервер запущен → http://localhost:${PORT}`));