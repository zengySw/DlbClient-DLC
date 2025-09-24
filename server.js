const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const port = 3000;

// === Middleware ===
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Настраиваем EJS для шаблонов
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// === Настройка multer для загрузки файлов ===
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage });

// === Инициализация базы данных ===
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err.message);
    } else {
        console.log('Подключение к SQLite базе данных установлено');

        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);
    }
});

// === Маршрут для главной страницы ===
app.get('/', (req, res) => {
    res.render('index'); // ищет views/index.ejs
});

// === API для регистрации ===
app.post('/api/register', async (req, res) => {
    const { login, email, password } = req.body;

    if (!login || !email || !password) {
        return res.status(400).json({ message: 'Все поля обязательны' });
    }

    if (password.length < 6) {
        return res.status(400).json({ message: 'Пароль слишком короткий' });
    }

    db.get('SELECT * FROM users WHERE login = ? OR email = ?', [login, email], async (err, row) => {
        if (err) return res.status(500).json({ message: 'Ошибка сервера' });

        if (row) {
            return res.status(400).json({ 
                message: row.login === login 
                    ? 'Логин уже используется' 
                    : 'Email уже используется' 
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.run('INSERT INTO users (login, email, password) VALUES (?, ?, ?)',
            [login, email, hashedPassword],
            function (err) {
                if (err) return res.status(500).json({ message: 'Ошибка при добавлении пользователя' });

                res.status(201).json({
                    message: 'Регистрация успешна',
                    user: { id: this.lastID, login, email }
                });
            }
        );
    });
});

// === API для входа ===
app.post('/api/login', (req, res) => {
    const { login, password } = req.body;
    if (!login || !password) return res.status(400).json({ message: 'Введите логин и пароль' });

    db.get('SELECT * FROM users WHERE login = ? OR email = ?', [login, login], async (err, row) => {
        if (err) return res.status(500).json({ message: 'Ошибка сервера' });
        if (!row) return res.status(400).json({ message: 'Пользователь не найден' });

        const valid = await bcrypt.compare(password, row.password);
        if (!valid) return res.status(400).json({ message: 'Неверный пароль' });

        res.json({ message: 'Вход успешен', user: { id: row.id, login: row.login, email: row.email } });
    });
});

// === API для загрузки файлов ===
app.post('/api/upload', upload.single('program'), (req, res) => {
    const userId = req.body.userId;
    if (!userId) return res.status(401).json({ message: 'Нет userId' });
    if (!req.file) return res.status(400).json({ message: 'Файл не выбран' });

    db.run('INSERT INTO files (user_id, filename, original_name, file_path) VALUES (?, ?, ?, ?)',
        [userId, req.file.filename, req.file.originalname, req.file.path],
        function (err) {
            if (err) return res.status(500).json({ message: 'Ошибка сохранения файла' });

            res.json({
                message: 'Файл загружен',
                file: { id: this.lastID, filename: req.file.filename, originalName: req.file.originalname }
            });
        });
});

// === API для получения файлов пользователя ===
app.get('/api/files/:userId', (req, res) => {
    db.all('SELECT * FROM files WHERE user_id = ? ORDER BY upload_date DESC', [req.params.userId], (err, rows) => {
        if (err) return res.status(500).json({ message: 'Ошибка сервера' });
        res.json({ files: rows });
    });
});

// === API для информации о пользователе ===
app.get('/api/user/:id', (req, res) => {
    db.get('SELECT id, login, email, created_at FROM users WHERE id = ?', [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ message: 'Ошибка сервера' });
        if (!row) return res.status(404).json({ message: 'Пользователь не найден' });
        res.json({ user: row });
    });
});

// === API для списка пользователей (админ) ===
app.get('/api/users', (req, res) => {
    db.all('SELECT id, login, email, created_at FROM users ORDER BY id', (err, rows) => {
        if (err) return res.status(500).json({ message: 'Ошибка сервера' });
        res.json({ users: rows });
    });
});

// === Ошибки ===
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
});

// === Запуск сервера ===
app.listen(port, () => {
    console.log(`Сервер работает: http://localhost:${port}`);
});

// === Закрытие базы при выходе ===
process.on('SIGINT', () => {
    db.close();
    console.log('SQLite закрыта');
    process.exit(0);
});
