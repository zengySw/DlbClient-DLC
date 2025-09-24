const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.static('public')); // Для статических файлов
app.use(express.urlencoded({ extended: true }));

// Настройка multer для загрузки файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage: storage });

// Инициализация базы данных
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err.message);
    } else {
        console.log('Подключение к SQLite базе данных установлено');
        
        // Создание таблицы пользователей
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) {
                console.error('Ошибка создания таблицы users:', err.message);
            } else {
                console.log('Таблица users создана или уже существует');
            }
        });

        // Создание таблицы для файлов
        db.run(`CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`, (err) => {
            if (err) {
                console.error('Ошибка создания таблицы files:', err.message);
            } else {
                console.log('Таблица files создана или уже существует');
            }
        });
    }
});

// Маршрут для главной страницы
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API для регистрации
app.post('/api/register', async (req, res) => {
    const { login, email, password } = req.body;

    // Валидация данных
    if (!login || !email || !password) {
        return res.status(400).json({ message: 'Все поля обязательны для заполнения' });
    }

    if (password.length < 6) {
        return res.status(400).json({ message: 'Пароль должен быть не менее 6 символов' });
    }

    try {
        // Проверка на существование пользователя
        db.get('SELECT * FROM users WHERE login = ? OR email = ?', [login, email], async (err, row) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }

            if (row) {
                if (row.login === login) {
                    return res.status(400).json({ message: 'Пользователь с таким логином уже существует' });
                }
                if (row.email === email) {
                    return res.status(400).json({ message: 'Пользователь с такой почтой уже существует' });
                }
            }

            // Хеширование пароля
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Добавление пользователя в базу
            db.run('INSERT INTO users (login, email, password) VALUES (?, ?, ?)', 
                [login, email, hashedPassword], 
                function(err) {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Ошибка создания пользователя' });
                    }

                    const userId = this.lastID;
                    res.status(201).json({
                        message: 'Пользователь успешно зарегистрирован',
                        user: {
                            id: userId,
                            login: login,
                            email: email
                        }
                    });
                }
            );
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// API для входа
app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(400).json({ message: 'Логин и пароль обязательны' });
    }

    // Поиск пользователя по логину или email
    db.get('SELECT * FROM users WHERE login = ? OR email = ?', [login, login], async (err, row) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Ошибка сервера' });
        }

        if (!row) {
            return res.status(400).json({ message: 'Пользователь не найден' });
        }

        try {
            // Проверка пароля
            const isValidPassword = await bcrypt.compare(password, row.password);
            
            if (!isValidPassword) {
                return res.status(400).json({ message: 'Неверный пароль' });
            }

            res.json({
                message: 'Успешный вход',
                user: {
                    id: row.id,
                    login: row.login,
                    email: row.email
                }
            });
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Ошибка проверки пароля' });
        }
    });
});

// API для загрузки файлов
app.post('/api/upload', upload.single('program'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'Файл не выбран' });
    }

    const userId = req.body.userId; // В реальном приложении лучше использовать JWT токены
    
    if (!userId) {
        return res.status(401).json({ message: 'Пользователь не авторизован' });
    }

    // Сохранение информации о файле в базе данных
    db.run('INSERT INTO files (user_id, filename, original_name, file_path) VALUES (?, ?, ?, ?)',
        [userId, req.file.filename, req.file.originalname, req.file.path],
        function(err) {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Ошибка сохранения файла в базе данных' });
            }

            res.json({
                message: 'Файл успешно загружен',
                file: {
                    id: this.lastID,
                    filename: req.file.filename,
                    originalName: req.file.originalname,
                    size: req.file.size
                }
            });
        }
    );
});

// API для получения файлов пользователя
app.get('/api/files/:userId', (req, res) => {
    const userId = req.params.userId;

    db.all('SELECT * FROM files WHERE user_id = ? ORDER BY upload_date DESC', [userId], (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Ошибка получения файлов' });
        }

        res.json({ files: rows });
    });
});

// API для получения информации о пользователе
app.get('/api/user/:id', (req, res) => {
    const userId = req.params.id;

    db.get('SELECT id, login, email, created_at FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Ошибка получения данных пользователя' });
        }

        if (!row) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }

        res.json({ user: row });
    });
});

// API для получения списка всех пользователей (для администрирования)
app.get('/api/users', (req, res) => {
    db.all('SELECT id, login, email, created_at FROM users ORDER BY id', (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Ошибка получения списка пользователей' });
        }

        res.json({ users: rows });
    });
});

// Обработка ошибок
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Что-то пошло не так!' });
});

// Запуск сервера
app.listen(port, () => {
    console.log(`Сервер запущен на http://localhost:${port}`);
});

// Грациозное закрытие базы данных
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error(err.message);
        } else {
            console.log('Соединение с базой данных закрыто');
        }
        process.exit(0);
    });
});