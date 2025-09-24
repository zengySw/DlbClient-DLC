// server.js - БЕЗОПАСНАЯ ВЕРСИЯ
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const validator = require('validator');

const app = express();
const port = process.env.PORT || 3000;

// JWT Secret (в продакшене должен быть в переменных окружения)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = '24h';

// === БЕЗОПАСНОСТЬ ===
app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
        },
    },
}));

// Отключаем X-Powered-By заголовок
app.disable('x-powered-by');

// === Rate Limiting ===
const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 5, // максимум 5 запросов для auth endpoints
    message: { success: false, message: 'Слишком много попыток. Попробуйте через 15 минут' },
    standardHeaders: true,
    legacyHeaders: false,
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Слишком много запросов' }
});

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 час
    max: 10, // максимум 10 загрузок в час
    message: { success: false, message: 'Слишком много загрузок файлов. Попробуйте через час' }
});

// === Middleware ===
app.use(generalLimiter);
app.use(express.json({ limit: '1mb' })); // Ограничиваем размер JSON
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// === Функции безопасности ===
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    return validator.escape(input.trim());
}

function validateEmail(email) {
    return validator.isEmail(email) && email.length <= 254;
}

function validateLogin(login) {
    return validator.isAlphanumeric(login, 'en-US', {ignore: '_'}) && 
           login.length >= 3 && login.length <= 30;
}

function validatePassword(password) {
    // Минимум 8 символов, хотя бы одна буква и одна цифра
    return password && 
           password.length >= 8 && 
           /[a-zA-Z]/.test(password) && 
           /[0-9]/.test(password);
}

// Middleware для проверки JWT токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ success: false, message: 'Токен доступа отсутствует' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Недействительный токен' });
        }
        req.user = user;
        next();
    });
}

// === Настройка multer для безопасной загрузки файлов ===
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Генерируем безопасное имя файла
        const ext = path.extname(file.originalname).toLowerCase();
        const safeName = crypto.randomUUID() + ext;
        cb(null, safeName);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB максимум
        files: 1
    },
    fileFilter: (req, file, cb) => {
        // УБИРАЕМ .exe - только безопасные форматы!
        const allowedTypes = /\.(zip|rar|7z|tar|gz)$/i;
        const allowedMimes = [
            'application/zip',
            'application/x-rar-compressed',
            'application/x-7z-compressed',
            'application/x-tar',
            'application/gzip'
        ];
        
        if (allowedTypes.test(file.originalname) && allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Недопустимый тип файла. Разрешены: ZIP, RAR, 7Z, TAR, GZ'), false);
        }
    }
});

// === Инициализация базы данных ===
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err.message);
        process.exit(1);
    } else {
        console.log('Подключение к SQLite базе данных установлено');
        
        // Включаем внешние ключи
        db.run('PRAGMA foreign_keys = ON');
        
        // Создание таблиц
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE NOT NULL COLLATE NOCASE,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                failed_login_attempts INTEGER DEFAULT 0,
                account_locked_until DATETIME
            )`);

            db.run(`CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                original_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                mime_type TEXT,
                upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )`);

            // Создание индексов
            db.run(`CREATE INDEX IF NOT EXISTS idx_users_login ON users(login)`);
            db.run(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
            db.run(`CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id)`);
        });
    }
});

// === Маршруты ===
app.get('/', (req, res) => {
    res.render('index');
});

// === API для регистрации ===
app.post('/api/register', strictLimiter, async (req, res) => {
    try {
        let { login, email, password } = req.body;

        // Валидация входных данных
        if (!login || !email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Все поля обязательны' 
            });
        }

        // Санитизация
        login = sanitizeInput(login);
        email = sanitizeInput(email.toLowerCase());

        // Проверка корректности данных
        if (!validateLogin(login)) {
            return res.status(400).json({ 
                success: false,
                message: 'Логин должен содержать 3-30 символов (буквы, цифры, подчеркивания)' 
            });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ 
                success: false,
                message: 'Введите корректный email адрес' 
            });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ 
                success: false,
                message: 'Пароль должен содержать минимум 8 символов, включая буквы и цифры' 
            });
        }

        // Проверка уникальности
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT id FROM users WHERE login = ? OR email = ?', 
                [login, email], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
        });

        if (existingUser) {
            return res.status(400).json({ 
                success: false,
                message: 'Пользователь с таким логином или email уже существует'
            });
        }

        // Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, 12);

        // Создание пользователя
        const result = await new Promise((resolve, reject) => {
            db.run('INSERT INTO users (login, email, password) VALUES (?, ?, ?)',
                [login, email, hashedPassword],
                function (err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID });
                }
            );
        });

        console.log(`Новый пользователь зарегистрирован: ${login} (ID: ${result.id})`);
        
        res.status(201).json({
            success: true,
            message: 'Регистрация успешна',
            user: { 
                id: result.id, 
                login, 
                email
            }
        });

    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка сервера' 
        });
    }
});

// === API для входа ===
app.post('/api/login', strictLimiter, async (req, res) => {
    try {
        let { login, password } = req.body;
        
        if (!login || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Введите логин/email и пароль' 
            });
        }

        login = sanitizeInput(login.toLowerCase());

        // Поиск пользователя
        const user = await new Promise((resolve, reject) => {
            db.get(`SELECT id, login, email, password, failed_login_attempts, account_locked_until 
                    FROM users WHERE LOWER(login) = ? OR LOWER(email) = ?`, 
                [login, login], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
        });

        if (!user) {
            return res.status(400).json({ 
                success: false, 
                message: 'Неверный логин/email или пароль' 
            });
        }

        // Проверка блокировки аккаунта
        if (user.account_locked_until && new Date() < new Date(user.account_locked_until)) {
            return res.status(429).json({ 
                success: false, 
                message: 'Аккаунт временно заблокирован из-за множественных неудачных попыток входа' 
            });
        }

        // Проверка пароля
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            // Увеличиваем счетчик неудачных попыток
            const failedAttempts = (user.failed_login_attempts || 0) + 1;
            let lockUntil = null;
            
            if (failedAttempts >= 5) {
                lockUntil = new Date(Date.now() + 15 * 60 * 1000); // Блокировка на 15 минут
            }

            await new Promise((resolve) => {
                db.run(`UPDATE users SET failed_login_attempts = ?, account_locked_until = ? 
                        WHERE id = ?`,
                    [failedAttempts, lockUntil, user.id], resolve);
            });

            return res.status(400).json({ 
                success: false, 
                message: 'Неверный логин/email или пароль' 
            });
        }

        // Успешный вход - сбрасываем счетчики и обновляем время входа
        await new Promise((resolve) => {
            db.run(`UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, 
                    last_login = CURRENT_TIMESTAMP WHERE id = ?`,
                [user.id], resolve);
        });

        // Создание JWT токена
        const token = jwt.sign(
            { 
                userId: user.id, 
                login: user.login, 
                email: user.email 
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        console.log(`Пользователь ${user.login} (ID: ${user.id}) вошел в систему`);

        res.json({ 
            success: true,
            message: 'Вход успешен',
            token: token,
            user: { 
                id: user.id, 
                login: user.login, 
                email: user.email
            } 
        });

    } catch (error) {
        console.error('Ошибка авторизации:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка сервера' 
        });
    }
});

// === API для загрузки файлов (требует аутентификации) ===
app.post('/api/upload', uploadLimiter, authenticateToken, (req, res) => {
    upload.single('program')(req, res, async (err) => {
        if (err) {
            console.error('Ошибка загрузки файла:', err);
            return res.status(400).json({ 
                success: false, 
                message: err.message 
            });
        }

        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                message: 'Файл не выбран' 
            });
        }

        try {
            // Используем userId из JWT токена, а не из тела запроса!
            const userId = req.user.userId;

            // Дополнительная проверка размера файла
            if (req.file.size > 10 * 1024 * 1024) {
                fs.unlink(req.file.path, () => {}); // Удаляем файл
                return res.status(400).json({ 
                    success: false, 
                    message: 'Размер файла превышает 10MB' 
                });
            }

            // Сохранение в базу данных
            const result = await new Promise((resolve, reject) => {
                db.run(`INSERT INTO files (user_id, filename, original_name, file_path, file_size, mime_type) 
                        VALUES (?, ?, ?, ?, ?, ?)`,
                    [userId, req.file.filename, req.file.originalname, req.file.path, 
                     req.file.size, req.file.mimetype],
                    function (err) {
                        if (err) reject(err);
                        else resolve({ id: this.lastID });
                    }
                );
            });

            console.log(`Файл загружен пользователем ${userId}: ${req.file.originalname} (${req.file.size} bytes)`);

            res.json({
                success: true,
                message: 'Файл успешно загружен',
                file: { 
                    id: result.id, 
                    filename: req.file.filename, 
                    originalName: req.file.originalname,
                    size: req.file.size,
                    uploadDate: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('Ошибка сохранения файла:', error);
            // Удаляем загруженный файл при ошибке
            fs.unlink(req.file.path, () => {});
            res.status(500).json({ 
                success: false, 
                message: 'Ошибка сохранения файла' 
            });
        }
    });
});

// === API для получения файлов пользователя (требует аутентификации) ===
app.get('/api/files', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        const files = await new Promise((resolve, reject) => {
            db.all(`SELECT id, filename, original_name, file_size, upload_date 
                    FROM files 
                    WHERE user_id = ? 
                    ORDER BY upload_date DESC`, 
                [userId], (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows || []);
                });
        });
        
        res.json({ 
            success: true, 
            files: files 
        });

    } catch (error) {
        console.error('Ошибка получения файлов:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка сервера' 
        });
    }
});

// === API для получения информации о текущем пользователе ===
app.get('/api/user/me', authenticateToken, (req, res) => {
    res.json({ 
        success: true, 
        user: {
            id: req.user.userId,
            login: req.user.login,
            email: req.user.email
        }
    });
});

// === API для удаления файла ===
app.delete('/api/files/:fileId', authenticateToken, async (req, res) => {
    try {
        const fileId = parseInt(req.params.fileId);
        const userId = req.user.userId;

        if (!fileId) {
            return res.status(400).json({ 
                success: false, 
                message: 'Некорректный ID файла' 
            });
        }

        // Получаем информацию о файле
        const file = await new Promise((resolve, reject) => {
            db.get('SELECT file_path FROM files WHERE id = ? AND user_id = ?', 
                [fileId, userId], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
        });

        if (!file) {
            return res.status(404).json({ 
                success: false, 
                message: 'Файл не найден' 
            });
        }

        // Удаляем из базы данных
        await new Promise((resolve, reject) => {
            db.run('DELETE FROM files WHERE id = ? AND user_id = ?', 
                [fileId, userId], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
        });

        // Удаляем физический файл
        fs.unlink(file.file_path, (err) => {
            if (err) console.error('Ошибка удаления физического файла:', err);
        });

        res.json({ 
            success: true, 
            message: 'Файл удален' 
        });

    } catch (error) {
        console.error('Ошибка удаления файла:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка сервера' 
        });
    }
});

// === Проверка токена ===
app.post('/api/verify-token', authenticateToken, (req, res) => {
    res.json({ 
        success: true, 
        message: 'Токен действителен',
        user: {
            id: req.user.userId,
            login: req.user.login,
            email: req.user.email
        }
    });
});

// === Обработка ошибок ===
app.use((err, req, res, next) => {
    console.error('Необработанная ошибка:', err);
    res.status(500).json({ 
        success: false, 
        message: 'Внутренняя ошибка сервера' 
    });
});

// === 404 handler ===
app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        message: 'Эндпоинт не найден' 
    });
});

// === Запуск сервера ===
app.listen(port, () => {
    console.log(`Безопасный сервер NURSULTAN работает на порту ${port}`);
    console.log(`Открыть в браузере: http://localhost:${port}`);
    
    if (!process.env.JWT_SECRET) {
        console.warn('⚠️  ВНИМАНИЕ: JWT_SECRET не установлен в переменных окружения!');
    }
});

// === Graceful shutdown ===
const shutdown = () => {
    console.log('\nЗакрытие сервера...');
    db.close((err) => {
        if (err) {
            console.error('Ошибка закрытия БД:', err);
        } else {
            console.log('База данных закрыта');
        }
        process.exit(0);
    });
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);