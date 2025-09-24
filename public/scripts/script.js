// public/scripts/script.js - ОБНОВЛЕННАЯ ВЕРСИЯ С JWT

// ========================
// СИСТЕМА БЕЗОПАСНОСТИ (клиентская часть)
// ========================

class SecurityManager {
    static sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        
        return input
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;')
            .replace(/&/g, '&amp;')
            .trim();
    }

    static setTextContent(element, text) {
        if (!element) return;
        const sanitized = this.sanitizeInput(text);
        element.textContent = sanitized;
    }

    static validatePasswordStrength(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);

        const issues = [];
        
        if (password.length < minLength) {
            issues.push(`Минимум ${minLength} символов`);
        }
        if (!hasUpperCase) {
            issues.push('Хотя бы одна заглавная буква');
        }
        if (!hasLowerCase) {
            issues.push('Хотя бы одна строчная буква');
        }
        if (!hasNumbers) {
            issues.push('Хотя бы одна цифра');
        }

        return {
            isValid: issues.length === 0,
            issues: issues
        };
    }

    static checkRateLimit(identifier, maxAttempts = 5, timeWindow = 300000) {
        const attempts = sessionStorage.getItem('rateLimitAttempts');
        const attemptsObj = attempts ? JSON.parse(attempts) : {};
        const now = Date.now();
        
        if (!attemptsObj[identifier]) {
            attemptsObj[identifier] = { count: 1, firstAttempt: now };
            sessionStorage.setItem('rateLimitAttempts', JSON.stringify(attemptsObj));
            return true;
        }

        const timePassed = now - attemptsObj[identifier].firstAttempt;
        
        if (timePassed > timeWindow) {
            attemptsObj[identifier] = { count: 1, firstAttempt: now };
            sessionStorage.setItem('rateLimitAttempts', JSON.stringify(attemptsObj));
            return true;
        }

        if (attemptsObj[identifier].count >= maxAttempts) {
            return false;
        }

        attemptsObj[identifier].count++;
        sessionStorage.setItem('rateLimitAttempts', JSON.stringify(attemptsObj));
        return true;
    }
}

// ========================
// JWT TOKEN MANAGER
// ========================

class TokenManager {
    static getToken() {
        return localStorage.getItem('nursultan_jwt_token');
    }

    static setToken(token) {
        localStorage.setItem('nursultan_jwt_token', token);
    }

    static removeToken() {
        localStorage.removeItem('nursultan_jwt_token');
    }

    static isTokenExpired(token) {
        if (!token) return true;
        
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const currentTime = Date.now() / 1000;
            return payload.exp < currentTime;
        } catch (error) {
            console.error('Ошибка проверки токена:', error);
            return true;
        }
    }

    static getTokenPayload(token) {
        if (!token) return null;
        
        try {
            return JSON.parse(atob(token.split('.')[1]));
        } catch (error) {
            console.error('Ошибка парсинга токена:', error);
            return null;
        }
    }
}

// ========================
// API МЕНЕДЖЕР (обновленный с JWT)
// ========================

class ApiManager {
    static async request(url, options = {}) {
        try {
            const token = TokenManager.getToken();
            
            const defaultOptions = {
                headers: {
                    'Content-Type': 'application/json',
                },
                ...options
            };

            // Добавляем JWT токен в заголовки если он есть
            if (token && !TokenManager.isTokenExpired(token)) {
                defaultOptions.headers['Authorization'] = `Bearer ${token}`;
            }

            const response = await fetch(url, defaultOptions);
            const data = await response.json();

            // Если токен недействителен - очищаем его
            if (response.status === 401 || response.status === 403) {
                TokenManager.removeToken();
                if (nursultanApp && nursultanApp.userManager) {
                    nursultanApp.userManager.handleTokenExpiry();
                }
            }

            if (!response.ok) {
                throw new Error(data.message || 'Ошибка сервера');
            }

            return data;
        } catch (error) {
            throw new Error(error.message || 'Ошибка сети');
        }
    }

    static async register(userData) {
        return this.request('/api/register', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    }

    static async login(credentials) {
        return this.request('/api/login', {
            method: 'POST',
            body: JSON.stringify(credentials)
        });
    }

    static async getUserInfo() {
        return this.request('/api/user/me');
    }

    static async uploadFile(formData) {
        const token = TokenManager.getToken();
        if (!token || TokenManager.isTokenExpired(token)) {
            throw new Error('Требуется авторизация');
        }

        return this.request('/api/upload', {
            method: 'POST',
            body: formData,
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
    }

    static async getUserFiles() {
        return this.request('/api/files');
    }

    static async deleteFile(fileId) {
        return this.request(`/api/files/${fileId}`, {
            method: 'DELETE'
        });
    }

    static async verifyToken() {
        return this.request('/api/verify-token', {
            method: 'POST'
        });
    }
}

// ========================
// СИСТЕМА УПРАВЛЕНИЯ ПОЛЬЗОВАТЕЛЯМИ (обновленная)
// ========================

class UserManager {
    constructor() {
        this.currentUser = null;
        this.tokenCheckInterval = null;
        this.init();
    }

    async init() {
        const token = TokenManager.getToken();
        if (token && !TokenManager.isTokenExpired(token)) {
            try {
                const response = await ApiManager.verifyToken();
                if (response.success) {
                    this.currentUser = response.user;
                    this.showUserDashboard();
                    this.updateAuthButton();
                    this.startTokenCheck();
                }
            } catch (error) {
                console.error('Ошибка проверки токена:', error);
                this.handleTokenExpiry();
            }
        }
    }

    startTokenCheck() {
        // Проверяем токен каждые 5 минут
        this.tokenCheckInterval = setInterval(() => {
            const token = TokenManager.getToken();
            if (!token || TokenManager.isTokenExpired(token)) {
                this.handleTokenExpiry();
            }
        }, 5 * 60 * 1000); // 5 минут
    }

    stopTokenCheck() {
        if (this.tokenCheckInterval) {
            clearInterval(this.tokenCheckInterval);
            this.tokenCheckInterval = null;
        }
    }

    handleTokenExpiry() {
        this.logout();
        if (nursultanApp && nursultanApp.notificationManager) {
            nursultanApp.notificationManager.show('Сессия истекла. Пожалуйста, войдите снова', 'warning');
        }
    }

    isValidEmail(email) {
        if (!email || typeof email !== 'string') return false;
        
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        
        if (email.length > 254) return false;
        
        return emailRegex.test(email);
    }

    isValidLogin(login) {
        if (!login || typeof login !== 'string') return false;
        
        const loginRegex = /^[a-zA-Z0-9_]{3,30}$/;
        return loginRegex.test(login);
    }

    isValidPassword(password) {
        if (!password || typeof password !== 'string') return false;
        return password.length >= 8 && /[a-zA-Z]/.test(password) && /[0-9]/.test(password);
    }

    async register(userData) {
        const { login, email, password } = userData;

        const sanitizedLogin = SecurityManager.sanitizeInput(login);
        const sanitizedEmail = SecurityManager.sanitizeInput(email);

        // Проверка rate limiting
        if (!SecurityManager.checkRateLimit('register_' + sanitizedEmail, 3, 600000)) {
            throw new Error('Слишком много попыток регистрации. Попробуйте позже.');
        }

        // Клиентская валидация
        if (!this.isValidLogin(sanitizedLogin)) {
            throw new Error('Логин должен содержать 3-30 символов (буквы, цифры, подчеркивания)');
        }

        if (!this.isValidEmail(sanitizedEmail)) {
            throw new Error('Введите корректный email адрес');
        }

        if (!this.isValidPassword(password)) {
            throw new Error('Пароль должен содержать минимум 8 символов, включая буквы и цифры');
        }

        const response = await ApiManager.register({
            login: sanitizedLogin,
            email: sanitizedEmail.toLowerCase(),
            password: password
        });

        return response;
    }

    async login(loginOrEmail, password) {
        if (!loginOrEmail || !password) {
            throw new Error('Заполните все поля');
        }

        const sanitizedLoginOrEmail = SecurityManager.sanitizeInput(loginOrEmail);

        // Проверка rate limiting
        if (!SecurityManager.checkRateLimit('login_' + sanitizedLoginOrEmail, 5, 900000)) {
            throw new Error('Слишком много попыток входа. Попробуйте позже.');
        }

        const response = await ApiManager.login({
            login: sanitizedLoginOrEmail,
            password: password
        });

        if (response.success && response.token) {
            // Сохраняем токен
            TokenManager.setToken(response.token);
            this.currentUser = response.user;
            this.startTokenCheck();
            return response.user;
        } else {
            throw new Error('Ошибка авторизации');
        }
    }

    logout() {
        TokenManager.removeToken();
        this.currentUser = null;
        this.stopTokenCheck();
        this.hideUserDashboard();
        this.updateAuthButton();
    }

    showUserDashboard() {
        const dashboard = document.getElementById('user-dashboard');
        const usernameSpan = document.getElementById('username');
        const useridSpan = document.getElementById('userid');
        const useremailSpan = document.getElementById('useremail');

        if (dashboard && this.currentUser) {
            dashboard.classList.remove('hidden');
            
            if (usernameSpan) {
                SecurityManager.setTextContent(usernameSpan, this.currentUser.login);
            }
            if (useridSpan) {
                SecurityManager.setTextContent(useridSpan, this.currentUser.id.toString());
            }
            if (useremailSpan) {
                SecurityManager.setTextContent(useremailSpan, this.currentUser.email);
            }

            this.showFileUpload();
        }
    }

    hideUserDashboard() {
        const dashboard = document.getElementById('user-dashboard');
        if (dashboard) {
            dashboard.classList.add('hidden');
        }
    }

    updateAuthButton() {
        const authButton = document.querySelector('.auth-button');
        if (authButton) {
            if (this.currentUser) {
                const buttonText = `${SecurityManager.sanitizeInput(this.currentUser.login)} ▼`;
                SecurityManager.setTextContent(authButton, buttonText);
                authButton.onclick = () => this.logout();
            } else {
                authButton.textContent = 'Авторизация';
                authButton.onclick = () => openModal('login');
            }
        }
    }

    showFileUpload() {
        const dashboard = document.getElementById('user-dashboard');
        if (!dashboard || !this.currentUser) return;

        // Проверяем, есть ли уже форма
        if (dashboard.querySelector('.file-upload-form')) return;

        const fileUploadHTML = `
            <div class="file-upload-section" style="margin-top: 20px; padding: 20px; background: rgba(0,30,60,0.2); border-radius: 12px; border: 1px solid rgba(0,150,255,0.2);">
                <h3 style="color: #00ccff; margin-bottom: 15px;">Загрузить программу</h3>
                <form class="file-upload-form" enctype="multipart/form-data">
                    <div class="form-group">
                        <input type="file" name="program" accept=".zip,.rar,.7z,.tar,.gz" required style="margin-bottom: 15px;">
                        <small style="color: rgba(255,255,255,0.7); display: block; margin-bottom: 10px;">
                            Разрешенные форматы: ZIP, RAR, 7Z, TAR, GZ (максимум 10MB)
                        </small>
                    </div>
                    <button type="submit" class="btn-primary">Загрузить</button>
                </form>
                <div class="user-files" style="margin-top: 20px;">
                    <h4 style="color: #00ccff;">Ваши файлы:</h4>
                    <div class="files-list"></div>
                </div>
            </div>
        `;

        dashboard.insertAdjacentHTML('beforeend', fileUploadHTML);
        this.initFileUpload();
        this.loadUserFiles();
    }

    initFileUpload() {
        const form = document.querySelector('.file-upload-form');
        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData();
            const fileInput = form.querySelector('input[type="file"]');
            
            if (!fileInput.files[0]) {
                nursultanApp.notificationManager.show('Выберите файл', 'error');
                return;
            }

            const file = fileInput.files[0];
            
            // Проверка размера файла на клиенте
            if (file.size > 10 * 1024 * 1024) {
                nursultanApp.notificationManager.show('Размер файла превышает 10MB', 'error');
                return;
            }

            // Проверка типа файла
            const allowedExtensions = ['.zip', '.rar', '.7z', '.tar', '.gz'];
            const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
            
            if (!allowedExtensions.includes(fileExtension)) {
                nursultanApp.notificationManager.show('Недопустимый тип файла', 'error');
                return;
            }

            formData.append('program', file);

            try {
                const submitButton = form.querySelector('button[type="submit"]');
                submitButton.disabled = true;
                submitButton.textContent = 'Загружается...';

                const response = await ApiManager.uploadFile(formData);
                
                if (response.success) {
                    nursultanApp.notificationManager.show(response.message, 'success');
                    form.reset();
                    this.loadUserFiles();
                }
            } catch (error) {
                nursultanApp.notificationManager.show(error.message, 'error');
            } finally {
                const submitButton = form.querySelector('button[type="submit"]');
                submitButton.disabled = false;
                submitButton.textContent = 'Загрузить';
            }
        });
    }

    async loadUserFiles() {
        if (!this.currentUser) return;

        try {
            const response = await ApiManager.getUserFiles();
            if (response.success) {
                this.displayFiles(response.files);
            }
        } catch (error) {
            console.error('Ошибка загрузки файлов:', error);
        }
    }

    displayFiles(files) {
        const filesList = document.querySelector('.files-list');
        if (!filesList) return;

        if (files.length === 0) {
            filesList.innerHTML = '<p style="color: rgba(255,255,255,0.7);">Файлы не найдены</p>';
            return;
        }

        const filesHTML = files.map(file => {
            const uploadDate = new Date(file.upload_date).toLocaleString('ru-RU');
            const fileSize = (file.file_size / 1024 / 1024).toFixed(2);
            
            return `
                <div class="file-item" style="padding: 10px; margin: 5px 0; background: rgba(0,20,40,0.3); border-radius: 8px; border: 1px solid rgba(0,150,255,0.1); display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-weight: 600; color: #00ccff;">${SecurityManager.sanitizeInput(file.original_name)}</div>
                        <div style="font-size: 12px; color: rgba(255,255,255,0.7);">
                            Размер: ${fileSize} MB | Загружен: ${uploadDate}
                        </div>
                    </div>
                    <button class="delete-file-btn" data-file-id="${file.id}" style="background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px;">
                        Удалить
                    </button>
                </div>
            `;
        }).join('');

        filesList.innerHTML = filesHTML;

        // Добавляем обработчики для кнопок удаления
        filesList.querySelectorAll('.delete-file-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const fileId = e.target.getAttribute('data-file-id');
                if (confirm('Вы уверены, что хотите удалить этот файл?')) {
                    try {
                        await ApiManager.deleteFile(fileId);
                        nursultanApp.notificationManager.show('Файл удален', 'success');
                        this.loadUserFiles();
                    } catch (error) {
                        nursultanApp.notificationManager.show(error.message, 'error');
                    }
                }
            });
        });
    }
}

// ========================
// СИСТЕМА УВЕДОМЛЕНИЙ
// ========================

class NotificationManager {
    constructor() {
        this.createNotificationContainer();
    }

    createNotificationContainer() {
        if (!document.getElementById('notification-container')) {
            const container = document.createElement('div');
            container.id = 'notification-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 9999;
                pointer-events: none;
            `;
            document.body.appendChild(container);
        }
    }

    show(message, type = 'info', duration = 5000) {
        const sanitizedMessage = SecurityManager.sanitizeInput(message);
        
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            background: ${this.getBackgroundColor(type)};
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            border-left: 4px solid ${this.getBorderColor(type)};
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
            pointer-events: auto;
            cursor: pointer;
            max-width: 350px;
            word-wrap: break-word;
        `;
        
        SecurityManager.setTextContent(notification, sanitizedMessage);

        const container = document.getElementById('notification-container');
        container.appendChild(notification);

        setTimeout(() => {
            notification.style.opacity = '1';
            notification.style.transform = 'translateX(0)';
        }, 10);

        setTimeout(() => {
            this.hide(notification);
        }, duration);

        notification.addEventListener('click', () => {
            this.hide(notification);
        });
    }

    hide(notification) {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }

    getBackgroundColor(type) {
        const colors = {
            success: 'linear-gradient(135deg, #28a745, #20c997)',
            error: 'linear-gradient(135deg, #dc3545, #e74c3c)',
            warning: 'linear-gradient(135deg, #ffc107, #f39c12)',
            info: 'linear-gradient(135deg, #007bff, #0066cc)'
        };
        return colors[type] || colors.info;
    }

    getBorderColor(type) {
        const colors = {
            success: '#20c997',
            error: '#e74c3c',
            warning: '#f39c12',
            info: '#0066cc'
        };
        return colors[type] || colors.info;
    }
}

// ========================
// СИСТЕМА МОДАЛЬНЫХ ОКОН
// ========================

class ModalManager {
    constructor() {
        this.activeModal = null;
        this.initEventListeners();
    }

    initEventListeners() {
        window.addEventListener('click', (event) => {
            if (event.target.classList.contains('modal')) {
                this.closeModal();
            }
        });

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.activeModal) {
                this.closeModal();
            }
        });

        // Добавляем обработчики для кнопок закрытия
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('close')) {
                this.closeModal();
            }
        });
    }

    openModal(type) {
        const modal = document.getElementById(type + 'Modal');
        if (modal) {
            modal.style.display = 'flex';
            this.activeModal = type;
            const firstInput = modal.querySelector('input');
            if (firstInput) {
                setTimeout(() => firstInput.focus(), 100);
            }
        }
    }

    closeModal(type = null) {
        if (type) {
            const modal = document.getElementById(type + 'Modal');
            if (modal) {
                modal.style.display = 'none';
            }
        } else if (this.activeModal) {
            const modal = document.getElementById(this.activeModal + 'Modal');
            if (modal) {
                modal.style.display = 'none';
            }
        }
        this.activeModal = null;
    }
}

// ========================
// СИСТЕМА ЧАСТИЦ
// ========================

class ParticleSystem {
    constructor() {
        this.container = document.querySelector('.particles');
        this.particles = [];
        this.createParticles();
    }

    createParticles() {
        if (!this.container) return;

        const particleCount = window.innerWidth < 768 ? 50 : 100;

        for (let i = 0; i < particleCount; i++) {
            const particle = document.createElement('div');
            particle.classList.add('particle');
            
            const size = Math.random() * 2 + 1;
            particle.style.cssText = `
                top: ${Math.random() * 100}%;
                left: ${Math.random() * 100}%;
                width: ${size}px;
                height: ${size}px;
                animation-duration: ${Math.random() * 5 + 3}s;
                animation-delay: ${Math.random() * 2}s;
                opacity: ${Math.random() * 0.8 + 0.2};
            `;
            
            this.container.appendChild(particle);
            this.particles.push(particle);
        }
    }

    destroy() {
        this.particles.forEach(particle => {
            if (particle.parentNode) {
                particle.parentNode.removeChild(particle);
            }
        });
        this.particles = [];
    }

    regenerate() {
        this.destroy();
        this.createParticles();
    }
}

// ========================
// ГЛАВНОЕ ПРИЛОЖЕНИЕ
// ========================

class NursultanApp {
    constructor() {
        this.userManager = new UserManager();
        this.modalManager = new ModalManager();
        this.notificationManager = new NotificationManager();
        this.particleSystem = new ParticleSystem();
        
        this.initEventListeners();
        this.initForms();
    }

    initEventListeners() {
        window.addEventListener('resize', () => {
            this.particleSystem.regenerate();
        });

        document.addEventListener('click', (e) => {
            if (e.target.matches('[onclick*="scrollToSection"]')) {
                e.preventDefault();
                const sectionId = e.target.getAttribute('onclick').match(/'([^']+)'/)[1];
                this.scrollToSection(sectionId);
            }
        });
    }

    initForms() {
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin(e.target);
            });
        }

        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleRegister(e.target);
            });
        }

        this.addRealTimeValidation();
    }

    addRealTimeValidation() {
        const emailInputs = document.querySelectorAll('input[type="email"]');
        emailInputs.forEach(input => {
            input.addEventListener('input', () => {
                const isValid = this.userManager.isValidEmail(input.value);
                this.toggleInputValidation(input, isValid);
            });
        });

        const loginInputs = document.querySelectorAll('input[name="login"]');
        loginInputs.forEach(input => {
            input.addEventListener('input', () => {
                const isValid = this.userManager.isValidLogin(input.value);
                this.toggleInputValidation(input, isValid);
            });
        });

        const passwordInputs = document.querySelectorAll('input[type="password"]');
        passwordInputs.forEach(input => {
            input.addEventListener('input', () => {
                const isValid = this.userManager.isValidPassword(input.value);
                this.toggleInputValidation(input, isValid);
            });
        });
    }

    toggleInputValidation(input, isValid) {
        if (input.value.length === 0) {
            input.style.borderColor = 'rgba(0, 150, 255, 0.3)';
            return;
        }

        if (isValid) {
            input.style.borderColor = '#28a745';
        } else {
            input.style.borderColor = '#dc3545';
        }
    }

    async handleLogin(form) {
        try {
            const formData = new FormData(form);
            const loginOrEmail = formData.get('loginOrEmail');
            const password = formData.get('password');

            if (!loginOrEmail || !password) {
                this.notificationManager.show('Заполните все поля', 'error');
                return;
            }

            const user = await this.userManager.login(loginOrEmail, password);
            
            this.notificationManager.show(`Добро пожаловать, ${user.login}!`, 'success');
            this.modalManager.closeModal('login');
            this.userManager.showUserDashboard();
            this.userManager.updateAuthButton();
            form.reset();
        } catch (error) {
            this.notificationManager.show(error.message, 'error');
        }
    }

    async handleRegister(form) {
        try {
            const formData = new FormData(form);
            const login = formData.get('login');
            const email = formData.get('email');
            const password = formData.get('password');

            if (!login || !email || !password) {
                this.notificationManager.show('Заполните все поля', 'error');
                return;
            }

            const response = await this.userManager.register({ login, email, password });
            
            if (response.success) {
                this.notificationManager.show('Регистрация успешна! Теперь можете войти в систему.', 'success');
                this.modalManager.closeModal('register');
                form.reset();
                
                setTimeout(() => {
                    this.modalManager.openModal('login');
                }, 1000);
            }
        } catch (error) {
            this.notificationManager.show(error.message, 'error');
        }
    }

    scrollToSection(sectionId) {
        const element = document.getElementById(sectionId);
        if (element) {
            element.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    }
}

// ========================
// ГЛОБАЛЬНЫЕ ФУНКЦИИ
// ========================

let nursultanApp;

function openModal(type) {
    if (nursultanApp) {
        nursultanApp.modalManager.openModal(type);
    }
}

function closeModal(type) {
    if (nursultanApp) {
        nursultanApp.modalManager.closeModal(type);
    }
}

function logout() {
    if (nursultanApp) {
        nursultanApp.userManager.logout();
        nursultanApp.notificationManager.show('Вы вышли из системы', 'info');
    }
}

function scrollToSection(id) {
    if (nursultanApp) {
        nursultanApp.scrollToSection(id);
    }
}

// ========================
// ИНИЦИАЛИЗАЦИЯ
// ========================

document.addEventListener('DOMContentLoaded', () => {
    nursultanApp = new NursultanApp();
    console.log('NURSULTAN App загружен с безопасной JWT аутентификацией!');
});