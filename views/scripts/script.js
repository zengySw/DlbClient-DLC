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

    static validateForSQL(input) {
        if (typeof input !== 'string') return false;
        
        const sqlInjectionPatterns = [
            /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/i,
            /(-{2}|\/\*|\*\/)/i,
            /(;|\||&)/g,
            /(script|javascript|vbscript|onload|onerror|onclick)/i
        ];

        return !sqlInjectionPatterns.some(pattern => pattern.test(input));
    }

    static setTextContent(element, text) {
        if (!element) return;
        const sanitized = this.sanitizeInput(text);
        element.textContent = sanitized;
    }

    static validatePasswordStrength(password) {
        const minLength = 6; // Соответствует серверу
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
        const attempts = window.rateLimitAttempts || {};
        const now = Date.now();
        
        if (!attempts[identifier]) {
            attempts[identifier] = { count: 1, firstAttempt: now };
            window.rateLimitAttempts = attempts;
            return true;
        }

        const timePassed = now - attempts[identifier].firstAttempt;
        
        if (timePassed > timeWindow) {
            attempts[identifier] = { count: 1, firstAttempt: now };
            window.rateLimitAttempts = attempts;
            return true;
        }

        if (attempts[identifier].count >= maxAttempts) {
            return false;
        }

        attempts[identifier].count++;
        window.rateLimitAttempts = attempts;
        return true;
    }
}

// ========================
// API МЕНЕДЖЕР (работа с сервером)
// ========================

class ApiManager {
    static async request(url, options = {}) {
        try {
            const defaultOptions = {
                headers: {
                    'Content-Type': 'application/json',
                },
                ...options
            };

            const response = await fetch(url, defaultOptions);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Ошибка сервера');
            }

            return data;
        } catch (error) {
            throw new Error(error.message || 'Ошибка сети');
        }
    }

    // Регистрация на сервере
    static async register(userData) {
        return this.request('/api/register', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    }

    // Авторизация на сервере
    static async login(credentials) {
        return this.request('/api/login', {
            method: 'POST',
            body: JSON.stringify(credentials)
        });
    }

    // Получение информации о пользователе
    static async getUserInfo(userId) {
        return this.request(`/api/user/${userId}`);
    }

    // Загрузка файла
    static async uploadFile(formData) {
        return this.request('/api/upload', {
            method: 'POST',
            body: formData,
            headers: {} // FormData сам установит Content-Type
        });
    }

    // Получение файлов пользователя
    static async getUserFiles(userId) {
        return this.request(`/api/files/${userId}`);
    }
}

// ========================
// СИСТЕМА УПРАВЛЕНИЯ ПОЛЬЗОВАТЕЛЯМИ
// ========================

class UserManager {
    constructor() {
        this.currentUser = this.loadCurrentUser();
        this.init();
    }

    loadCurrentUser() {
        const userData = localStorage.getItem('nursultan_user');
        return userData ? JSON.parse(userData) : null;
    }

    saveCurrentUser(user) {
        localStorage.setItem('nursultan_user', JSON.stringify(user));
        this.currentUser = user;
    }

    clearCurrentUser() {
        localStorage.removeItem('nursultan_user');
        this.currentUser = null;
    }

    init() {
        if (this.currentUser) {
            this.showUserDashboard();
            this.updateAuthButton();
        }
    }

    isValidEmail(email) {
        if (!email || typeof email !== 'string') return false;
        
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        
        if (!SecurityManager.validateForSQL(email)) return false;
        if (email.length > 254) return false;
        
        return emailRegex.test(email);
    }

    isValidLogin(login) {
        if (!login || typeof login !== 'string') return false;
        if (!SecurityManager.validateForSQL(login)) return false;
        
        const loginRegex = /^[a-zA-Z0-9_]{3,30}$/;
        return loginRegex.test(login);
    }

    isValidPassword(password) {
        if (!password || typeof password !== 'string') return false;
        return password.length >= 6; // Соответствует серверу
    }

    getPasswordStrengthIssues(password) {
        const validation = SecurityManager.validatePasswordStrength(password);
        return validation.issues;
    }

    // Регистрация через сервер
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
            throw new Error('Пароль должен содержать минимум 6 символов');
        }

        // Отправка на сервер
        const response = await ApiManager.register({
            login: sanitizedLogin,
            email: sanitizedEmail.toLowerCase(),
            password: password
        });

        return response;
    }

    // Авторизация через сервер
    async login(loginOrEmail, password) {
        if (!loginOrEmail || !password) {
            throw new Error('Заполните все поля');
        }

        const sanitizedLoginOrEmail = SecurityManager.sanitizeInput(loginOrEmail);

        // Проверка rate limiting
        if (!SecurityManager.checkRateLimit('login_' + sanitizedLoginOrEmail, 5, 900000)) {
            throw new Error('Слишком много попыток входа. Попробуйте позже.');
        }

        // Отправка на сервер
        const response = await ApiManager.login({
            login: sanitizedLoginOrEmail,
            password: password
        });

        // Сохраняем пользователя локально
        this.saveCurrentUser(response.user);
        return response.user;
    }

    logout() {
        this.clearCurrentUser();
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

            // Добавляем загрузку файлов
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

    // Отображение формы загрузки файлов
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
                        <input type="file" name="program" accept=".exe,.zip,.rar" required style="margin-bottom: 15px;">
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

    // Инициализация загрузки файлов
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

            formData.append('program', fileInput.files[0]);
            formData.append('userId', this.currentUser.id);

            try {
                const response = await ApiManager.uploadFile(formData);
                nursultanApp.notificationManager.show(response.message, 'success');
                form.reset();
                this.loadUserFiles(); // Обновляем список файлов
            } catch (error) {
                nursultanApp.notificationManager.show(error.message, 'error');
            }
        });
    }

    // Загрузка списка файлов пользователя
    async loadUserFiles() {
        if (!this.currentUser) return;

        try {
            const response = await ApiManager.getUserFiles(this.currentUser.id);
            this.displayFiles(response.files);
        } catch (error) {
            console.error('Ошибка загрузки файлов:', error);
        }
    }

    // Отображение файлов
    displayFiles(files) {
        const filesList = document.querySelector('.files-list');
        if (!filesList) return;

        if (files.length === 0) {
            filesList.innerHTML = '<p style="color: rgba(255,255,255,0.7);">Файлы не найдены</p>';
            return;
        }

        const filesHTML = files.map(file => {
            const uploadDate = new Date(file.upload_date).toLocaleString('ru-RU');
            return `
                <div class="file-item" style="padding: 10px; margin: 5px 0; background: rgba(0,20,40,0.3); border-radius: 8px; border: 1px solid rgba(0,150,255,0.1);">
                    <div style="font-weight: 600; color: #00ccff;">${SecurityManager.sanitizeInput(file.original_name)}</div>
                    <div style="font-size: 12px; color: rgba(255,255,255,0.7);">Загружен: ${uploadDate}</div>
                </div>
            `;
        }).join('');

        filesList.innerHTML = filesHTML;
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

            await this.userManager.register({ login, email, password });
            
            this.notificationManager.show('Регистрация успешна! Теперь можете войти в систему.', 'success');
            this.modalManager.closeModal('register');
            form.reset();
            
            setTimeout(() => {
                this.modalManager.openModal('login');
            }, 1000);
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
    console.log('NURSULTAN App загружен и интегрирован с сервером!');
});