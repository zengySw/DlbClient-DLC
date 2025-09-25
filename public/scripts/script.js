// DLB Frontend Script
// Совместимый с EJS шаблоном скрипт

class DlbApp {
    constructor() {
        this.currentUser = null;
        this.particles = [];
        this.init();
    }

    init() {
        this.initEventListeners();
        this.initModals();
        this.initParticles();
        this.checkAuthStatus();
    }

    // ========================
    // СИСТЕМА ЧАСТИЦ
    // ========================
    
    initParticles() {
        const particlesContainer = document.querySelector('.particles');
        if (!particlesContainer) return;

        const particleCount = window.innerWidth < 768 ? 30 : 60;

        for (let i = 0; i < particleCount; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            
            const size = Math.random() * 3 + 1;
            particle.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                background: rgba(0, 204, 255, ${Math.random() * 0.5 + 0.2});
                border-radius: 50%;
                top: ${Math.random() * 100}vh;
                left: ${Math.random() * 100}vw;
                pointer-events: none;
                animation: float ${Math.random() * 6 + 4}s linear infinite;
            `;
            
            particlesContainer.appendChild(particle);
            this.particles.push(particle);
        }

        // Добавляем CSS анимацию если её нет
        this.addParticleStyles();
    }

    addParticleStyles() {
        const styleId = 'particle-styles';
        if (document.getElementById(styleId)) return;

        const style = document.createElement('style');
        style.id = styleId;
        style.textContent = `
            @keyframes float {
                0% {
                    transform: translateY(100vh) rotate(0deg);
                    opacity: 0;
                }
                10% {
                    opacity: 1;
                }
                90% {
                    opacity: 1;
                }
                100% {
                    transform: translateY(-10vh) rotate(360deg);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }

    // ========================
    // МОДАЛЬНЫЕ ОКНА
    // ========================

    initModals() {
        // Кнопки открытия модальных окон
        document.querySelectorAll('[data-modal]').forEach(btn => {
            btn.addEventListener('click', () => {
                const modalType = btn.getAttribute('data-modal');
                this.openModal(modalType);
            });
        });

        // Кнопки закрытия модальных окон
        document.querySelectorAll('[data-close]').forEach(btn => {
            btn.addEventListener('click', () => {
                const modalType = btn.getAttribute('data-close');
                this.closeModal(modalType);
            });
        });

        // Переключение между модалями
        document.querySelectorAll('[data-switch]').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const toModal = link.getAttribute('data-switch');
                const fromModal = link.getAttribute('data-from');
                this.closeModal(fromModal);
                setTimeout(() => this.openModal(toModal), 200);
            });
        });

        // Закрытие модалей по клику вне их
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    const modalId = modal.id.replace('Modal', '');
                    this.closeModal(modalId);
                }
            });
        });

        // Закрытие по ESC
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal').forEach(modal => {
                    if (modal.style.display === 'flex') {
                        const modalId = modal.id.replace('Modal', '');
                        this.closeModal(modalId);
                    }
                });
            }
        });
    }

    openModal(modalType) {
        const modal = document.getElementById(modalType + 'Modal');
        if (modal) {
            modal.style.display = 'flex';
            // Фокус на первое поле ввода
            const firstInput = modal.querySelector('input');
            if (firstInput) {
                setTimeout(() => firstInput.focus(), 100);
            }
        }
    }

    closeModal(modalType) {
        const modal = document.getElementById(modalType + 'Modal');
        if (modal) {
            modal.style.display = 'none';
            // Очистка формы при закрытии
            const form = modal.querySelector('form');
            if (form) {
                form.reset();
                this.clearValidationStyles(form);
            }
        }
    }

    clearValidationStyles(form) {
        const inputs = form.querySelectorAll('input');
        inputs.forEach(input => {
            input.style.borderColor = '';
        });
    }

    // ========================
    // ОБРАБОТЧИКИ СОБЫТИЙ
    // ========================

    initEventListeners() {
        // Инициализация форм
        this.initForms();

        // Кнопки скролла
        document.querySelectorAll('[data-scroll]').forEach(btn => {
            btn.addEventListener('click', () => {
                const sectionId = btn.getAttribute('data-scroll');
                this.scrollToSection(sectionId);
            });
        });

        // Кнопка выхода
        document.querySelectorAll('[data-action="logout"]').forEach(btn => {
            btn.addEventListener('click', () => this.logout());
        });

        // Адаптивность частиц при изменении размера окна
        window.addEventListener('resize', () => {
            this.reinitParticles();
        });
    }

    initForms() {
        // Форма входа
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin(loginForm);
            });
        }

        // Форма регистрации
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleRegister(registerForm);
            });
        }

        // Валидация в реальном времени
        this.initRealtimeValidation();
    }

    initRealtimeValidation() {
        // Email валидация
        document.querySelectorAll('input[type="email"]').forEach(input => {
            input.addEventListener('input', () => {
                this.validateEmail(input);
            });
        });

        // Логин валидация
        document.querySelectorAll('input[name="login"]').forEach(input => {
            input.addEventListener('input', () => {
                this.validateLogin(input);
            });
        });

        // Пароль валидация
        document.querySelectorAll('input[type="password"]').forEach(input => {
            input.addEventListener('input', () => {
                this.validatePassword(input);
            });
        });
    }

    // ========================
    // ВАЛИДАЦИЯ
    // ========================

    validateEmail(input) {
        const email = input.value.trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        
        if (email === '') {
            this.setInputState(input, 'neutral');
        } else if (emailRegex.test(email) && email.length <= 254) {
            this.setInputState(input, 'valid');
        } else {
            this.setInputState(input, 'invalid');
        }
    }

    validateLogin(input) {
        const login = input.value.trim();
        const loginRegex = /^[a-zA-Z0-9_]{3,30}$/;
        
        if (login === '') {
            this.setInputState(input, 'neutral');
        } else if (loginRegex.test(login)) {
            this.setInputState(input, 'valid');
        } else {
            this.setInputState(input, 'invalid');
        }
    }

    validatePassword(input) {
        const password = input.value;
        const hasLength = password.length >= 8;
        const hasLetters = /[a-zA-Z]/.test(password);
        const hasNumbers = /\d/.test(password);
        
        if (password === '') {
            this.setInputState(input, 'neutral');
        } else if (hasLength && hasLetters && hasNumbers) {
            this.setInputState(input, 'valid');
        } else {
            this.setInputState(input, 'invalid');
        }
    }

    setInputState(input, state) {
        const colors = {
            neutral: 'rgba(0, 150, 255, 0.3)',
            valid: '#28a745',
            invalid: '#dc3545'
        };
        input.style.borderColor = colors[state];
    }

    // ========================
    // АВТОРИЗАЦИЯ И РЕГИСТРАЦИЯ
    // ========================

   async handleLogin(form) {
    const formData = new FormData(form);
    console.log('loginOrEmail:', formData.get('loginOrEmail'));
    console.log('password:', formData.get('password'));

    const login = (formData.get('loginOrEmail') || '').trim();
    const password = formData.get('password') || '';

    // правильная проверка
    if (!login || !password) {
        this.showNotification('Заполните все поля', 'error');
        return;
    }

    try {
        const response = await this.makeApiRequest('/api/login', {
            method: 'POST',
            body: JSON.stringify({ login, password }) // отправляем login и password
        });

        if (response.success) {
            this.currentUser = response.user;
            this.saveAuthToken(response.token);
            this.showUserDashboard();
            this.updateAuthButton();
            this.closeModal('login');
            this.showNotification(`Добро пожаловать, ${response.user.login}!`, 'success');
        }
    } catch (error) {
        this.showNotification(error.message, 'error');
    }
}


    async handleRegister(form) {
        const formData = new FormData(form);
        const registerData = {
            login: formData.get('login')?.trim(),
            email: formData.get('email')?.trim().toLowerCase(),
            password: formData.get('password')
        };

        // Клиентская валидация
        if (!this.validateRegisterData(registerData)) {
            return;
        }

        try {
            const response = await this.makeApiRequest('/api/register', {
                method: 'POST',
                body: JSON.stringify(registerData)
            });

            if (response.success) {
                this.closeModal('register');
                this.showNotification('Регистрация успешна! Теперь можете войти в систему.', 'success');
                setTimeout(() => this.openModal('login'), 1000);
            }
        } catch (error) {
            this.showNotification(error.message, 'error');
        }
    }

    validateRegisterData(data) {
        if (!data.login || !data.email || !data.password) {
            this.showNotification('Заполните все поля', 'error');
            return false;
        }

        if (!/^[a-zA-Z0-9_]{3,30}$/.test(data.login)) {
            this.showNotification('Логин должен содержать 3-30 символов (буквы, цифры, подчеркивания)', 'error');
            return false;
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
            this.showNotification('Введите корректный email адрес', 'error');
            return false;
        }

        if (data.password.length < 8 || !/[a-zA-Z]/.test(data.password) || !/\d/.test(data.password)) {
            this.showNotification('Пароль должен содержать минимум 8 символов, включая буквы и цифры', 'error');
            return false;
        }

        return true;
    }

    // ========================
    // API ЗАПРОСЫ
    // ========================

    async makeApiRequest(url, options = {}) {
        const token = this.getAuthToken();
        
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json'
            },
            ...options
        };

        if (token) {
            defaultOptions.headers.Authorization = `Bearer ${token}`;
        }

        const response = await fetch(url, defaultOptions);
        const data = await response.json();

        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                this.handleTokenExpiry();
            }
            throw new Error(data.message || 'Ошибка сервера');
        }

        return data;
    }

    // ========================
    // УПРАВЛЕНИЕ ТОКЕНАМИ
    // ========================

    saveAuthToken(token) {
        localStorage.setItem('dlb_auth_token', token);
    }

    getAuthToken() {
        return localStorage.getItem('dlb_auth_token');
    }

    removeAuthToken() {
        localStorage.removeItem('dlb_auth_token');
    }

    handleTokenExpiry() {
        this.removeAuthToken();
        this.currentUser = null;
        this.hideUserDashboard();
        this.updateAuthButton();
        this.showNotification('Сессия истекла. Пожалуйста, войдите снова', 'warning');
    }

    async checkAuthStatus() {
        const token = this.getAuthToken();
        if (token) {
            try {
                const response = await this.makeApiRequest('/api/verify-token', {
                    method: 'POST'
                });
                
                if (response.success) {
                    this.currentUser = response.user;
                    this.showUserDashboard();
                    this.updateAuthButton();
                }
            } catch (error) {
                this.handleTokenExpiry();
            }
        }
    }

    // ========================
    // ПОЛЬЗОВАТЕЛЬСКИЙ ИНТЕРФЕЙС
    // ========================

    showUserDashboard() {
        const dashboard = document.getElementById('user-dashboard');
        if (dashboard && this.currentUser) {
            dashboard.classList.remove('hidden');
            
            const usernameEl = document.getElementById('username');
            const useridEl = document.getElementById('userid');
            const useremailEl = document.getElementById('useremail');

            if (usernameEl) usernameEl.textContent = this.currentUser.login;
            if (useridEl) useridEl.textContent = this.currentUser.id;
            if (useremailEl) useremailEl.textContent = this.currentUser.email;
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
                authButton.textContent = `${this.currentUser.login} ▼`;
                authButton.onclick = () => this.logout();
            } else {
                authButton.textContent = 'Авторизация';
                authButton.onclick = () => this.openModal('login');
            }
        }
    }

    logout() {
        this.removeAuthToken();
        this.currentUser = null;
        this.hideUserDashboard();
        this.updateAuthButton();
        this.showNotification('Вы вышли из системы', 'info');
    }

    // ========================
    // УВЕДОМЛЕНИЯ
    // ========================

    showNotification(message, type = 'info', duration = 5000) {
        // Создаем контейнер для уведомлений если его нет
        let container = document.getElementById('notification-container');
        if (!container) {
            container = document.createElement('div');
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

        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            background: ${this.getNotificationColor(type)};
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            border-left: 4px solid ${this.getNotificationBorderColor(type)};
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
            pointer-events: auto;
            cursor: pointer;
            max-width: 350px;
            word-wrap: break-word;
        `;
        
        notification.textContent = message;
        container.appendChild(notification);

        // Анимация появления
        setTimeout(() => {
            notification.style.opacity = '1';
            notification.style.transform = 'translateX(0)';
        }, 10);

        // Автоматическое исчезновение
        setTimeout(() => {
            this.hideNotification(notification);
        }, duration);

        // Исчезновение по клику
        notification.addEventListener('click', () => {
            this.hideNotification(notification);
        });
    }

    hideNotification(notification) {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }

    getNotificationColor(type) {
        const colors = {
            success: 'linear-gradient(135deg, #28a745, #20c997)',
            error: 'linear-gradient(135deg, #dc3545, #e74c3c)',
            warning: 'linear-gradient(135deg, #ffc107, #f39c12)',
            info: 'linear-gradient(135deg, #007bff, #0066cc)'
        };
        return colors[type] || colors.info;
    }

    getNotificationBorderColor(type) {
        const colors = {
            success: '#20c997',
            error: '#e74c3c',
            warning: '#f39c12',
            info: '#0066cc'
        };
        return colors[type] || colors.info;
    }

    // ========================
    // УТИЛИТЫ
    // ========================

    scrollToSection(sectionId) {
        const element = document.getElementById(sectionId);
        if (element) {
            element.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    }

    reinitParticles() {
        // Удаляем старые частицы
        this.particles.forEach(particle => {
            if (particle.parentNode) {
                particle.parentNode.removeChild(particle);
            }
        });
        this.particles = [];

        // Создаем новые
        setTimeout(() => this.initParticles(), 100);
    }

    // ========================
    // БЕЗОПАСНОСТЬ
    // ========================

    sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        
        return input
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;')
            .trim();
    }
}

// ========================
// ГЛОБАЛЬНЫЕ ФУНКЦИИ
// ========================

let app;

// Функции для совместимости с HTML
window.openModal = function(type) {
    if (app) app.openModal(type);
};

window.closeModal = function(type) {
    if (app) app.closeModal(type);
};

window.scrollToSection = function(id) {
    if (app) app.scrollToSection(id);
};

// ========================
// ИНИЦИАЛИЗАЦИЯ
// ========================

document.addEventListener('DOMContentLoaded', () => {
    app = new DlbApp();
    console.log('DLB App успешно загружен!');
});