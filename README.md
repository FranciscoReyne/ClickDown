# ClickDown

**ClickDown es una aplicación python opensource para gestion online de trabajos en equipo.**
*ClickDown es una replica de ClickUp*

*por FranciscoReyne*

---

*ATENCIÓN !!!: ESTE PROYECTO ESTÁ EN CONSTRUCCIÓN.-*

---

Para desarrollar una réplica modular de ClickUp en Python. Primero, te presentaré el pseudocódigo general y luego podemos ir desarrollando cada sección.

### Pseudocódigo de réplica de ClickUp

```
1. SISTEMA BASE
   - Inicializar aplicación (framework)
   - Configurar base de datos
   - Configurar autenticación de usuarios
   - Configurar API RESTful

2. MÓDULO DE USUARIOS
   - Gestión de usuarios (crear, actualizar, eliminar)
   - Roles y permisos
   - Autenticación y autorización
   - Perfiles de usuario

3. MÓDULO DE ESPACIOS DE TRABAJO
   - Crear/editar/eliminar espacios
   - Gestionar miembros del espacio
   - Configuración del espacio

4. MÓDULO DE PROYECTOS/LISTAS
   - Crear/editar/eliminar proyectos
   - Organizar proyectos en espacios
   - Configurar vistas de proyectos

5. MÓDULO DE TAREAS
   - CRUD de tareas
   - Asignación de responsables
   - Estados y prioridades
   - Fechas límite
   - Subtareas

6. MÓDULO DE VISTAS
   - Vista de lista
   - Vista de tablero (Kanban)
   - Vista de calendario
   - Vista de Gantt
   - Vista de línea de tiempo

7. MÓDULO DE NOTIFICACIONES
   - Alertas de cambios
   - Menciones
   - Recordatorios

8. MÓDULO DE INTEGRACIONES
   - API para conectar con otras herramientas
   - Webhooks

9. INTERFAZ DE USUARIO
   - Frontend (web/móvil)
   - Diseño responsive
```

## Recomendación de entorno de desarrollo

Para un proyecto de esta envergadura, te recomendaría usar:

1. **VS Code** como IDE principal en lugar de Jupyter o Spyder. Es más adecuado para desarrollo de aplicaciones completas porque:
   - Tiene mejor gestión de proyectos con múltiples archivos
   - Mejor soporte para control de versiones (Git)
   - Extensiones específicas para desarrollo web
   - Mejor depuración

2. **Stack tecnológico recomendado**:
   - **Backend**: Flask o FastAPI (más moderno y rápido)
   - **Base de datos**: PostgreSQL para datos relacionales, MongoDB para ciertos aspectos no relacionales
   - **ORM**: SQLAlchemy para abstracción de base de datos
   - **Frontend**: React o Vue.js (aunque podemos mantener esto simple al inicio)

3. **Estructura de proyecto**: Organización por módulos siguiendo patrones como repositorio/servicio/controlador

Empecemos desarrollando la estructura base y el módulo de usuarios para tener una base sólida.

# Parte 1 y 2: Estructura base y el módulo de usuarios


## Estructura base y el módulo de usuarios para nuestra réplica de ClickUp.

```python
# Estructura de directorios del proyecto
"""
clickup_clone/
│
├── app/
│   ├── __init__.py           # Inicialización de la aplicación
│   ├── config.py             # Configuraciones
│   ├── models/               # Modelos de datos
│   │   ├── __init__.py
│   │   ├── user.py           # Modelo de usuario
│   │   ├── workspace.py      # Modelo de espacio de trabajo
│   │   ├── project.py        # Modelo de proyecto
│   │   └── task.py           # Modelo de tarea
│   │
│   ├── api/                  # API RESTful
│   │   ├── __init__.py
│   │   ├── users.py          # Endpoints de usuarios
│   │   ├── workspaces.py     # Endpoints de espacios
│   │   ├── projects.py       # Endpoints de proyectos
│   │   └── tasks.py          # Endpoints de tareas
│   │
│   ├── services/             # Lógica de negocio
│   │   ├── __init__.py
│   │   ├── user_service.py   # Servicio de usuarios
│   │   ├── workspace_service.py
│   │   ├── project_service.py
│   │   └── task_service.py
│   │
│   ├── auth/                 # Autenticación
│   │   ├── __init__.py
│   │   └── auth.py           # Lógica de autenticación
│   │
│   └── utils/                # Utilidades
│       ├── __init__.py
│       └── helpers.py        # Funciones auxiliares
│
├── migrations/               # Migraciones de base de datos
│
├── tests/                    # Pruebas
│   ├── __init__.py
│   ├── test_users.py
│   ├── test_workspaces.py
│   └── test_tasks.py
│
├── instance/                 # Configuración de instancia
│   └── config.py             # Configuración local
│
├── requirements.txt          # Dependencias
├── run.py                    # Punto de entrada para ejecutar la aplicación
└── README.md                 # Documentación
"""

```

## Archivos principales para la configuración base y el módulo de usuarios:


### Inicialización de la Aplicación y Configuración
```python
# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS

# Inicializar extensiones
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()

def create_app(config_name='default'):
    app = Flask(__name__)
    
    # Cargar configuración
    from app.config import config_by_name
    app.config.from_object(config_by_name[config_name])
    
    # Inicializar extensiones con la aplicación
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    CORS(app)
    
    # Registrar blueprints (rutas API)
    from app.api.users import user_bp
    app.register_blueprint(user_bp, url_prefix='/api/users')
    
    # Agregar más blueprints aquí a medida que se desarrollen
    
    @app.route('/health')
    def health_check():
        return {"status": "healthy"}, 200
        
    return app

# app/config.py
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev_key_change_in_production')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt_dev_key')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL', 'sqlite:///dev_clickup.db')

class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL', 'sqlite:///test_clickup.db')

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

```

###  Modelo de Usuario

```python
# app/models/user.py
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    avatar_url = db.Column(db.String(256))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relaciones
    # workspaces = db.relationship('Workspace', secondary='workspace_members', back_populates='members')
    # assigned_tasks = db.relationship('Task', back_populates='assignee')
    # created_tasks = db.relationship('Task', back_populates='creator')
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
        
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def to_dict(self):
        return {
            'id': self.public_id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'avatar_url': self.avatar_url,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
    def __repr__(self):
        return f'<User {self.username}>'

```

### Servicio de Usuario

```python
# app/services/user_service.py
from app import db
from app.models.user import User
from sqlalchemy.exc import IntegrityError
from typing import Dict, List, Optional, Tuple
import uuid

class UserService:
    @staticmethod
    def create_user(user_data: Dict) -> Tuple[Optional[User], Optional[str]]:
        """Crea un nuevo usuario"""
        try:
            user = User(
                username=user_data.get('username'),
                email=user_data.get('email'),
                first_name=user_data.get('first_name', ''),
                last_name=user_data.get('last_name', ''),
                avatar_url=user_data.get('avatar_url', '')
            )
            user.password = user_data.get('password')
            
            db.session.add(user)
            db.session.commit()
            return user, None
            
        except IntegrityError as e:
            db.session.rollback()
            if 'users.username' in str(e):
                return None, "El nombre de usuario ya está en uso"
            if 'users.email' in str(e):
                return None, "El correo electrónico ya está registrado"
            return None, "Error al crear el usuario"
            
        except Exception as e:
            db.session.rollback()
            return None, str(e)
    
    @staticmethod
    def get_user_by_id(user_id: str) -> Optional[User]:
        """Obtiene un usuario por su ID público"""
        return User.query.filter_by(public_id=user_id).first()
    
    @staticmethod
    def get_user_by_email(email: str) -> Optional[User]:
        """Obtiene un usuario por su correo electrónico"""
        return User.query.filter_by(email=email).first()
    
    @staticmethod
    def get_user_by_username(username: str) -> Optional[User]:
        """Obtiene un usuario por su nombre de usuario"""
        return User.query.filter_by(username=username).first()
    
    @staticmethod
    def get_all_users() -> List[User]:
        """Obtiene todos los usuarios"""
        return User.query.all()
    
    @staticmethod
    def update_user(user_id: str, user_data: Dict) -> Tuple[Optional[User], Optional[str]]:
        """Actualiza un usuario existente"""
        user = UserService.get_user_by_id(user_id)
        if not user:
            return None, "Usuario no encontrado"
            
        try:
            if 'username' in user_data:
                user.username = user_data['username']
            if 'email' in user_data:
                user.email = user_data['email']
            if 'first_name' in user_data:
                user.first_name = user_data['first_name']
            if 'last_name' in user_data:
                user.last_name = user_data['last_name']
            if 'avatar_url' in user_data:
                user.avatar_url = user_data['avatar_url']
            if 'password' in user_data:
                user.password = user_data['password']
            if 'is_active' in user_data:
                user.is_active = user_data['is_active']
            if 'is_admin' in user_data and isinstance(user_data['is_admin'], bool):
                user.is_admin = user_data['is_admin']
                
            db.session.commit()
            return user, None
            
        except IntegrityError as e:
            db.session.rollback()
            if 'users.username' in str(e):
                return None, "El nombre de usuario ya está en uso"
            if 'users.email' in str(e):
                return None, "El correo electrónico ya está registrado"
            return None, "Error al actualizar el usuario"
            
        except Exception as e:
            db.session.rollback()
            return None, str(e)
    
    @staticmethod
    def delete_user(user_id: str) -> Tuple[bool, Optional[str]]:
        """Elimina un usuario"""
        user = UserService.get_user_by_id(user_id)
        if not user:
            return False, "Usuario no encontrado"
            
        try:
            db.session.delete(user)
            db.session.commit()
            return True, None
            
        except Exception as e:
            db.session.rollback()
            return False, str(e)

```

### Servicio de Autenticación

```python
# app/auth/auth.py
from flask_jwt_extended import create_access_token, create_refresh_token
from app.services.user_service import UserService
from typing import Dict, Tuple, Optional

class AuthService:
    @staticmethod
    def login(credentials: Dict) -> Tuple[Dict, int]:
        """Autentica a un usuario y genera tokens JWT"""
        # Verificar si se proporciona email o username
        email = credentials.get('email')
        username = credentials.get('username')
        password = credentials.get('password')
        
        if not password:
            return {"error": "La contraseña es requerida"}, 400
            
        # Buscar usuario por email o username
        user = None
        if email:
            user = UserService.get_user_by_email(email)
        elif username:
            user = UserService.get_user_by_username(username)
        else:
            return {"error": "Se requiere email o nombre de usuario"}, 400
            
        # Verificar si el usuario existe y la contraseña es correcta
        if not user or not user.verify_password(password):
            return {"error": "Credenciales inválidas"}, 401
            
        # Verificar si el usuario está activo
        if not user.is_active:
            return {"error": "Cuenta desactivada. Contacte al administrador"}, 403
            
        # Generar tokens
        access_token = create_access_token(identity=user.public_id)
        refresh_token = create_refresh_token(identity=user.public_id)
        
        return {
            "message": "Inicio de sesión exitoso",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.to_dict()
        }, 200
    
    @staticmethod
    def register(user_data: Dict) -> Tuple[Dict, int]:
        """Registra un nuevo usuario"""
        # Validar datos requeridos
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not user_data.get(field):
                return {"error": f"El campo {field} es requerido"}, 400
                
        # Crear nuevo usuario
        user, error = UserService.create_user(user_data)
        if error:
            return {"error": error}, 400
            
        # Generar tokens
        access_token = create_access_token(identity=user.public_id)
        refresh_token = create_refresh_token(identity=user.public_id)
        
        return {
            "message": "Usuario registrado exitosamente",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.to_dict()
        }, 201
    
    @staticmethod
    def refresh_token(user_id: str) -> Tuple[Dict, int]:
        """Genera un nuevo access token usando el refresh token"""
        user = UserService.get_user_by_id(user_id)
        if not user:
            return {"error": "Usuario no encontrado"}, 404
            
        if not user.is_active:
            return {"error": "Cuenta desactivada"}, 403
            
        access_token = create_access_token(identity=user.public_id)
        
        return {
            "access_token": access_token
        }, 200

```


### API de Usuarios

```python
# app/api/users.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.user_service import UserService
from app.auth.auth import AuthService

user_bp = Blueprint('users', __name__)

@user_bp.route('/register', methods=['POST'])
def register():
    """Endpoint para registrar un nuevo usuario"""
    data = request.get_json()
    response, status_code = AuthService.register(data)
    return jsonify(response), status_code

@user_bp.route('/login', methods=['POST'])
def login():
    """Endpoint para autenticar un usuario"""
    data = request.get_json()
    response, status_code = AuthService.login(data)
    return jsonify(response), status_code

@user_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """Endpoint para renovar el token de acceso"""
    current_user = get_jwt_identity()
    response, status_code = AuthService.refresh_token(current_user)
    return jsonify(response), status_code

@user_bp.route('/', methods=['GET'])
@jwt_required()
def get_users():
    """Endpoint para obtener todos los usuarios"""
    users = UserService.get_all_users()
    return jsonify([user.to_dict() for user in users]), 200

@user_bp.route('/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Endpoint para obtener un usuario específico"""
    user = UserService.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
    return jsonify(user.to_dict()), 200

@user_bp.route('/<user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """Endpoint para actualizar un usuario"""
    current_user = get_jwt_identity()
    user = UserService.get_user_by_id(current_user)
    
    # Solo permitir que un usuario actualice su propio perfil o un administrador
    if current_user != user_id and not user.is_admin:
        return jsonify({"error": "No autorizado"}), 403
        
    data = request.get_json()
    updated_user, error = UserService.update_user(user_id, data)
    
    if error:
        return jsonify({"error": error}), 400
        
    return jsonify({
        "message": "Usuario actualizado exitosamente",
        "user": updated_user.to_dict()
    }), 200

@user_bp.route('/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """Endpoint para eliminar un usuario"""
    current_user = get_jwt_identity()
    user = UserService.get_user_by_id(current_user)
    
    # Solo permitir que un usuario elimine su propia cuenta o un administrador
    if current_user != user_id and not user.is_admin:
        return jsonify({"error": "No autorizado"}), 403
        
    success, error = UserService.delete_user(user_id)
    
    if not success:
        return jsonify({"error": error}), 400
        
    return jsonify({"message": "Usuario eliminado exitosamente"}), 200

@user_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Endpoint para obtener el usuario actualmente autenticado"""
    current_user = get_jwt_identity()
    user = UserService.get_user_by_id(current_user)
    
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
        
    return jsonify(user.to_dict()), 200

```

### Punto de Entrada de la Aplicación

```python
# run.py
import os
from app import create_app

app = create_app(os.getenv('FLASK_CONFIG') or 'default')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

```
### Archivo de Requisitos

```text
# requirements.txt
flask==2.2.3
flask-sqlalchemy==3.0.3
flask-migrate==4.0.4
flask-jwt-extended==4.4.4
flask-cors==3.0.10
psycopg2-binary==2.9.5
python-dotenv==1.0.0
werkzeug==2.2.3

```

## Explicación del código implementado

Hemos desarrollado la estructura base y el módulo de usuarios para nuestra réplica de ClickUp (ClickDown). Aquí está la explicación de cada componente:

1. **Estructura del proyecto**: Organizada de manera modular con separación clara de responsabilidades siguiendo el patrón MVC+S (Modelo-Vista-Controlador+Servicio).

2. **Configuración y app**: 
   - Implementé Flask como framework base con configuración para diferentes entornos (desarrollo, pruebas, producción)
   - Configuración de JWT para autenticación basada en tokens
   - Sistema de blueprints para estructurar los endpoints API

3. **Módulo de usuarios**:
   - Modelo de usuario con todos los campos necesarios y relaciones preparadas para otros módulos
   - Servicios para la gestión completa de usuarios (CRUD)
   - Autenticación con JWT para generar tokens de acceso y refresco
   - API RESTful con endpoints para todas las operaciones de usuarios

4. **Seguridad**:
   - Contraseñas almacenadas con hash seguro
   - Control de acceso basado en roles (usuario normal vs administrador)
   - Validación de datos de entrada

## Pasos para ejecutar la aplicación

1. **Crear un entorno virtual**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # En Windows: venv\Scripts\activate
   ```

2. **Instalar dependencias**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configurar variables de entorno** (opcional, crea un archivo `.env`):
   ```
   FLASK_APP=run.py
   FLASK_ENV=development
   FLASK_CONFIG=development
   SECRET_KEY=tu_clave_secreta_aqui
   JWT_SECRET_KEY=tu_clave_jwt_aqui
   ```

4. **Inicializar la base de datos**:
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

5. **Ejecutar la aplicación**:
   ```bash
   flask run
   ```

## IMPORTANTE!!! Próximos pasos...

1. Implementar el módulo de espacios de trabajo (workspaces) [Parte 3]
2. Desarrollar el módulo de proyectos [Parte 4]
3. Crear el módulo de tareas [Parte 5]
4. Implementar las diferentes vistas (lista, kanban, etc.) [Parte 6-8]

---

Ahora vamos a diseñar el pseudocódigo para el módulo de espacios de trabajo (workspaces) antes de implementarlo. Esto nos ayudará a tener una visión clara de lo que necesitamos desarrollar.


Para no extender tanto este documento he creado uno propio para la Parte 3: Implementar el módulo de espacios de trabajo (workspaces).

[Ir a Parte 3: Workspace](https://github.com/FranciscoReyne/ClickDown/blob/main/parte-3_WorkSpaces)







