
# Parte 3: Implementar el módulo de espacios de trabajo (workspaces).

Para implementar el módulo de espacios de trabajo (workspaces), necesitaremos desarrollar código adicional. Lo que te he proporcionado hasta ahora es la estructura base y el módulo de usuarios, pero el módulo de workspaces requiere sus propios componentes.

### Específicamente, necesitaremos crear:

- Modelo de Workspace: Un nuevo archivo en la carpeta models que defina la estructura de datos para los espacios de trabajo, incluyendo relaciones con usuarios y proyectos.
- Servicio de Workspace: Lógica de negocio para crear, leer, actualizar y eliminar espacios de trabajo, así como gestionar miembros.
- API de Workspace: Endpoints REST para interactuar con los espacios de trabajo.
- Tabla de relación: Para manejar la relación muchos-a-muchos entre usuarios y espacios (ya que un usuario puede pertenecer a varios espacios y un espacio puede tener varios miembros).
- Actualizar referencias: Modificar algunos archivos existentes para integrar las relaciones con el módulo de usuarios que ya hemos creado.

No es simplemente integrar los códigos actuales, sino desarrollar nuevos componentes que se conectarán con la estructura que ya tenemos. El código actual proporciona la base sobre la cual construiremos los nuevos módulos de forma incremental.

---

## Pseudocódigo para Módulo de Espacios de Trabajo (Workspaces).

### 1. Modelo de Workspace (workspace.py)
```
Clase Workspace:
    Atributos:
        - id (entero, clave primaria)
        - public_id (string, único)
        - nombre (string)
        - descripción (string, opcional)
        - icono/logo (string, url, opcional)
        - es_privado (booleano)
        - creado_por (relación con Usuario)
        - fecha_creación (datetime)
        - fecha_actualización (datetime)
        
    Relaciones:
        - miembros (relación muchos-a-muchos con Usuario a través de WorkspaceMember)
        - proyectos (relación uno-a-muchos con Proyecto)
        
    Métodos:
        - to_dict(): convertir a diccionario para respuestas API
```

### 2. Modelo de Membresía de Workspace (workspace_member.py)
```
Clase WorkspaceMember:
    Atributos:
        - id (entero, clave primaria)
        - workspace_id (clave foránea a Workspace)
        - user_id (clave foránea a User)
        - rol (string: 'admin', 'member', 'guest')
        - fecha_unión (datetime)
        
    Métodos:
        - to_dict(): convertir a diccionario para respuestas API
```

### 3. Servicio de Workspace (workspace_service.py)
```
Clase WorkspaceService:
    Métodos Estáticos:
        - crear_workspace(datos_workspace, usuario_creador): 
            Validar datos
            Crear nuevo workspace
            Asignar creador como admin
            Retornar workspace o error
            
        - obtener_workspace_por_id(workspace_id):
            Buscar workspace por ID
            Retornar workspace o None
            
        - obtener_workspaces_por_usuario(user_id):
            Buscar todos los workspaces donde el usuario es miembro
            Retornar lista de workspaces
            
        - actualizar_workspace(workspace_id, datos_actualizados):
            Validar datos
            Buscar y actualizar workspace
            Retornar workspace actualizado o error
            
        - eliminar_workspace(workspace_id):
            Validar permisos
            Eliminar workspace y relaciones
            Retornar éxito o error
            
        - agregar_miembro(workspace_id, user_id, rol='member'):
            Verificar si el usuario ya es miembro
            Agregar usuario al workspace con rol especificado
            Retornar estado de operación
            
        - actualizar_rol_miembro(workspace_id, user_id, nuevo_rol):
            Validar datos y permisos
            Actualizar rol del miembro
            Retornar estado de operación
            
        - eliminar_miembro(workspace_id, user_id):
            Validar permisos (no eliminar último admin)
            Eliminar membresía
            Retornar estado de operación
```

### 4. API de Workspace (workspaces.py)
```
Blueprint workspace_bp:

    Endpoint POST /api/workspaces:
        Autenticar usuario (JWT)
        Obtener datos del request
        Llamar a WorkspaceService.crear_workspace()
        Retornar resultado

    Endpoint GET /api/workspaces:
        Autenticar usuario (JWT)
        Llamar a WorkspaceService.obtener_workspaces_por_usuario()
        Retornar lista de workspaces

    Endpoint GET /api/workspaces/<workspace_id>:
        Autenticar usuario (JWT)
        Verificar permisos del usuario en el workspace
        Llamar a WorkspaceService.obtener_workspace_por_id()
        Retornar resultado

    Endpoint PUT /api/workspaces/<workspace_id>:
        Autenticar usuario (JWT)
        Verificar permisos de admin
        Obtener datos del request
        Llamar a WorkspaceService.actualizar_workspace()
        Retornar resultado

    Endpoint DELETE /api/workspaces/<workspace_id>:
        Autenticar usuario (JWT)
        Verificar permisos de admin
        Llamar a WorkspaceService.eliminar_workspace()
        Retornar resultado

    Endpoint POST /api/workspaces/<workspace_id>/members:
        Autenticar usuario (JWT)
        Verificar permisos de admin
        Obtener datos del usuario a agregar
        Llamar a WorkspaceService.agregar_miembro()
        Retornar resultado

    Endpoint PUT /api/workspaces/<workspace_id>/members/<user_id>:
        Autenticar usuario (JWT)
        Verificar permisos de admin
        Obtener nuevo rol del request
        Llamar a WorkspaceService.actualizar_rol_miembro()
        Retornar resultado

    Endpoint DELETE /api/workspaces/<workspace_id>/members/<user_id>:
        Autenticar usuario (JWT)
        Verificar permisos de admin
        Llamar a WorkspaceService.eliminar_miembro()
        Retornar resultado
```

### 5. Actualización de Modelo de Usuario
```
Actualizar User:
    Relaciones:
        - Agregar relación con Workspace a través de WorkspaceMember
        - Agregar método para verificar permisos en un workspace específico
```

### 6. Lógica de Permisos (auth/permissions.py)
```
Funciones de Verificación de Permisos:
    
    - verificar_admin_workspace(user_id, workspace_id):
        Buscar membresía del usuario en el workspace
        Verificar si tiene rol 'admin'
        Retornar booleano
        
    - verificar_miembro_workspace(user_id, workspace_id):
        Buscar membresía del usuario en el workspace
        Retornar booleano
        
    - decorador require_workspace_permission(workspace_id_param, roles=['admin']):
        Función decoradora para endpoints que requieren permisos específicos
```

### 7. Registro de Blueprint en app/__init__.py
```
Actualizar create_app():
    Importar workspace_bp
    Registrar blueprint con url_prefix='/api/workspaces'
```

Este pseudocódigo proporciona una estructura completa para el módulo de espacios de trabajo, incluyendo:

1. La estructura de datos necesaria
2. La lógica de negocio para todas las operaciones CRUD
3. El control de acceso basado en roles dentro de los workspaces
4. Los endpoints API para interactuar con los workspaces
5. La integración con el módulo de usuarios existente

---
---


# Implementación del código: Módulo de espacios de trabajo (workspaces)

Procedamos con la implementación del código para el módulo de espacios de trabajo (workspaces). Este es efectivamente el paso 1 para construir esta funcionalidad en nuestra réplica de ClickUp.


## Explicación del Módulo de Workspaces

Implementaremos el módulo completo de espacios de trabajo (workspaces) para nuestra réplica de ClickUp. Aquí está la explicación de cada componente:

1. **Modelo de Workspace (workspace.py)**:
   - Define la estructura de datos para los espacios de trabajo
   - Implementa la relación muchos-a-muchos con usuarios a través de una tabla intermedia
   - Incluye métodos para gestionar miembros y sus roles
   - Provee funcionalidad para convertir la información a formato API

2. **Servicio de Workspace (workspace_service.py)**:
   - Proporciona todas las operaciones CRUD para workspaces
   - Implementa la lógica para añadir, actualizar y eliminar miembros
   - Incluye funciones de verificación de roles y permisos
   - Maneja errores y transacciones de base de datos

3. **Permisos de Workspace (permissions.py)**:
   - Define decoradores para proteger endpoints según el rol del usuario
   - Implementa verificación de permisos para administradores y miembros

4. **API de Workspaces (workspaces.py)**:
   - Expone endpoints RESTful para todas las operaciones
   - Implementa autenticación con JWT
   - Aplica verificación de permisos según el rol
   - Gestiona respuestas y códigos de estado HTTP

5. **Actualización de app/__init__.py**:
   - Registra el nuevo blueprint de workspaces en la aplicación

## Características a implementar:

1. **Gestión completa de espacios de trabajo**:
   - Crear, leer, actualizar y eliminar workspaces
   - Personalización (nombre, descripción, icono)
   - Configuración de privacidad

2. **Sistema de roles y permisos**:
   - Roles: admin, member, guest
   - Control de acceso basado en roles
   - Protección para evitar eliminar al último administrador

3. **Gestión de miembros**:
   - Añadir y eliminar miembros
   - Actualizar roles de miembros
   - Visualizar todos los miembros de un workspace

4. **Integraciones**:
   - Conexión con el módulo de usuarios
   - Preparado para conexión con futuros módulos (proyectos, tareas)

# Códigos para implementar los workspaces

---

## Modelo de Workspace

```python
# app/models/workspace.py
from app import db
from datetime import datetime
import uuid

# Tabla de relación entre workspaces y usuarios (muchos a muchos)
workspace_members = db.Table(
    'workspace_members',
    db.Column('workspace_id', db.Integer, db.ForeignKey('workspaces.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role', db.String(20), default='member'),  # roles: admin, member, guest
    db.Column('joined_at', db.DateTime, default=datetime.utcnow)
)

class Workspace(db.Model):
    __tablename__ = 'workspaces'
    
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    icon_url = db.Column(db.String(256))
    is_private = db.Column(db.Boolean, default=False)
    
    # Relación con el usuario que creó el workspace
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    creator = db.relationship('User', backref='created_workspaces')
    
    # Relación muchos a muchos con usuarios
    members = db.relationship('User', 
                             secondary=workspace_members,
                             backref=db.backref('workspaces', lazy='dynamic'),
                             lazy='dynamic')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def add_member(self, user, role='member'):
        """Agrega un miembro al workspace con un rol específico"""
        stmt = workspace_members.insert().values(
            workspace_id=self.id,
            user_id=user.id,
            role=role
        )
        db.session.execute(stmt)
        db.session.commit()
    
    def remove_member(self, user):
        """Elimina un miembro del workspace"""
        stmt = workspace_members.delete().where(
            (workspace_members.c.workspace_id == self.id) &
            (workspace_members.c.user_id == user.id)
        )
        db.session.execute(stmt)
        db.session.commit()
    
    def update_member_role(self, user, role):
        """Actualiza el rol de un miembro"""
        stmt = workspace_members.update().where(
            (workspace_members.c.workspace_id == self.id) &
            (workspace_members.c.user_id == user.id)
        ).values(role=role)
        db.session.execute(stmt)
        db.session.commit()
    
    def get_member_role(self, user):
        """Obtiene el rol de un miembro en el workspace"""
        result = db.session.execute(
            db.select([workspace_members.c.role]).where(
                (workspace_members.c.workspace_id == self.id) &
                (workspace_members.c.user_id == user.id)
            )
        ).fetchone()
        return result[0] if result else None
    
    def to_dict(self, include_members=False):
        """Convierte el workspace a un diccionario para la API"""
        workspace_dict = {
            'id': self.public_id,
            'name': self.name,
            'description': self.description,
            'icon_url': self.icon_url,
            'is_private': self.is_private,
            'creator_id': self.creator.public_id if self.creator else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        if include_members:
            workspace_dict['members'] = []
            for member in self.members:
                role = self.get_member_role(member)
                workspace_dict['members'].append({
                    'id': member.public_id,
                    'username': member.username,
                    'email': member.email,
                    'role': role,
                    'avatar_url': member.avatar_url
                })
        
        return workspace_dict
    
    def __repr__(self):
        return f'<Workspace {self.name}>'

```


## Servicio de Workspace

```python
# app/services/workspace_service.py
from app import db
from app.models.workspace import Workspace, workspace_members
from app.services.user_service import UserService
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select
from typing import Dict, List, Optional, Tuple
import uuid

class WorkspaceService:
    @staticmethod
    def create_workspace(workspace_data: Dict, creator_id: str) -> Tuple[Optional[Workspace], Optional[str]]:
        """Crea un nuevo workspace"""
        try:
            # Validar datos requeridos
            if not workspace_data.get('name'):
                return None, "El nombre del workspace es requerido"
                
            # Obtener el usuario creador
            creator = UserService.get_user_by_id(creator_id)
            if not creator:
                return None, "Usuario no encontrado"
                
            # Crear el workspace
            workspace = Workspace(
                name=workspace_data.get('name'),
                description=workspace_data.get('description', ''),
                icon_url=workspace_data.get('icon_url', ''),
                is_private=workspace_data.get('is_private', False),
                creator=creator
            )
            
            db.session.add(workspace)
            db.session.flush()  # Para obtener el ID asignado
            
            # Agregar al creador como administrador
            workspace.add_member(creator, role='admin')
            
            db.session.commit()
            return workspace, None
            
        except IntegrityError as e:
            db.session.rollback()
            return None, f"Error de integridad: {str(e)}"
            
        except Exception as e:
            db.session.rollback()
            return None, str(e)
    
    @staticmethod
    def get_workspace_by_id(workspace_id: str) -> Optional[Workspace]:
        """Obtiene un workspace por su ID público"""
        return Workspace.query.filter_by(public_id=workspace_id).first()
    
    @staticmethod
    def get_workspaces_by_user(user_id: str) -> List[Workspace]:
        """Obtiene todos los workspaces donde el usuario es miembro"""
        user = UserService.get_user_by_id(user_id)
        if not user:
            return []
            
        return user.workspaces.all()
    
    @staticmethod
    def update_workspace(workspace_id: str, workspace_data: Dict) -> Tuple[Optional[Workspace], Optional[str]]:
        """Actualiza un workspace existente"""
        workspace = WorkspaceService.get_workspace_by_id(workspace_id)
        if not workspace:
            return None, "Workspace no encontrado"
            
        try:
            if 'name' in workspace_data:
                workspace.name = workspace_data['name']
            if 'description' in workspace_data:
                workspace.description = workspace_data['description']
            if 'icon_url' in workspace_data:
                workspace.icon_url = workspace_data['icon_url']
            if 'is_private' in workspace_data and isinstance(workspace_data['is_private'], bool):
                workspace.is_private = workspace_data['is_private']
                
            db.session.commit()
            return workspace, None
            
        except Exception as e:
            db.session.rollback()
            return None, str(e)
    
    @staticmethod
    def delete_workspace(workspace_id: str) -> Tuple[bool, Optional[str]]:
        """Elimina un workspace"""
        workspace = WorkspaceService.get_workspace_by_id(workspace_id)
        if not workspace:
            return False, "Workspace no encontrado"
            
        try:
            db.session.delete(workspace)
            db.session.commit()
            return True, None
            
        except Exception as e:
            db.session.rollback()
            return False, str(e)
    
    @staticmethod
    def add_member(workspace_id: str, user_id: str, role: str = 'member') -> Tuple[bool, Optional[str]]:
        """Agrega un miembro al workspace"""
        workspace = WorkspaceService.get_workspace_by_id(workspace_id)
        if not workspace:
            return False, "Workspace no encontrado"
            
        user = UserService.get_user_by_id(user_id)
        if not user:
            return False, "Usuario no encontrado"
            
        # Verificar si ya es miembro
        if workspace.get_member_role(user):
            return False, "El usuario ya es miembro de este workspace"
            
        try:
            workspace.add_member(user, role)
            return True, None
            
        except Exception as e:
            db.session.rollback()
            return False, str(e)
    
    @staticmethod
    def update_member_role(workspace_id: str, user_id: str, role: str) -> Tuple[bool, Optional[str]]:
        """Actualiza el rol de un miembro en el workspace"""
        workspace = WorkspaceService.get_workspace_by_id(workspace_id)
        if not workspace:
            return False, "Workspace no encontrado"
            
        user = UserService.get_user_by_id(user_id)
        if not user:
            return False, "Usuario no encontrado"
            
        # Verificar si es miembro
        if not workspace.get_member_role(user):
            return False, "El usuario no es miembro de este workspace"
            
        # Validar rol
        valid_roles = ['admin', 'member', 'guest']
        if role not in valid_roles:
            return False, f"Rol no válido. Opciones: {', '.join(valid_roles)}"
            
        try:
            workspace.update_member_role(user, role)
            return True, None
            
        except Exception as e:
            db.session.rollback()
            return False, str(e)
    
    @staticmethod
    def remove_member(workspace_id: str, user_id: str) -> Tuple[bool, Optional[str]]:
        """Elimina un miembro del workspace"""
        workspace = WorkspaceService.get_workspace_by_id(workspace_id)
        if not workspace:
            return False, "Workspace no encontrado"
            
        user = UserService.get_user_by_id(user_id)
        if not user:
            return False, "Usuario no encontrado"
            
        # Verificar si es miembro
        if not workspace.get_member_role(user):
            return False, "El usuario no es miembro de este workspace"
            
        # Evitar eliminar al último administrador
        if workspace.get_member_role(user) == 'admin':
            # Contar administradores
            admin_count = db.session.execute(
                select([db.func.count()]).select_from(workspace_members).where(
                    (workspace_members.c.workspace_id == workspace.id) &
                    (workspace_members.c.role == 'admin')
                )
            ).scalar()
            
            if admin_count == 1:
                return False, "No se puede eliminar al último administrador del workspace"
            
        try:
            workspace.remove_member(user)
            return True, None
            
        except Exception as e:
            db.session.rollback()
            return False, str(e)
    
    @staticmethod
    def check_user_role(workspace_id: str, user_id: str) -> str:
        """Verifica el rol de un usuario en un workspace"""
        workspace = WorkspaceService.get_workspace_by_id(workspace_id)
        if not workspace:
            return None
            
        user = UserService.get_user_by_id(user_id)
        if not user:
            return None
            
        return workspace.get_member_role(user)
    
    @staticmethod
    def is_workspace_admin(workspace_id: str, user_id: str) -> bool:
        """Verifica si un usuario es administrador del workspace"""
        role = WorkspaceService.check_user_role(workspace_id, user_id)
        return role == 'admin'
    
    @staticmethod
    def is_workspace_member(workspace_id: str, user_id: str) -> bool:
        """Verifica si un usuario es miembro del workspace"""
        role = WorkspaceService.check_user_role(workspace_id, user_id)
        return role is not None

```

## Permisos de Workspace

```python
# app/auth/permissions.py
from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity
from app.services.workspace_service import WorkspaceService

def workspace_admin_required(f):
    """Decorador para requerir permisos de administrador de workspace"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_jwt_identity()
        workspace_id = kwargs.get('workspace_id')
        
        if not WorkspaceService.is_workspace_admin(workspace_id, current_user):
            return jsonify({"error": "Se requieren permisos de administrador para esta acción"}), 403
            
        return f(*args, **kwargs)
    return decorated_function

def workspace_member_required(f):
    """Decorador para requerir que el usuario sea miembro del workspace"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_jwt_identity()
        workspace_id = kwargs.get('workspace_id')
        
        if not WorkspaceService.is_workspace_member(workspace_id, current_user):
            return jsonify({"error": "Debe ser miembro del workspace para acceder"}), 403
            
        return f(*args, **kwargs)
    return decorated_function

```


## API de Workspaces

```python
# app/api/workspaces.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.workspace_service import WorkspaceService
from app.auth.permissions import workspace_admin_required, workspace_member_required

workspace_bp = Blueprint('workspaces', __name__)

@workspace_bp.route('/', methods=['POST'])
@jwt_required()
def create_workspace():
    """Endpoint para crear un nuevo workspace"""
    current_user = get_jwt_identity()
    data = request.get_json()
    
    workspace, error = WorkspaceService.create_workspace(data, current_user)
    
    if error:
        return jsonify({"error": error}), 400
        
    return jsonify({
        "message": "Workspace creado exitosamente",
        "workspace": workspace.to_dict()
    }), 201

@workspace_bp.route('/', methods=['GET'])
@jwt_required()
def get_user_workspaces():
    """Endpoint para obtener todos los workspaces del usuario actual"""
    current_user = get_jwt_identity()
    
    workspaces = WorkspaceService.get_workspaces_by_user(current_user)
    
    return jsonify([workspace.to_dict() for workspace in workspaces]), 200

@workspace_bp.route('/<workspace_id>', methods=['GET'])
@jwt_required()
@workspace_member_required
def get_workspace(workspace_id):
    """Endpoint para obtener un workspace específico"""
    workspace = WorkspaceService.get_workspace_by_id(workspace_id)
    
    if not workspace:
        return jsonify({"error": "Workspace no encontrado"}), 404
        
    return jsonify(workspace.to_dict(include_members=True)), 200

@workspace_bp.route('/<workspace_id>', methods=['PUT'])
@jwt_required()
@workspace_admin_required
def update_workspace(workspace_id):
    """Endpoint para actualizar un workspace"""
    data = request.get_json()
    
    workspace, error = WorkspaceService.update_workspace(workspace_id, data)
    
    if error:
        return jsonify({"error": error}), 400
        
    return jsonify({
        "message": "Workspace actualizado exitosamente",
        "workspace": workspace.to_dict()
    }), 200

@workspace_bp.route('/<workspace_id>', methods=['DELETE'])
@jwt_required()
@workspace_admin_required
def delete_workspace(workspace_id):
    """Endpoint para eliminar un workspace"""
    success, error = WorkspaceService.delete_workspace(workspace_id)
    
    if not success:
        return jsonify({"error": error}), 400
        
    return jsonify({"message": "Workspace eliminado exitosamente"}), 200

@workspace_bp.route('/<workspace_id>/members', methods=['POST'])
@jwt_required()
@workspace_admin_required
def add_member(workspace_id):
    """Endpoint para agregar un miembro al workspace"""
    data = request.get_json()
    
    user_id = data.get('user_id')
    role = data.get('role', 'member')
    
    if not user_id:
        return jsonify({"error": "ID de usuario requerido"}), 400
        
    success, error = WorkspaceService.add_member(workspace_id, user_id, role)
    
    if not success:
        return jsonify({"error": error}), 400
        
    return jsonify({"message": "Miembro agregado exitosamente"}), 200

@workspace_bp.route('/<workspace_id>/members/<user_id>', methods=['PUT'])
@jwt_required()
@workspace_admin_required
def update_member_role(workspace_id, user_id):
    """Endpoint para actualizar el rol de un miembro"""
    data = request.get_json()
    
    role = data.get('role')
    if not role:
        return jsonify({"error": "Rol requerido"}), 400
        
    success, error = WorkspaceService.update_member_role(workspace_id, user_id, role)
    
    if not success:
        return jsonify({"error": error}), 400
        
    return jsonify({"message": "Rol de miembro actualizado exitosamente"}), 200

@workspace_bp.route('/<workspace_id>/members/<user_id>', methods=['DELETE'])
@jwt_required()
@workspace_admin_required
def remove_member(workspace_id, user_id):
    """Endpoint para eliminar un miembro del workspace"""
    success, error = WorkspaceService.remove_member(workspace_id, user_id)
    
    if not success:
        return jsonify({"error": error}), 400
        
    return jsonify({"message": "Miembro eliminado exitosamente"}), 200

@workspace_bp.route('/<workspace_id>/members', methods=['GET'])
@jwt_required()
@workspace_member_required
def get_workspace_members(workspace_id):
    """Endpoint para obtener todos los miembros de un workspace"""
    workspace = WorkspaceService.get_workspace_by_id(workspace_id)
    
    if not workspace:
        return jsonify({"error": "Workspace no encontrado"}), 404
        
    # Extraer información de miembros
    members_data = []
    for member in workspace.members:
        role = workspace.get_member_role(member)
        members_data.append({
            'id': member.public_id,
            'username': member.username,
            'email': member.email,
            'role': role,
            'avatar_url': member.avatar_url
        })
        
    return jsonify(members_data), 200

```

## Actualización de app/__init__.py

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
    
    # Registrar blueprint de workspaces
    from app.api.workspaces import workspace_bp
    app.register_blueprint(workspace_bp, url_prefix='/api/workspaces')
    
    # Agregar más blueprints aquí a medida que se desarrollen
    
    @app.route('/health')
    def health_check():
        return {"status": "healthy"}, 200
        
    return app

```
---

## Próximos pasos

Con el módulo de workspaces implementado, ahora podemos avanzar a:

1. Implementar el módulo de proyectos (listas)
2. Crear el módulo de tareas
3. Desarrollar las diferentes vistas.








