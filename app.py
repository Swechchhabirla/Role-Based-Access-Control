from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity



# Initialize Flask App
app = Flask(__name__)
@app.route('/some-protected-endpoint', methods=['GET'])
@jwt_required()
def protected():
    # Access the identity of the current user from the JWT
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# App Configurations

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/HP/flask_rbac/rbac.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Define Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class RolePermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id'))

# Initialize Database

with app.app_context():
    db.create_all()
    # Check if the permission already exists
    existing_permission = Permission.query.filter_by(name="Read").first()
    if not existing_permission:
        read_permission = Permission(name="Read")
        db.session.add(read_permission)
        db.session.commit()
    else:
        print("Permission 'Read' already exists.")


# Endpoint 1: User Registration
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password are required"}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], password=hashed_password, role_id=data.get('role_id'))
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201

# Endpoint 2: User Login
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        # Convert user ID to a string for the JWT token
        token = create_access_token(identity=str(user.id))
        return jsonify({"access_token": token}), 200
    return jsonify({"message": "Invalid credentials"}), 401


# Endpoint 3: Role Creation
@app.route('/roles/create', methods=['POST'])
@jwt_required()
def create_role():
    try:
        
        
        data = request.get_json()
        print(f"Received data: {data}")

        
        # Check if 'name' is provided and is a string
        role_name = data.get('name')
        if not isinstance(role_name, str):
            return jsonify({"msg": "Role name must be a string"}), 422

        # Create and save the role
        role = Role(name=role_name)
        db.session.add(role)
        db.session.commit()
        

        return jsonify({"message": "Role created successfully!"}), 201
    except Exception as e:
        print(e)

# Endpoint 4: Permission Assignment
@app.route('/roles/assign-permission', methods=['POST'])
@jwt_required()
def assign_permission():
    data = request.json
    try:
        # Fetch role and permission using db.session.get()
        role = db.session.get(Role, data.get('role_id'))
        permission = db.session.get(Permission, data.get('permission_id'))

        # Check if role or permission is missing
        if not role:
            return jsonify({"message": "Role not found"}), 404
        if not permission:
            return jsonify({"message": "Permission not found"}), 404

        # Create RolePermission association
        role_permission = RolePermission(role_id=role.id, permission_id=permission.id)
        db.session.add(role_permission)
        db.session.commit()
        return jsonify({"message": "Permission assigned successfully!"}), 200
    except Exception as e:
        print(e)
        return jsonify({"error": "An error occurred while assigning the permission"}), 500





# Run the App
if __name__ == "__main__":
    app.run()