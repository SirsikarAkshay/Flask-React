from enum import unique
from os import name
from flask import Flask, jsonify, make_response
from flask.globals import request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity,unset_jwt_cookies
from flask_sqlalchemy import SQLAlchemy
from marshmallow import fields
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.schema import ForeignKey, PrimaryKeyConstraint
from werkzeug.security import generate_password_hash, check_password_hash
#from flask_cors import CORS
from flask_marshmallow import Marshmallow

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://azrlfnltdwrany:e2a5ce5b8693b0ef7dab37bfdf5569eef27ee328fb78110c30e8f13f988d515d@ec2-54-156-60-12.compute-1.amazonaws.com:5432/daqn47k12p75k7'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#Setup the flask-jwt-extended extension
app.config['JWT_SECRET_KEY'] = "super_secret"

#cors = CORS(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)

#Declare the User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    username = db.Column(db.String(15))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(256))
    admin = db.Column(db.String(256))

    def __init__(self, username, email, password, admin):
        self.username=username,
        self.email=email,
        self.password=password
        self.admin=admin

class UserSchema(ma.Schema):
    class Meta:
        fields = ('username', 'email', 'password', 'admin')


#Declare the Restaurant model
class Restaurant(db.Model):
    __tablename__ = 'restaurant'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    location = db.Column(db.String(50))
    owner = db.Column(db.String(50))

    def __init__(self, name, location, owner):
        self.name = name
        self.location=location
        self.owner=owner

class RestaurantSchema(ma.Schema):
    class Meta:
        fields = ('id','name','location','owner')

restaurant_schema = RestaurantSchema()
restaurants_schema = RestaurantSchema(many=True)

#Declare the Food Model
class Food(db.Model):
    __tablename__ = 'food'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    category = db.Column(db.String(50))
    price = db.Column(db.Integer)
    restaurant_id = db.Column(db.Integer, ForeignKey('restaurant.id'))

    def __init__(self, name, category, price, restaurant_id):
        self.name = name
        self.category = category
        self.price = price
        self.restaurant_id = restaurant_id

class FoodSchema(ma.Schema):
    class Meta:
        fields = ('id','name','category','price','restaurant_id')

food_schema = FoodSchema()
foods_schema = FoodSchema(many=True)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    category = db.Column(db.String(50))
    price = db.Column(db.Integer)

    def __init__(self, name, category, price):
        self.name = name
        self.category = category
        self.price = price

class OrderSchema(ma.Schema):
    class Meta:
        fields = ('id','name','category','price')
    
order_schema = OrderSchema()
orders_schema = OrderSchema(many=True)



@app.route('/register' , methods=['GET', 'POST'])
def register():

    #Validate the user table and data.
    if request.method == 'POST':
        username = request.json['username']
        email=request.json['email']
        password=request.json['password']
        admin=request.json['admin']

        hashed_password = generate_password_hash(password=password, method='sha256')

        #Create a new user object using the form data.
        new_user = User(username,email, password=hashed_password, admin=admin)

        #Add the user to the database
        db.session.add(new_user)
        db.session.commit()
        return jsonify("Successfully registered")
    
    else:
        return 'Please register'

@app.route('/login', methods = ['POST'])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    user = User.query.filter_by(username=username).first()

    if user is None:
        return jsonify({"msg": "Bad Username or Password"}), 401

    if check_password_hash(user.password, password):
        #Create a new token with user id inside
        access_token = create_access_token(identity=user.id)
        return jsonify({"token":access_token,"admin":user.admin})

@app.route('/createRestaurant', methods = ['POST'])
@jwt_required()
def createRestaurant():

    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    data = request.get_json()
    name = data['name']
    location = data['location']
    owner = user.username

    new_restaurant = Restaurant(name, location ,owner)

    db.session.add(new_restaurant)
    db.session.commit()

    op = f'Restaurant {name} created by {owner} '
    return jsonify(op)

@app.route('/updateRestaurant/<id>', methods = ['PUT'])
@jwt_required()
def updateRestaurant(id):
    my_data = Restaurant.query.get(id)
    my_data.name = request.json['name']
    my_data.location = request.json['location']

    db.session.commit()
    return jsonify("Updated successfully")

@app.route('/deleteRestaurant/<id>', methods = ['POST'])
@jwt_required()
def deleteRestaurant(id):
    my_data = Restaurant.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
        
    return jsonify("Restaurant Removed")
 


@app.route('/displayRestaurants', methods = ['GET'])
@jwt_required()
def displayRestaurants():
    data = Restaurant.query.all()

    return restaurants_schema.jsonify(data)


@app.route('/createFood/<id>', methods = ['POST'])
@jwt_required()
def createFood(id):
    name=request.json['name']
    category=request.json['category']
    price=request.json['price']
    restaurant_id=id

    new_food = Food(name, category, price, restaurant_id)

    db.session.add(new_food)
    db.session.commit()

    return jsonify("Food Created successfully")


@app.route("/displayFood/<restaurant_id>", methods = ['GET', 'POST'])
@jwt_required()
def displayFood(restaurant_id):
    my_data = Food.query.filter_by(restaurant_id=restaurant_id).all()
    return foods_schema.jsonify(my_data)

@app.route("/updateFood/<id>", methods = ['PUT'])
@jwt_required()
def updateFood(id):
    my_data = Food.query.get(id)
    my_data.name = request.json['name']
    my_data.category = request.json['category']
    my_data.price = request.json['price']

    db.session.commit()
    return jsonify("Updated successfully")

@app.route("/deleteFood/<id>", methods = ['POST'])
@jwt_required()
def deleteFood(id):
    my_data = Food.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
        
    return "Restaurant Removed"
 



@app.route('/createOrder/<id>', methods = ['POST'])
@jwt_required()
def createOrder(id):
    my_food = Food.query.get(id)
    
    new_order = Order(my_food.name,my_food.category,my_food.price)
    db.session.add(new_order)

    db.session.commit()
    return "Added to cart successfully"



@app.route('/deleteCart/<id>', methods = ['POST'])
@jwt_required()
def deleteCart(id):
    my_data = Order.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
        
    return order_schema.jsonify(my_data)



@app.route('/displayCart', methods = ['GET', 'POST'])
@jwt_required()
def displayCart():
    data = Order.query.all()
    return orders_schema.jsonify(data)



@app.route('/logout', methods = ['POST'])
def logout():
    my_data = Order.query.delete()
    db.session.commit()
    return jsonify("Logout Successful")


if __name__ == '__main__':
    #Create the user table.
    db.create_all()

    #run the app
    app.run()












        

