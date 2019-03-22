from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy
app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SimilarityDB
users = db["Users"]

def retresp(code,msg):
    retJson = {
        'status':code,
        'msg': msg
    }
    return retJson

def UserExist(username):
    if users.find({"Username":username}).count() == 0:
        return False
    else:
        return True

class Register(Resource):
    def post(self):
        #Step 1 is to get posted data by the user
        postedData = request.get_json()

        #Get the data
        username = postedData["username"]
        password = postedData["password"] #"123xyz"

        if UserExist(username):
            # retJson = {
            #     'status':301,
            #     'msg': 'Invalid Username'
            # }
            return retresp(301,'Invalid Username')

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        #Store username and pw into the database
        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Tokens":6
        })

        """retJson = {
            "status": 200,
            "msg": "You successfully signed up for the API"
        }"""
        return retresp(200,"You successfully signed up for the API")

def verifyPw(username, password):
    if not UserExist(username):
        return False

    hashed_pw = users.find({
        "Username":username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def countTokens(username):
    tokens = users.find({
        "Username":username
    })[0]["Tokens"]
    return tokens

class Detect(Resource):
    def post(self):
        #Step 1 get the posted data
        postedData = request.get_json()

        #Step 2 is to read the data
        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        if not UserExist(username):
            # retJson = {
            #     'status':301,
            #     'msg': "Invalid Username"
            # }
            return retresp(301,"Invalid Username")
        #Step 3 verify the username pw match
        correct_pw = verifyPw(username, password)

        if not correct_pw:
            # retJson = {
            #     "status":302,
            #     "msg": "Incorrect Password"
            # }
            return retresp(302,"Incorrect Password")
        #Step 4 Verify user has enough tokens
        num_tokens = countTokens(username)
        if num_tokens <= 0:
            # retJson = {
            #     "status": 303,
            #     "msg": "You are out of tokens, please refill!"
            # }
            return retresp(303,"You are out of tokens, please refill!")

        #Calculate edit distance between text1, text2

        nlp = spacy.load('en_core_web_sm')
        text1 = nlp(text1)
        text2 = nlp(text2)

        ratio = text1.similarity(text2)

        retJson = {
            "status":200,
            "ratio": ratio,
            "msg":"Similarity score calculated successfully"
        }

        #Take away 1 token from user
        current_tokens = countTokens(username)
        users.update({
            "Username":username
        }, {
            "$set":{
                "Tokens":current_tokens-1
                }
        })

        return jsonify(retJson)

class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["admin_pw"]
        refill_amount = postedData["refill"]

        if not UserExist(username):
            # retJson = {
            #     "status": 301,
            #     "msg": "Invalid Username"
            # }
            return retresp(301,"Invalid Username")

        correct_pw = "abc123"
        if not password == correct_pw:
            # retJson = {
            #     "status":304,
            #     "msg": "Invalid Admin Password"
            # }
            return retresp(304,"Invalid Admin pass")

        #MAKE THE USER PAY!
        users.update({
            "Username":username
        }, {
            "$set":{
                "Tokens":refill_amount
                }
        })

        # retJson = {
        #     "status":200,
        #     "msg": "Refilled successfully"
        # }
        return retresp(200,"Refilled successfully")


api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')
api.add_resource(Refill, '/refill')


if __name__=="__main__":
    app.run(host='0.0.0.0')
