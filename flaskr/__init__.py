import boto3

from flask import Flask

app = Flask(__name__)
client = boto3.client('dynamodb')

#from flask import Flask
#from flask_sqlalchemy import SQLAlchemy
#import boto3
#
#app = Flask(__name__)
app.config.from_object('flaskr.config')
#
#db = SQLAlchemy(app)
#
## serverless.ymlから変数を受け取る
##TODOS_TABLE = os.environ['TODOS_TABLE']
#
## boto3はawsにアクセスするライブラリ
## dynamodbのテーブルを取得
#dynamodb = boto3.resource('dynamodb')
##table = dynamodb.Table(TODOS_TABLE)
#table = dynamodb.Table('usersTable')
#
#

import flaskr.views

