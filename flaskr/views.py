import os
import json
import logging

from werkzeug import check_password_hash, generate_password_hash
from flask import Flask, jsonify, request, redirect, url_for, render_template, flash, abort, session
from flaskr import app, client

logger = logging.getLogger()

USERS_TABLE = os.environ['USERS_TABLE']
ENTRIES_TABLE = os.environ['ENTRIES_TABLE']

@app.route('/')
def show_entries():
    entries = client.scan(TableName=ENTRIES_TABLE)
    return render_template('show_entries.html', entries=entries['Items'])

@app.route("/add", methods=["POST"])
def add_entry():
    logger.warn("DEBUG DEBUG DEBUG entry add")
    title = request.form['title']
    text = request.form['text']
    if not title or not text:
        return jsonify({'error': 'Please provide title and text'}), 400

    resp = client.put_item(
        TableName=ENTRIES_TABLE,
        Item={
            'title': {'S': title },
            'text': {'S': text }
        }
    )

    return redirect(url_for('show_entries'))

@app.route('/users/create/', methods=['GET', 'POST'])
def user_create():
    if request.method == 'POST':
        logger.warn("DEBUG DEBUG DEBUG user_create")
        id=request.form['id']
        name=request.form['name']
        email=request.form['email']
        password=request.form['password']

        if password:
            password = password.strip()
        _password = generate_password_hash(password)

        resp = client.put_item(
            TableName=USERS_TABLE,
            Item={
                'id': {'S': id },
                'name': {'S': name },
                'email': {'S': email },
                'password': {'S': _password }
            }
        )

        return redirect(url_for('user_list'))
    return render_template('user/edit.html')

@app.route('/users/')
def user_list():
    users = client.scan(TableName=USERS_TABLE)
    return render_template('user/list.html', users=users['Items'])

@app.route('/users/<int:user_id>/')
def user_detail(user_id):
    user = client.get_item(
        TableName=USERS_TABLE,
        Key={
            'id': {'S': str(user_id)}
        }
    )
    return render_template('user/detail.html', user=user['Item'])

@app.route('/users/<int:user_id>/edit/', methods=['GET', 'POST'])
def user_edit(user_id):
    logger.warn("DEBUG DEBUG DEBUG user_edit")

    user = client.get_item(
        TableName=USERS_TABLE,
        Key={
            'id': {'S': str(user_id)}
        }
    )
    if user is None:
        abort(404)

    if request.method == 'POST':
        name=request.form['name']
        email=request.form['email']
        password=request.form['password']

        if password:
            password = password.strip()
        _password = generate_password_hash(password)

        resp = client.update_item(
            TableName=USERS_TABLE,
            Key={
                'id': {'S': str(user_id) },
            },
            ExpressionAttributeValues={
                ':email': {'S': email },
                ':password': {'S': _password }
            },
            UpdateExpression='SET email = :email, password = :password',
            ReturnValues='UPDATED_NEW'
        )
        return redirect(url_for('user_detail', user_id=user_id))
    return render_template('user/edit.html', user=user)

@app.route('/users/<int:user_id>/delete/', methods=['DELETE'])
def user_delete(user_id):
    logger.warn("DEBUG DEBUG DEBUG user_delete")
    user = client.get_item(
        TableName=USERS_TABLE,
        Key={
            'id': {'S': str(user_id)}
        }
    )
    if user is None:
        response = jsonify({'status': 'Not Found'})
        response.status_code = 404
        return response

    user = client.delete_item(
        TableName=USERS_TABLE,
        Key={
            'id': {'S': str(user_id)}
        }
    )
    return jsonify({'status': 'OK'})
#    return redirect(url_for('user_list'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        logger.warn("DEBUG DEBUG DEBUG login")
        id = request.form['id']
        logger.warn(id)
        user = client.get_item(
            TableName=USERS_TABLE,
            Key={
                 'id': {'S': str(id)}
            }
        )
        logger.warn("DEBUG DEBUG DEBUG 1")
        if user is None:
            logger.warn("DEBUG DEBUG DEBUG no User")
            flash('Invalid email or password')

        logger.warn("DEBUG DEBUG DEBUG 2")
        logger.warn(user['Item']['password']['S'])
        logger.warn(request.form['password'])
        authenticated = check_password_hash(user['Item']['password']['S'], request.form['password'])

        logger.warn("DEBUG DEBUG DEBUG 3")
        logger.warn(authenticated)
        if authenticated:
            logger.warn("DEBUG DEBUG DEBUG 4")
            logger.warn(str(user['Item']['email']['S']))
            session['user_id'] = str(user['Item']['email']['S'])
            logger.warn("DEBUG DEBUG DEBUG 5")
            flash('You were logged in')
            return redirect(url_for('show_entries'))
        else:
            flash('Invalid email or password')
        logger.warn("DEBUG DEBUG DEBUG 6")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You were logged out')
    return redirect(url_for('show_entries'))

