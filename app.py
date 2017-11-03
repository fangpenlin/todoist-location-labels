import sys
import os
import uuid

import requests
from flask import Flask
from flask import request
from flask import json
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'sqlite:////tmp/test.db'
)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    oauth_token = db.Column(db.String(64), nullable=True)


class LocationLabel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    user= db.relationship(
        'User',
        backref=db.backref('location_labels', lazy='dynamic')
    )
    label_id = db.Column(db.Integer, nullable=False, index=True)
    name = db.Column(db.String, nullable=False)
    long = db.Column(db.Float, nullable=False)
    lat = db.Column(db.Float, nullable=False)
    loc_trigger = db.Column(db.String, nullable=False)
    radius = db.Column(db.Float, nullable=False)


@app.route("/")
def hello():
    return "Hello World!"


@app.route('/webhook', methods=['POST'])
def webhook():
    event = request.json
    if event['event_name'] not in ['item:added', 'item:updated']:
        return ''
    initiator = event['initiator']
    event_data = event['event_data']
    user = User.query.get(initiator['id'])
    for label_id in event_data['labels']:
        loc_labels = user.location_labels.filter_by(label_id=label_id).all()
        if not loc_labels:
            continue
        for loc_label in loc_labels:
            temp_id = uuid.uuid4().hex
            req_uuid = uuid.uuid4().hex
            resp = requests.post('https://todoist.com/api/v7/sync', data=dict(
                token=user.oauth_token,
                commands=json.dumps([
                    dict(
                        type='reminder_add',
                        temp_id=temp_id,
                        uuid=req_uuid,
                        args=dict(
                            item_id=event_data['id'],
                            type='location',
                            name=loc_label.name,
                            loc_long=loc_label.long,
                            loc_lat=loc_label.lat,
                            loc_trigger=loc_label.loc_trigger,
                            radius=loc_label.radius 
                        )
                    )
                ])
            ))
            print(resp.json())
            resp.raise_for_status()
    return ''

if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == 'initdb':
        db.create_all()
    else:
        app.run(debug=True, use_reloader=True)
