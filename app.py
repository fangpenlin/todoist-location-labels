import sys
import os
import logging
import urllib.parse
import base64
import itertools

import todoist
import requests
from flask import Flask
from flask import request
from flask import json
from flask import render_template
from flask import redirect
from flask import session
from flask import abort
from flask import url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

if 'DYNO' in os.environ:
    # app.logger.addHandler(logging.StreamHandler(sys.stdout))
    app.logger.setLevel(logging.INFO)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'sqlite:///test.db'
)
app.secret_key = os.environ['APP_SECRET_KEY']
db = SQLAlchemy(app)
client_id = os.environ['CLIENT_ID']
client_secret = os.environ['CLIENT_SECRET']
google_map_api_key = os.environ['GOOGLE_MAP_API_KEY']
google_analytics_id = os.environ.get('GOOGLE_ANALYTICS_ID')


class User(db.Model):
    id = db.Column(db.BigInteger, primary_key=True)
    oauth_token = db.Column(db.String(64), nullable=True)


class LocationLabel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('user.id'),
        nullable=False)
    user= db.relationship(
        'User',
        backref=db.backref('location_labels', lazy='dynamic')
    )
    label_id = db.Column(db.BigInteger, nullable=False, index=True)
    name = db.Column(db.String, nullable=False)
    long = db.Column(db.Float, nullable=False)
    lat = db.Column(db.Float, nullable=False)
    loc_trigger = db.Column(db.String, nullable=False)
    radius = db.Column(db.Float, nullable=False)


def get_current_user():
    user_id = session.get('user_id')
    if user_id is None:
        abort(401)
    user = User.query.get(user_id)
    if user is None:
        abort(401)
    return user


@app.route('/')
def index():
    user_id = session.get('user_id')
    kwargs = {
        'google_map_api_key': google_map_api_key,
        'google_analytics_id': google_analytics_id
    }
    if user_id is not None:
        user = User.query.get(user_id)
        labels = requests.get(
            'https://api.todoist.com/rest/v1/labels',
            params=dict(token=user.oauth_token)
        ).json()
        kwargs['labels'] = labels
        api = todoist.TodoistAPI(user.oauth_token)
        api.sync()
        kwargs['user_full_name'] = api.user.get('full_name')
        # map from label id to location labels
        location_labels = {}
        for label_id, group in itertools.groupby(
            user.location_labels.all(),
            lambda ll: ll.label_id
        ):
            location_labels[label_id] = list(group)
        kwargs['location_labels'] = location_labels
    return render_template('index.html', **kwargs)


@app.route('/authorize')
def authorize():
    state = base64.b64encode(os.urandom(32)).decode('utf8')
    session['oauth_secret_state'] = state
    return redirect(
        'https://todoist.com/oauth/authorize?' + urllib.parse.urlencode(dict(
            client_id=client_id,
            scope='data:read_write,data:delete',
            state=state,
        ))
    )


@app.route('/oauth/redirect')
def oauth_redirect():
    state = session['oauth_secret_state']
    if request.args.get('state') != state:
        return abort(401)
    code = request.args.get('code')
    if not code:
        return abort(400)
    resp = requests.post('https://todoist.com/oauth/access_token', data=dict(
        client_id=client_id,
        client_secret=client_secret,
        code=code,
        redirect_uri=url_for('authorize', _external=True),
    ))
    resp.raise_for_status()
    access_token = resp.json()['access_token']
    api = todoist.TodoistAPI(access_token)
    api.sync()
    user_id = api.user.get_id()
    user = User.query.get(user_id)
    if user is None:
        user = User(id=user_id, oauth_token=access_token)
        db.session.add(user)
    else:
        user.oauth_token = access_token
    db.session.commit()
    session['user_id'] = user.id
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    del session['user_id']
    return redirect(url_for('index'))


@app.route('/delete_label_location/<int:label_location_id>')
def delete_label_location(label_location_id):
    user = get_current_user()
    label_location = LocationLabel.query.get(label_location_id)
    if label_location is None:
        return abort(404)
    if label_location.user.id != user.id:
        return abort(401)

    db.session.delete(label_location)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/create_label_location', methods=['POST'])
def create_label_location():
    user = get_current_user()
    label_id = int(request.form['label_id'])
    trigger = request.form['trigger']
    address = request.form['address']
    lat = float(request.form['lat'])
    long = float(request.form['long'])
    radius = float(request.form.get('radius', 300))
    location_label = LocationLabel(
        user=user,
        label_id=label_id,
        loc_trigger=trigger,
        long=long,
        lat=lat,
        name=address,
        radius=radius,
    )
    db.session.add(location_label)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/webhook', methods=['POST'])
def webhook():
    event = request.json
    # app.logger.info('Full event: %s', event)
    if event['event_name'] not in ['item:added', 'item:updated']:
        return ''
    initiator = event['initiator']
    event_data = event['event_data']
    app.logger.info(
        'Received webhook event %s for %s with info: %s',
        event['event_name'],
        event_data['id'],
        event_data
    )
    user = User.query.get(initiator['id'])
    api = todoist.TodoistAPI(user.oauth_token)
    api.sync()
    item_reminders = list(filter(lambda x: x['type'] == 'location' and x['item_id']==event_data['id'] , api.reminders.all()))
    not_used_location_labels = user.location_labels.filter(~LocationLabel.label_id.in_(event_data['labels'])).all()
    to_be_deleted_reminders = list(filter(lambda x: x['name'] in map(lambda y: y.name, not_used_location_labels) and x['loc_trigger'] in map(lambda y: y.loc_trigger, not_used_location_labels) and x['radius'] in map(lambda y: y.radius, not_used_location_labels), item_reminders))
    for reminder in to_be_deleted_reminders:
        app.logger.info(
            'Reminder found that should be deleted: %s, deleting',
            reminder['id']
        )
        api.reminders.delete(reminder['id']);
    for label_id in event_data['labels']:
        loc_labels = user.location_labels.filter_by(label_id=label_id).all()
        if not loc_labels:
            app.logger.info(
                'No location labels found for label %s, skip',
                label_id
            )
            continue
        for loc_label in loc_labels:
            app.logger.info(
                'Adding location reminder for item %s from location label %s',
                event_data['id'],
                loc_label.id,
            )
            api_reminders = filter(lambda x: x['item_id'] == event_data['id'] and x['type'] == 'location', api.state['reminders'])
            existing_reminder = list(filter (lambda x: x['name'] == loc_label.name and x['loc_trigger'] == loc_label.loc_trigger and x['radius'] == loc_label.radius, api_reminders))
            if existing_reminder:
                app.logger.info(
                    'Not adding location reminder for item %s from location label %s, does already exist!',
                    event_data['id'],
                    loc_label.id,
                )
                continue

            api.reminders.add(
                event_data['id'],
                type='location',
                name=loc_label.name,
                loc_lat=str(loc_label.lat),
                loc_long=str(loc_label.long),
                loc_trigger=loc_label.loc_trigger,
                radius=loc_label.radius
            )
            app.logger.info(
                'Location reminder added for item %s from location label %s',
                event_data['id'],
                loc_label.id,
            )
    api.commit()
    return 'ok'

if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == 'initdb':
        db.create_all()
    else:
        app.run(debug=True, use_reloader=True)
