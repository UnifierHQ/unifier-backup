"""
Unifier - A sophisticated Discord bot uniting servers and platforms
Copyright (C) 2024  Green, ItsAsheer

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from flask import Flask, request, jsonify, abort
import ujson as json
import hashlib
from utils import log
import logging
import os
import sys
import secrets
import string
import base64
import time

app = Flask(__name__)
logger = log.buildlogger('unifier_backup','webapp',logging.INFO)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

with open('webapp_config.json', 'r') as file:
    config = json.load(file)

class KeyManager:
    def __init__(self, filename):
        self.__filename = filename
        try:
            with open(self.__filename, 'r') as file:
                self.__keys = json.load(file)
            if len(self.__keys) == 0:
                raise ValueError()
        except:
            self.__keys = []
        self.empty = len(self.__keys) == 0

    def generate_api_key(self):
        __key = ''
        for i in range(32):
            __letter = secrets.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits)
            __key += __letter
        self.add_key(__key)
        return __key

    def encrypt_string(self, hash_string):
        sha_signature = \
            hashlib.sha256(hash_string.encode()).hexdigest()
        return sha_signature

    def check_key(self, key):
        return self.encrypt_string(key) in self.__keys

    def add_key(self, key):
        self.__keys.append(self.encrypt_string(key))
        with open(self.__filename, 'w+') as file:
            json.dump(self.__keys, file)
        self.empty = len(self.__keys) == 0
        return len(self.__keys)


keymgr = KeyManager('keys.json')

if keymgr.empty:
    newkey = keymgr.generate_api_key()
    logger.warning('An API key was generated as there were no keys!')
    logger.warning('Your API key (DO NOT SHARE): '+newkey)

@app.before_request
def before_request():
    ipaddr = request.environ.get('REMOTE_ADDR')

    # Allow all if there's no allowed IPs
    if len(config['allowed_ips']) > 0:
        if not ipaddr in config['allowed_ips']:
            logger.debug(f'Rejecting {ipaddr}: IP not whitelisted')
            abort(403)

    # Check for API key
    try:
        api_key = dict(request.headers)['Authorization'].replace('Bearer ','',1)
        if not api_key:
            raise ValueError()
    except:
        logger.debug(f'Rejecting {ipaddr}: missing API key')
        abort(400)

    if api_key is None or not keymgr.check_key(api_key):
        logger.debug(f'Rejecting {ipaddr}: invalid API key, authentication failed')
        abort(401)

    logger.info(f'Accepting {ipaddr}: authentication successful')

@app.route('/api/v1/info', methods=['GET'])
def info():
    try:
        with open('backup.json', 'r') as file:
            backup_data = json.load(file)
    except:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'ok': True, 'data': backup_data}), 200

@app.route('/api/v1/backup',methods=['POST'])
def backup():
    data = request.json
    config_file = open('config.json', 'wb+')
    config_file.write(base64.b64decode(data['config'].encode()))
    config_file.close()
    data_file = open('data.json', 'wb+')
    data_file.write(base64.b64decode(data['data'].encode()))
    data_file.close()

    with open('backup.json', 'w+') as file:
        json.dump({'time': round(time.time()),'ivs': data['iv']}, file)
    logger.debug('Backed up data')
    return jsonify({'ok': True}), 200

@app.route('/api/v1/restore',methods=['GET'])
def restore():
    try:
        with open('backup.json', 'r') as file:
            backup_data = json.load(file)
        config_file = open('config.json', 'rb')
        configbytes: bytes = config_file.read()
        config_file.close()
        data_file = open('data.json', 'rb')
        databytes: bytes = data_file.read()
        data_file.close()
    except:
        return jsonify({'error': 'Not found'}), 404
    logger.info('Restored data')
    return jsonify({
        'ok': True,
        'config': base64.b64encode(configbytes).decode('ascii'),
        'data': base64.b64encode(databytes).decode('ascii'),
        'iv': backup_data['ivs']
    }), 200


if 'unifier.py' in os.listdir():
    logger.critical('Unifier installation detected - backup app cannot run here!')
    sys.exit(1)

if 'microfier.py' in os.listdir():
    logger.critical('Unifier Micro installation detected - backup app cannot run here!')
    sys.exit(1)

if __name__ == '__main__':
    logger.info(f'Starting Flask app')
    if config['custom_tls']:
        app.run(host='0.0.0.0', port=config['port'], ssl_context=tuple(config['tls_context']), debug=False)
    else:
        app.run(host='0.0.0.0', port=config['port'], debug=False)
