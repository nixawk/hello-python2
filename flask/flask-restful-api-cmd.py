#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask_restful import reqparse, abort, Api, Resource
from flask import Flask, request, jsonify

import subprocess
import threading


app = Flask(__name__)
api = Api(app)

parser = reqparse.RequestParser()
parser.add_argument('command')


class Command(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None
        self.stdout = ''
        self.stderr = ''

    def run(self, timeout):
        def target():
            # print 'Thread started'
            self.process = subprocess.Popen(self.cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            self.stdout, self.stderr = self.process.communicate()
            #print 'Thread finished'

        thread = threading.Thread(target=target)
        thread.start()

        thread.join(timeout)
        if thread.is_alive():
            # print 'Terminating process'
            self.process.terminate()
            thread.join()
        # print self.process.returncode


class API_COMMAND(Resource):

    # def get(self):
    #     command = request.args.get('command', '')
    #     return self.exec_command(command)

    #     # curl -v http://127.0.0.1:5000/api/cmd/?command=uname

    def post(self):
        args = parser.parse_args()
        command = args.get('command', '')
        return self.exec_command(command)

        # curl -v --data command=uname http://127.0.0.1:5000/api/cmd/

    def exec_command(self, command):
        if not command:
            abort(404, message="os command doesn't exist")
        cmd = Command(command)
        cmd.run(timeout=8)

        response = {
            "command": command,
            "stdout": cmd.stdout,
            "stderr": cmd.stderr
        }

        return jsonify(response)


if __name__ == '__main__':
    api.add_resource(API_COMMAND, '/api/cmd/')
    app.run()

# https://flask-restful.readthedocs.io/en/latest/quickstart.html
# https://stackoverflow.com/questions/1191374/using-module-subprocess-with-timeout