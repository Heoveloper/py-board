import pymysql
from flask import Flask, jsonify

def error_handle(app:Flask):
    @app.errorhandler(pymysql.err.DataError)
    def handler_data_error(e):
        return jsonify({"result": False, "msg" : "최대 입력 길이 초과"}), 400
