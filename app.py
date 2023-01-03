# from 모듈이름 import 모듈함수
from flask import Flask, render_template, redirect, request, url_for

app = Flask(__name__)

# 라우팅: route() 데코레이터는 Flask에서 URL 방문할 때 준비된 함수가 트리거되도록 바인딩
# route() 데코레이터의 methods 인수로 POST를 지정해서 POST요청도 처리
@app.route('/')
def home():
    return render_template("index.html")

@app.route('/sign-up')
def signUp():
    return render_template("sign-up.html")

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/board')
def board():
    return render_template("board.html")

# 직접 이 파일을 실행했을 때는 if문 문장이 참이 되어 app.run() 수행
if __name__ == '__main__':
    # debug=True 명시하면 해당 파일 코드 수정 시 Flask가 변경된 것을 인식하고 다시 시작
    app.run(debug=True)