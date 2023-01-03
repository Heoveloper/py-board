# from 모듈이름 import 모듈함수
#
import os
import pymysql # mysql을 python에서 사용할 시 추가
from flask import Flask, render_template, redirect, request, url_for
# from models import Member #일단 sqlalchemy 사용 안함

app = Flask(__name__)

# 라우팅: route() 데코레이터는 Flask에서 URL 방문할 때 준비된 함수가 트리거되도록 바인딩
@app.route('/')
def home():
    return render_template("index.html")

# route() 데코레이터의 methods 인수로 POST를 지정해서 POST요청도 처리
@app.route('/sign-up', methods=['GET', 'POST'])
def signUp():
    # 요청 메소드가 GET일 때
    if request.method == 'GET':
        # sign-up html파일을 렌더링
        return render_template("sign-up.html")
    # 요청 메소드가 POST일 때
    elif request.method == 'POST':
        id = request.form.get('id')
        pw = request.form.get('pw')
        pwc = request.form.get('pwc')
        nickname = request.form.get('nickname')

        if not(id and pw and pwc and nickname): # 모두 입력해야 가입 가능
            return "입력되지 않은 정보가 있습니다."
        elif pw != pwc: # 비밀번호 일치해야 가입 가능
            return "비밀번호가 일치하지 않습니다."
        else: # 입력이 정상일 경우 하위 명령 실행 (DB에 입력된다.)
            # MySQL 연결
            conn = pymysql.connect(host='127.0.0.1', user='root', password='admin1234', db='mydb', charset='utf8')
            # 커서 객체 생성 (커서 객체에 DB작업을 위한 함수들이 포함)
            cur = conn.cursor()
            # 실행할 SQL문 정의
            sql = '''
            insert into member(id, pw, nickname)
            values (%s, %s, %s);
            '''
            # SQL문에 들어갈 변수(가입 시 입력받을 값들)
            vals = (id, pw, nickname)
            # cursor.execute(sql): sql문 실행
            cur.execute(sql, vals)
            # commit 필요한 작업일 경우 commit
            conn.commit()
        
        # 가입완료 시 홈으로
        return redirect('/')
        

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