##### 모듈 #####
# from 모듈이름 import 모듈함수
import os
import jwt
import pymysql # mysql을 python에서 사용할 시 추가
from flask import Flask, render_template, redirect, request, session, url_for, jsonify
from flask_jwt_extended import *
from datetime import datetime, timedelta
import datetime
from config import HOST, USER, PASSWORD, DB, CHARSET, APP_SECRET_KEY, JWT_SECRET_KEY # 환경변수
####################

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

##### JWT 설정 #####
app.config.update(
    DEBUG = True,
    JWT_SECRET_KEY = JWT_SECRET_KEY
)
jwtm = JWTManager(app)
####################

##### DB 연결 #####
# MySQL 연결
conn = pymysql.connect(host=HOST, user=USER, password=PASSWORD, db=DB, charset=CHARSET)
# 커서 객체 생성 (커서 객체에 DB작업을 위한 함수들이 포함)
cur = conn.cursor()
####################

# 라우팅: route() 데코레이터는 Flask에서 URL 방문할 때 준비된 함수가 트리거되도록 바인딩
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'GET':
        return render_template("index.html")
    elif request.method == 'POST':
        return redirect('/logout')

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

        # 모두 입력해야 가입 가능
        if not(id and pw and pwc and nickname):
            return "입력되지 않은 정보가 있습니다."
        # 비밀번호 일치해야 가입 가능
        elif pw != pwc:
            return "비밀번호가 일치하지 않습니다."
        # 입력이 정상일 경우 하위 명령 실행 (DB에 입력된다.)
        else:
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 요청 메소드가 GET일 때
    if request.method == 'GET':
        # login html파일을 렌더링
        return render_template("login.html")
    # 요청 메소드가 POST일 때
    elif request.method == 'POST':
        id = request.form['id']
        pw = request.form['pw']

        if len(id) == 0 or len(pw) == 0:
            return "입력되지 않은 정보가 있습니다."
        else:
            # 실행할 SQL문 정의
            sql = '''
            select * from member
            where id=%s
            and pw=%s
            '''
            vals = (id, pw)
            cur.execute(sql, vals)
            res = cur.fetchone();

            if res:
                print(res) # (Member_num, ID, PW, Nickname, IsAdmin)
                print(res[1]) # ID

                access_token = create_access_token(identity=res[1], expires_delta=False, fresh=timedelta(minutes=15))
                print(access_token) # 인코딩된 토큰

                return redirect('/')
            else:
                return "잘못된 정보입니다."

# 토큰이 존재하면 블록리스트에 토큰을 넣음
@jwtm.token_in_blocklist_loader
def check_it_token_is_revoked(jwt_header, jwt_paypoad):
    jti = jwt_paypoad['jti']
    return jti in jwt_blocklist

# 토큰을 저장하기 위한 변수 초기화
jwt_blocklist = set()

# 토큰이 존재하면 코드 수행
# jti: 토큰을 고유ID로 저장
# jwt_blocklist: 토큰의 고유ID, 토큰 유지 기간, 토큰 유지 기간 설정 여부
# jwt_bloacklist에 jti만 넣어주고 생략하면 토큰 즉시 파괴
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    jwt_blocklist.add(jti)
    return {'message' : 'Log Out'}

@app.route('/board')
def board():
    return render_template("board.html")

@app.route('/board/write', methods=['POST'])
@jwt_required()
def write():
    cur_user = get_jwt_identity()
    print(cur_user)

    if cur_user is None:
        return "user only!"
    else:
        writer_num = request.form['writer_num']
        writer_nickname = request.form['writer_nickname']
        title = request.form['title']
        contents = request.form['contents']

        # 실행할 SQL문 정의
        sql = '''
        insert into board(writer_num, writer_nickname, title, contents)
        values(%s, %s, %s, %s);
        '''
        # SQL문에 들어갈 변수(가입 시 입력받을 값들)
        vals = (writer_num, writer_nickname, title, contents)
        # cursor.execute(sql): sql문 실행
        cur.execute(sql, vals)
        # commit 필요한 작업일 경우 commit
        conn.commit()
        return "작성 완료!"

@app.route('/board/modify', methods=['POST'])
@jwt_required()
def modify():
    cur_user = get_jwt_identity()

    post_num = request.form['post_num']
    ### writer_num = request.form['writer_num']

    # 실행할 SQL문 정의
    # sql = "select date_format(cdate, '%%h') From board where post_num=%s;"
    sql = '''
    select cdate from board where post_num=%s;
    '''
    # SQL문에 들어갈 변수(가입 시 입력받을 값들)
    vals = (post_num)
    # cursor.execute(sql): sql문 실행
    cur.execute(sql, vals)
    credate = cur.fetchone(); # sql문 돌리고 뽑은 작성시각
    now = datetime.datetime.now() # 현재시각
    delta = datetime.timedelta(hours = 1) # 1시간
    print(now)
    print(delta)
    print(credate[0])
    print(now > credate[0]+delta) # 현재시각이 작성시각+1시간보다 크면 true
    print(now - credate[0]) # 현재시각-작성시각
    print(credate[0] + delta) # 현재시각+1시간
    # print(hour[0]+'1')

    ### sql_writer = '''
    # select writer_nickname from board where writer_num=%s;
    # '''
    # vals_writer = (writer_num)
    # cur.execute(sql_writer, vals_writer)
    # writer_nick = cur.fetchone();
    # print(writer_nick)
    ### print(writer_nick[0])
    
    if cur_user is None:
        return "user only!"
    elif now > credate[0]+delta:
        return "1시간 지나서 수정 안돼"
    ### elif cur_user != writer_nick:
    ###     return "작성자도 아니면서 수정은 좀.."
    else:
        title = request.form['title']
        contents = request.form['contents']
        post_num = request.form['post_num']

        # 실행할 SQL문 정의
        sql = '''
        update board
        set title=%s, contents=%s
        where post_num=%s
        '''
        # SQL문에 들어갈 변수(가입 시 입력받을 값들)
        vals = (title, contents, post_num)
        # cursor.execute(sql): sql문 실행
        cur.execute(sql, vals)
        # commit 필요한 작업일 경우 commit
        conn.commit()
        return "수정 완료!"

@app.route('/board/delete', methods=['DELETE'])
@jwt_required()
def delete():
    cur_user = get_jwt_identity()

    param = request.get_json()
    post_num = param['post_num']

    # 실행할 SQL문 정의
    # sql = "select date_format(cdate, '%%h') From board where post_num=%s;"
    sql = '''
    select cdate from board where post_num=%s;
    '''
    # SQL문에 들어갈 변수(가입 시 입력받을 값들)
    vals = (post_num)
    # cursor.execute(sql): sql문 실행
    cur.execute(sql, vals)
    credate = cur.fetchone(); # sql문 돌리고 뽑은 작성시각
    now = datetime.datetime.now() # 현재시각
    delta = datetime.timedelta(hours = 3) # 3시간
    #delta = datetime.timedelta(seconds = 5) # 실험용 5초

    print(now)
    print(credate[0])
    print(credate[0]+delta)
    print(now > credate[0]+delta) # 현재시각이 작성시각+3시간보다 크면 true

    if cur_user is None:
        return "user only!"
    elif now > credate[0]+delta:
        return "3시간 지나면 삭제도 안돼(실험: 5초)"
    else:
        param = request.get_json()
        post_num = param['post_num']

        # 실행할 SQL문 정의
        sql = '''
        delete from board
        where post_num=%s
        '''
        # SQL문에 들어갈 변수(가입 시 입력받을 값들)
        vals = (post_num)
        # cursor.execute(sql): sql문 실행
        cur.execute(sql, vals)
        # commit 필요한 작업일 경우 commit
        conn.commit()
        return "삭제 완료!"


# 직접 이 파일을 실행했을 때는 if문 문장이 참이 되어 app.run() 수행
if __name__ == '__main__':
    # debug=True 명시하면 해당 파일 코드 수정 시 Flask가 변경된 것을 인식하고 다시 시작
    app.run(debug=True)