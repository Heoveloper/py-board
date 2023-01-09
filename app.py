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
from random import randrange # 난수 생성에 필요한 모듈
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

##### 현재 유저 #####
# @jwt_required(optional=True)
# def curUser():
#     cur_user = get_jwt_identity()

#     return jsonify(cur_user)
####################

##### 관리자 #####
@app.route('/admin')
@jwt_required(optional=True)
def isAdmin():
    # global cur_user
    # cur_user = curUser()
    cur_user = get_jwt_identity()

    sql = f"select is_admin from member where member_num={cur_user}"
    cur.execute(sql)
    conn.commit()

    isAdmin = cur.fetchone()
    print(f'현재 접속 회원의 관리자 여부: {isAdmin[0]}')
    
    return jsonify(isAdmin[0])
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
        # pwc = request.form.get('pwc')
        nickname = request.form.get('nickname')

        # [유효성 검사 부분]
        # 모두 입력해야 가입 가능
        # if not(id and pw and pwc and nickname):
        #     return "입력되지 않은 정보가 있습니다."
        # 비밀번호 일치해야 가입 가능
        # elif pw != pwc:
        #     return "비밀번호가 일치하지 않습니다."
        # 입력이 정상일 경우 하위 명령 실행 (DB에 입력된다.)

        # 실행할 SQL문 정의
        sql = f"insert into member (id, pw, nickname) values ('{id}', '{pw}', '{nickname}');"
        # cursor.execute(sql): sql문 실행
        cur.execute(sql)
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
            sql = f"select * from member where id='{id}' and pw='{pw}'"
            cur.execute(sql)

            res = cur.fetchone();
            if res:
                print(f'res: {res}') # (Member_num, ID, PW, Nickname, IsAdmin)
                print(f'res[0]: {res[0]}') # Member_num

                access_token = create_access_token(identity=res[0], expires_delta=False, fresh=timedelta(minutes=15))
                print(f'loginToken: {access_token}') # 인코딩된 토큰

                return redirect('/')
            else:
                return "잘못된 정보입니다."

########## 로그아웃 ##########
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
    cur_user = get_jwt_identity()

    jti = get_jwt()['jti']
    jwt_blocklist.add(jti)

    print(f"로그아웃한 회원의 번호: {cur_user}")
    return {'message' : 'Log Out'}
##############################

@app.route('/board')
def board():
    return render_template("board.html")

@app.route('/board/write', methods=['POST'])
@jwt_required()
def write():
    cur_user = get_jwt_identity()
    print(f'cur user: {cur_user}')

    if cur_user is None:
        return "user only!"
    else:
        writer_num = request.form['writer_num']
        writer_nickname = request.form['writer_nickname']
        title = request.form['title']
        contents = request.form['contents']

        # 실행할 SQL문 정의
        sql = f'''
        insert into board(writer_num, writer_nickname, title, contents)
        values ('{writer_num}', '{writer_nickname}', '{title}', '{contents}')
        '''
        # cursor.execute(sql): sql문 실행
        cur.execute(sql)
        # commit 필요한 작업일 경우 commit
        conn.commit()
        return "작성 완료!"

@app.route('/board/modify', methods=['POST'])
@jwt_required()
def modify():
    cur_user = get_jwt_identity()
    admin = isAdmin()

    title = request.form['title'] # 제목
    contents = request.form['contents'] # 내용
    post_num = request.form['post_num'] # 게시글 번호

    now = datetime.datetime.now() # 현재시각
    delta = datetime.timedelta(hours = 1) # 1시간

    # 실행할 SQL문 정의
    # sql = "select date_format(cdate, '%%h') From board where post_num=%s;"
    sql = f"select cdate from board where post_num={post_num}"
    # cursor.execute(sql): sql문 실행
    cur.execute(sql)

    credate = cur.fetchone(); # sql문 돌리고 뽑은 작성시각
    print(f'now: {now}')
    print(f'delta: {delta}')
    print(f'credate[0]: {credate[0]}')

    print(f'현재시각 > 작성시각 + 1시간: {now > credate[0] + delta}')
    print(f'현재시각 - 작성시각: {now - credate[0]}')
    print(f'현재시각 + 1시간: {credate[0] + delta}')

    # 작성자만 수정 가능
    sqlw = f"select writer_num from board where post_num={post_num}"
    cur.execute(sqlw)
    writer_num = cur.fetchone();
    print(f'writer_num: {writer_num[0]}')

    if not admin == 1:
        if cur_user is None:
            return "user only!"
        elif not cur_user == writer_num[0]:
            return "작성자만 수정 가능합니다."
        elif now > credate[0] + delta:
            return "작성 후 1시간이 지나면 수정 불가합니다."
        else:
            # 실행할 SQL문 정의
            sql = f"update board set title='{title}', contents='{contents}' where post_num={post_num}"
            # cursor.execute(sql): sql문 실행
            cur.execute(sql)
            # commit 필요한 작업일 경우 commit
            conn.commit()
            return "수정 완료!"
    else:
        # 실행할 SQL문 정의
        sql = f"update board set title='{title}', contents='{contents}' where post_num={post_num}"
        # cursor.execute(sql): sql문 실행
        cur.execute(sql)
        # commit 필요한 작업일 경우 commit
        conn.commit()
        return "수정 완료!"

@app.route('/board/delete', methods=['DELETE'])
@jwt_required()
def delete():
    cur_user = get_jwt_identity()

    param = request.get_json()
    post_num = param['post_num']

    now = datetime.datetime.now() # 현재시각
    delta = datetime.timedelta(hours = 3) # 3시간

    # 실행할 SQL문 정의
    sql = f"select cdate from board where post_num={post_num}"
    # cursor.execute(sql): sql문 실행
    cur.execute(sql)

    credate = cur.fetchone(); # sql문 돌리고 뽑은 작성시각
    print(f'now: {now}')
    print(f'delta: {delta}')
    print(f'credate[0]: {credate[0]}')
    print(f'credate[0] + delta: {credate[0]+delta}')
    print(f'현재시각 > 작성시각 + 3시간: {now > credate[0] + delta}')

    # 작성자만 삭제 가능
    sqlw = f"select writer_num from board where post_num={post_num}"
    cur.execute(sqlw)
    writer_num = cur.fetchone();
    print(f'writer_num: {writer_num[0]}')

    if cur_user is None:
        return "user only!"
    elif not cur_user == writer_num[0]:
        return "작성자만 삭제 가능합니다."
    elif now > credate[0] + delta:
        return "작성 후 3시간이 지나면 삭제 불가합니다."
    else:
        # 실행할 SQL문 정의
        sql = f"delete from board where post_num='{post_num}'"
        # cursor.execute(sql): sql문 실행
        cur.execute(sql)
        # commit 필요한 작업일 경우 commit
        conn.commit()
        return "삭제 완료!"

@app.route('/board/comment/write', methods=['POST'])
@jwt_required(optional=True)
def writeComment():
    cur_user = get_jwt_identity()

    post_num = request.form['post_num']
    member_num = request.form['member_num']
    member_nickname = request.form['member_nickname']
    contents = request.form['contents']

    # 비회원 댓글 작성 시
    if cur_user is None:
        nonmember_num = randrange(100000)
        nonmember_nickname = f'비회원_{nonmember_num}'
        print(f'비회원번호: {nonmember_num}')
        print(f'비회원닉네임: {nonmember_nickname}')
        # 실행할 SQL문 정의
        sql = f'''
        insert into comment(post_num, member_num, member_nickname, contents)
        values ({post_num}, {nonmember_num}, '{nonmember_nickname}', '{contents}')
        '''
    # 회원 댓글 작성 시
    else:
        # 실행할 SQL문 정의
        sql = f'''
        insert into comment(post_num, member_num, member_nickname, contents)
        values ({post_num}, {member_num}, '{member_nickname}', '{contents}')
        '''

    # cursor.execute(sql): sql문 실행
    cur.execute(sql)
    # commit 필요한 작업일 경우 commit
    conn.commit()
    return "댓글 작성 완료!"

@app.route('/board/comment/modify', methods=['PATCH'])
@jwt_required(optional=True)
def modifyComment():
    cur_user = get_jwt_identity()

    param = request.get_json()
    comment_num = param['comment_num']
    contents = param['contents']

    # 작성자만 수정 가능
    sqlm = f"select member_num from comment where comment_num={comment_num}"
    cur.execute(sqlm)
    member_num = cur.fetchone();
    print(f'member_num(현재 접속 회원): {member_num[0]}')

    if cur_user is None:
        return "user only!"
    elif not cur_user == member_num[0]:
        return "댓글 작성자만 수정 가능합니다."
    else:
        sql = f"update comment set contents='{contents}' where comment_num={comment_num}"
        cur.execute(sql)
        conn.commit()
        return "댓글 수정 완료!"

@app.route('/board/comment/delete', methods=['delete'])
@jwt_required(optional=True)
def deleteComment():
    cur_user = get_jwt_identity()

    param = request.get_json()
    comment_num = param['comment_num']

    # 작성자만 삭제 가능
    sqlm = f"select member_num from comment where comment_num='{comment_num}'"
    cur.execute(sqlm)
    member_num = cur.fetchone();
    print(f'member_num(현재 접속 회원): {member_num[0]}')

    if cur_user is None:
        return "user only!"
    elif not cur_user == member_num[0]:
        return "댓글 작성자만 삭제 가능합니다."
    else:
        sql = f"delete from comment where comment_num={comment_num}"
        cur.execute(sql)
        conn.commit()
        return "댓글 삭제 완료!"
    


# 직접 이 파일을 실행했을 때는 if문 문장이 참이 되어 app.run() 수행
if __name__ == '__main__':
    # debug=True 명시하면 해당 파일 코드 수정 시 Flask가 변경된 것을 인식하고 다시 시작
    app.run(debug=True)