##### 모듈 #####
# from 모듈이름 import 모듈함수
import os
import jwt, json, requests
import pymysql  # mysql을 python에서 사용할 시 추가
from flask import Flask, render_template, redirect, request, make_response, jsonify, session, url_for
from flask_jwt_extended import *
from datetime import datetime, timedelta
import datetime
from config import HOST, USER, PASSWORD, DB, CHARSET, APP_SECRET_KEY, JWT_SECRET_KEY  # 환경변수
from random import randrange  # 난수 생성에 필요한 모듈
# from flask_bcrypt import Bcrypt
import bcrypt
####################

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

##### JWT 설정 #####
app.config.update(
    DEBUG=True,
    JWT_SECRET_KEY=JWT_SECRET_KEY
)
jwtm = JWTManager(app)
####################

##### 암호화 설정 #####
# app.config['BCRYPT_LEVEL'] = 10
# bcryptm = Bcrypt(app)
####################

##### DB 연결 #####
# MySQL 연결
conn = pymysql.connect(host=HOST, user=USER,
                       password=PASSWORD, db=DB, charset=CHARSET)
# 커서 객체 생성 (커서 객체에 DB작업을 위한 함수들이 포함)
cur = conn.cursor()
####################

##### 관리자 #####
def isAdmin(cur_user):
    if cur_user is None:
        return 0
    else:
        sql = f"select is_admin from member where id={cur_user}"
        cur.execute(sql)
        conn.commit()

        admin = cur.fetchone() # (0,) or (1,)

    return admin[0] # 0 or 1
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
        pw = request.form.get('pw') # 회원가입 시 입력한 비밀번호 ex) 1234
        encoded_pw = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=10))
        # └> ex) b'$2b$10$vbQ.uAldvS9eAvvPI7KDIubwNuivOt6wTvJJxankAgfllmuwcTmru'
        decoded_pw = encoded_pw.decode('utf-8')
        # └> ex) $2b$10$vbQ.uAldvS9eAvvPI7KDIubwNuivOt6wTvJJxankAgfllmuwcTmru
        # pwc = request.form.get('pwc')
        nickname = request.form.get('nickname')

        # 확인용
        print('encoded_pw ', encoded_pw)
        print('decoded_pw ', decoded_pw)

        # [유효성 검사 부분]
        # 모두 입력해야 가입 가능
        # if not(id and pw and pwc and nickname):
        #     return "입력되지 않은 정보가 있습니다."
        # 비밀번호 일치해야 가입 가능
        # elif pw != pwc:
        #     return "비밀번호가 일치하지 않습니다."
        # 입력이 정상일 경우 하위 명령 실행 (DB에 입력된다.)

        # 실행할 SQL문 정의
        # sql = f"insert into member (login_id, password, nickname) values ('{id}', '{encoded_pw}', '{nickname}');"

        sql = f'''
        insert into member (login_id, password, nickname)
        values ("{id}", "{decoded_pw}", "{nickname}");
        '''

        # sql = f"insert into member (login_id, password, nickname) values ('{id}', '{pw_hash}', '{nickname}');"

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
        pw = request.form['pw'] # 로그인 시 입력한 비밀번호
        pwd = searchPw(id) # DB에 저장된 비밀번호
        print('pwd', pwd)

        # 하나라도 입력하지 않을 시
        if len(id) == 0 or len(pw) == 0:
            return "입력되지 않은 정보가 있습니다."
        # 비밀번호가 1234일 때 '(로그인 시 입력한 1234).encode'와
        # '(DB에 저장된 str형).encode' 비교해서 다를 시
        elif bcrypt.checkpw(pw.encode('utf-8'), pwd.encode('utf-8')) is False:
            return "비밀번호가 일치하지 않습니다."
        else:
            # 실행할 SQL문 정의
            sql = f"select * from member where login_id='{id}' and password='{pwd}';"
            cur.execute(sql)

            res = cur.fetchone()
            if res:
                print(f'res: {res}')  # (Member_num, ID, PW, Nickname, IsAdmin)
                print(f'res[0]: {res[0]}')  # Member_num

                access_token = create_access_token(identity=res[0], expires_delta=False, fresh=timedelta(minutes=15))
                print(f'loginToken: {access_token}')  # 인코딩된 토큰

                return redirect('/')
            else:
                return "잘못된 정보입니다."


######## 로그아웃 ##########
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

    return make_response(jsonify({"result" : True, "id" : f"{cur_user}", "msg" : "로그아웃 성공!"}), 200)
############################

@app.route('/board/<category>/<status>', methods=['GET', 'POST', 'PATCH', 'DELETE'])
@jwt_required(optional=True)
def board(category, status):
    cur_user = get_jwt_identity() # 현재 접속 중인 유저의 회원번호를 리턴
    admin = isAdmin(cur_user)  # 현재 접속 중인 유저의 관리자 여부가 인덱스0에 담긴 튜플을 리턴
    print(f'접속 유저 번호: {cur_user}')
    print(f'접속 유저가 관리자인가요?: {admin}')

    # GET 요청이거나, Category가 없거나
    if request.method == 'GET' or category is None:
        return boardHome()

    # 댓글 작성
    if category == "comment" and status == "write":
        return writeComment(cur_user, admin)

    # 공통 유효성 1. 회원만 작성, 수정, 삭제 가능 (댓글 작성 제외)
    if cur_user is None and admin == 0:
        return make_response(jsonify({"result" : False, "msg" : "로그인 후 가능합니다."}), 401)

    if request.method == 'POST':
        if status == "write":
            if category == "post":
                return writePost(admin)

    if request.method == 'PATCH':
        if status == "modify":
            if category == "post":
                return modifyPost(cur_user, admin, status)
            else:
                return modifyComment(cur_user, admin)

    if request.method == 'DELETE':
        if status == "delete":
            if category == "post":
                return deletePost(cur_user, admin, status)
            else:
                return deleteComment(cur_user, admin)

    return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "게시판 작업 성공!"}), 200)

##### 게시판 바로가기 #####
@app.route('/board')
def boardHome():
    return render_template("board.html")
#########################

##### 게시글 작성 #####
def writePost(admin):
    param = request.get_json()
    writer_num = param['writer_num']
    writer_nickname = param['writer_nickname']
    title = param['title']
    content = param['content']

    # 실행할 SQL문 정의
    sql = f'''
    insert into board (member_id, nickname, title, content)
    values ('{writer_num}', '{writer_nickname}', '{title}', '{content}');
    '''
    # cursor.execute(sql): sql문 실행
    cur.execute(sql)
    # commit 필요한 작업일 경우 commit
    conn.commit()

    if admin == 1:
        return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "관리자로 게시글 작성 완료!"}), 200)
    else:
        return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "게시글 작성 완료!"}), 200)
####################

##### 게시글 수정 #####
def modifyPost(cur_user, admin, status):
    param = request.get_json()
    title = param['title']
    content = param['content']
    post_num = param['post_num']
    writer_num = writerNum(post_num)

    if not cur_user == writer_num and not admin == 1:
        return make_response(jsonify({"result" : False, "is_admin" : f"{admin}", "msg" : "글 작성자만 수정 가능합니다."}), 401)
    elif not changeStatus(post_num, status) and not admin == 1:
        return make_response(jsonify({"result" : False, "is_admin" : f"{admin}", "msg" : "시간이 초과되어 수정하실 수 없습니다. (1시간 제한)"}), 408)
    else:
        # 실행할 SQL문 정의
        sql = f"update board set title='{title}', content='{content}' where id={post_num};"
        # cursor.execute(sql): sql문 실행
        cur.execute(sql)
        # commit 필요한 작업일 경우 commit
        conn.commit()

    if admin == 1:
        return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "관리자로 게시글 수정 완료!"}), 200)
    else:
        return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "게시글 수정 완료!"}), 200)
####################

##### 게시글 삭제 #####
def deletePost(cur_user, admin, status):
    param = request.get_json()
    post_num = param['post_num']
    writer_num = writerNum(post_num)

    if not cur_user == writer_num and not admin == 1:
        return make_response(jsonify({"result" : False, "is_admin" : f"{admin}", "msg" : "글 작성자만 삭제 가능합니다."}), 401)
    elif not changeStatus(post_num, status) and not admin == 1:
        return make_response(jsonify({"result" : False, "is_admin" : f"{admin}", "msg" : "시간이 초과되어 삭제하실 수 없습니다. (3시간 제한)"}), 408)
    else:
        # 실행할 SQL문 정의
        sql = f"delete from board where id='{post_num}';"
        # cursor.execute(sql): sql문 실행
        cur.execute(sql)
        # commit 필요한 작업일 경우 commit
        conn.commit()

    if admin == 1:
        return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "관리자로 게시글 삭제 완료!"}), 200)
    else:
        return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "게시글 삭제 완료!"}), 200)
####################

##### 댓글 작성 #####
def writeComment(cur_user, admin):
    param = request.get_json()
    post_num = param['post_num']
    content = param['content']

    # 비회원 댓글 작성 시
    if cur_user is None:
        nonmember_num = randrange(100000)
        nonmember_nickname = f'비회원_{nonmember_num}'
        non_pw = param['access_password'] # 비회원이 댓글 등록 시 설정한 댓글 비밀번호
        encoded_pw = bcrypt.hashpw(non_pw.encode("utf-8"), bcrypt.gensalt(rounds=10))
        decoded_pw = encoded_pw.decode('utf-8')

        print(f'비회원번호: {nonmember_num}')
        print(f'비회원닉네임: {nonmember_nickname}')
        # 실행할 SQL문 정의
        sql = f'''
        insert into comment (board_id, nickname, content, access_password)
        values ({post_num}, '{nonmember_nickname}', '{content}', '{decoded_pw}');
        '''
    # 회원 댓글 작성 시
    else:
        member_num = param['member_num']
        member_nickname = param['member_nickname']
        # 실행할 SQL문 정의
        sql = f'''
        insert into comment (board_id, member_id, nickname, content)
        values ({post_num}, {member_num}, '{member_nickname}', '{content}');
        '''

    # cursor.execute(sql): sql문 실행
    cur.execute(sql)
    # commit 필요한 작업일 경우 commit
    conn.commit()

    if admin == 1:
        return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "관리자로 댓글 작성 완료!"}), 200)
    # elif member_num is None:
    #     return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "비회원으로 댓글 작성 완료!"}), 200)
    else:
        return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "댓글 작성 완료!"}), 200)
####################

##### 댓글 수정 #####
def modifyComment(cur_user, admin):
    param = request.get_json()
    content = param['content']
    comment_num = param['comment_num']
    commenter_num = commenterNum(comment_num)

    if not cur_user == commenter_num and not admin == 1:
        return make_response(jsonify({"result" : False, "is_admin" : f"{admin}", "msg" : "댓글 작성자만 수정 가능합니다."}), 401)
    # 비회원 댓글 수정 시
    # elif cur_user is None:
    #     access_password =
    else:
        sql = f"update comment set content='{content}' where id={comment_num};"
        cur.execute(sql)
        conn.commit()
        if admin == 1:
            return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "관리자로 댓글 수정 완료!"}), 200)
        else:
            return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "댓글 수정 완료!"}), 200)
####################

##### 댓글 삭제 #####
def deleteComment(cur_user, admin):
    param = request.get_json()
    comment_num = param['comment_num']
    commenter_num = commenterNum(comment_num)

    if not cur_user == commenter_num and not admin == 1:
        return make_response(jsonify({"result" : False, "is_admin" : f"{admin}", "msg" : "댓글 작성자만 삭제 가능합니다."}), 401)
    else:
        sql = f"delete from comment where id={comment_num};"
        cur.execute(sql)
        conn.commit()
        if admin == 1:
            return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "관리자로 댓글 삭제 완료!"}), 200)
        else:
            return make_response(jsonify({"result" : True, "is_admin" : f"{admin}", "msg" : "댓글 삭제 완료!"}), 200)
####################


##### 작성자 번호 #####
def writerNum(post_num):
    sql = f"select member_id from board where id={post_num};"
    cur.execute(sql)
    writer_num = cur.fetchone()

    return writer_num[0]
####################

##### 댓글 작성자 번호 #####
def commenterNum(comment_num):
    sql = f"select member_id from comment where id={comment_num};"
    cur.execute(sql)
    commenter_num = cur.fetchone()

    return commenter_num[0]
####################

##### 상태 변경 가능 여부 (현재시각 > 작성시각 + 제한시간이면 상태 변경 불가) #####
def changeStatus(post_num, status):
    # now = 현재시각
    now = datetime.datetime.now()
    # delta = 상태가 수정이면 1시간, 삭제면 3시간
    delta = datetime.timedelta(hours=1) if status == "modify" else datetime.timedelta(hours=3)

    # 실행할 SQL문 정의
    # sql = "select date_format(cdate, '%%h') From board where post_num=%s;"
    sql = f"select created_at from board where id={post_num};"
    # cursor.execute(sql): sql문 실행
    cur.execute(sql)

    credate = cur.fetchone()

    # 결과 확인용
    print(f'now: {now}')
    print(f'delta: {delta}')
    print(f'credate[0]: {credate[0]}')

    print(f'현재시각 > 작성시각 + 1시간: {now > credate[0] + delta}')
    print(f'현재시각 - 작성시각: {now - credate[0]}')
    print(f'현재시각 + 1시간: {credate[0] + delta}')

    # 상태 변경 가능 시각이면 True
    if now < credate[0] + delta:
        return True
    # 상태 변경 불가능 시각이면 False
    else:
        return False
################################################################################

##### 로그인 아이디로 비밀번호 검색 (비밀번호 비교용) #####
def searchPw(id):
    sql = f"select password from member where login_id='{id}';"
    cur.execute(sql)

    pwd = cur.fetchone()

    print(pwd)
    print(pwd[0])

    return pwd[0]
#######################################################


# 직접 이 파일을 실행했을 때는 if문 문장이 참이 되어 app.run() 수행
if __name__ == '__main__':
    # debug=True 명시하면 해당 파일 코드 수정 시 Flask가 변경된 것을 인식하고 다시 시작
    app.run(debug=True)
