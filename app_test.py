# from flask import Flask, render_template, redirect, request, url_for
# from flaskext.mysql import MySQL

# mysql = MySQL()
# app = Flask(__name__)

# # 데이터베이스 값 설정
# app.config['MYSQL_DATABASE_USER'] = 'root'
# app.config['MYSQL_DATABASE_PASSWORD'] = 'admin1234'
# app.config['MYSQL_DATABASE_DB'] = 'mydb'
# app.config['MYSQL_DATABASE_HOST'] = '127.0.0.1:5000'
# app.secret_key = "ABCDEFGGFEDCBA"
# mysql.init_app(app)

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         id = request.form['id']
#         pw = request.form['pw']
#         pwc = request.form['pwc']
#         nn = request.form['nickname']

#         conn = mysql.connect() # DB와 연결
#         cursor = conn.cursor() # connection으로부터 cursor 생성
#         sql = "INSERT INTO member VALUES ('%s', '%s', '%s')" % (id, pw, nn) # 실행할 SQL문
#         cursor.execute(sql) # 메소드로 전달해 명령문을 실행
#         data = cursor.fetchall() # 실행한 결과 데이터를 꺼냄

#         if not data:
#             conn.commit()
#             return redirect(url_for('main'))
#         else:
#             conn.rollback()
#             return "가입 실패"
    
#     return render_template('sign-up.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     # 요청 메소드가 GET일 때
#     if request.method == 'GET':
#         # login html파일을 렌더링
#         return render_template("login.html")
#     # 요청 메소드가 POST일 때
#     elif request.method == 'POST':
#         id = request.form.get('id')
#         pw = request.form.get('pw')
        
#         if len(id) == 0 or len(pw) == 0:
#             return '입력되지 않은 정보가 있습니다.'
#         else:
#             # MySQL 연결
#             conn = pymysql.connect(host='127.0.0.1', user='root', password='admin1234', db='mydb', charset='utf8')
#             # 커서 객체 생성 (커서 객체에 DB작업을 위한 함수들이 포함)
#             cur = conn.cursor()
#             # 실행할 SQL문 정의
#             sql = '''
#             select * from member
#             where id=%s
#             and pw=%s
#             '''
#             vals = (id, pw)
#             cur.execute(sql, vals)
#             res = cur.fetchall()
#             session['id'] = res[0]

#             # (1, 'itez', '1234', 'itezitez', 'no')
#             # 그냥 print 해보는 용도(값 확인용)로 삭제 예정
#             for i in cur:
#                 print(i)
#             print(session['id'])

#             return redirect('/')


# if __name__ == '__main__':
#     # debug=True 명시하면 해당 파일 코드 수정 시 Flask가 변경된 것을 인식하고 다시 시작
#     app.run(debug=True)