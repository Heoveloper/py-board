from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy() # SQLAlchemy를 사용해서 데이터베이스 저장

class Member(db.Model):
    __tablename__ = 'member' # 테이블 이름: member

    member_num = db.Column(db.Integer, primary_key=True) # 회원번호가 PK
    id = db.Column(db.String(16), unique=True, nullable=False) # 데이터 타입과 길이, 유니크, 널가능여부 설정
    pw = db.Column(db.String(16), nullable=False) # 위와 동일
    nickname = db.Column(db.String(16), unique=True, nullable=False) # 위와 동일