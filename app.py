from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_pymongo import PyMongo
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta
from functools import wraps
import cloudinary
import cloudinary.uploader
import re
from werkzeug.utils import secure_filename
import uuid
from PIL import Image, ImageOps

# SteganoDCT.py 파일에서 StegoDCT 클래스를 가져옵니다.
from SteganoDCT import StegoDCT

# .env 파일에서 환경 변수 로드
load_dotenv()

app = Flask(__name__)

# MongoDB 및 Bcrypt 설정
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# SocketIO 설정
socketio = SocketIO(app, cors_allowed_origins="*")


# Cloudinary 설정
cloudinary.config(
  cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME"),
  api_key = os.getenv("CLOUDINARY_API_KEY"),
  api_secret = os.getenv("CLOUDINARY_API_SECRET")
)

# 개발 환경에서 모든 출처의 요청을 허용합니다.
CORS(app)

# 파일 업로드 및 결과 저장을 위한 폴더 설정
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'error': '인증 토큰이 없습니다!'}), 401
        try:
            data = jwt.decode(token, os.getenv("JWT_SECRET"), algorithms=["HS256"])
            current_user = mongo.db.users.find_one({'email': data['email']})
            if not current_user:
                 return jsonify({'error': '유효하지 않은 토큰입니다!'}), 401
        except Exception as e:
            print(f"Token validation error: {e}") # 로그 추가
            return jsonify({'error': '유효하지 않은 토큰입니다!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'error': '인증 토큰이 없습니다!'}), 401
        try:
            data = jwt.decode(token, os.getenv("JWT_SECRET"), algorithms=["HS256"])
            if data.get('role') != 'admin':
                return jsonify({'error': '관리자 권한이 필요합니다.'}), 403
        except Exception as e:
            print(f"Admin token validation error: {e}") # 로그 추가
            return jsonify({'error': '유효하지 않은 토큰입니다!'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the DDW API!'}), 200

@app.route('/api/register', methods=['POST'])
def register():
    users = mongo.db.users
    email = request.form.get('email')
    password = request.form.get('password')
    name = request.form.get('name')
    phone = request.form.get('phone')

    # 유효성 검사 업데이트
    if not email or not password or not name or not phone:
        return jsonify({'error': '모든 필드를 입력해야 합니다.'}), 400

    # 이메일 형식 유효성 검사
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'error': '유효한 이메일 주소를 입력해주세요.'}), 400

    # 비밀번호 유효성 검사 (영어와 숫자를 모두 포함)
    if not (re.search(r"[a-zA-Z]", password) and re.search(r"\d", password)):
        return jsonify({'error': '비밀번호는 영어와 숫자를 모두 포함해야 합니다.'}), 400
    
    # 전화번호 형식 유효성 검사 (예: 010-1234-5678)
    if not re.match(r"^\d{3}-\d{3,4}-\d{4}$", phone):
        return jsonify({'error': '유효한 전화번호 형식을 입력해주세요 (예: 010-1234-5678).'}), 400

    existing_user = users.find_one({'email': email})

    if existing_user:
        return jsonify({'error': '이미 가입된 이메일입니다.'}), 409

    # 관리자 계정 설정
    role = 'admin' if email == 'asdasd@naver.com' else 'user'

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users.insert_one({
        'email': email,
        'password': hashed_password,
        'name': name,
        'phone': phone,
        'role': role
    })

    return jsonify({'message': '회원가입이 성공적으로 완료되었습니다.'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    users = mongo.db.users
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return jsonify({'error': '이메일과 비밀번호를 모두 입력해야 합니다.'}), 400

    user = users.find_one({'email': email})

    if not user:
        return jsonify({'error': '이메일 또는 비밀번호가 잘못되었습니다.'}), 401

    if bcrypt.check_password_hash(user['password'], password):
        # JWT 토큰 생성 (1시간 후 만료)
        token = jwt.encode({
            'email': user['email'],
            'role': user.get('role', 'user'),
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, os.getenv("JWT_SECRET"), algorithm="HS256")

        return jsonify({
            'message': '로그인 성공!',
            'user': {
                'email': user['email'],
                'role': user.get('role', 'user'),
            },
            'token': token
        }), 200
    else:
        return jsonify({'error': '이메일 또는 비밀번호가 잘못되었습니다.'}), 401




@app.route('/api/posts', methods=['POST'])
@token_required
def create_post(current_user):
    if 'image' not in request.files:
        return jsonify({'error': '이미지 파일이 필요합니다.'}), 400

    def preprocess_image(input_path: str, output_path: str, max_long_side: int = 1280, quality: int = 90) -> str:
        """
        이미지 크기를 조정하고 메타데이터를 제거하여 표준 JPEG로 재압축합니다.
        이는 다양한 원본 이미지의 워터마킹 호환성을 높입니다.
        """
        try:
            with Image.open(input_path) as img:
                # EXIF 데이터를 기반으로 이미지 자동 회전
                # 스마트폰 사진 등이 회전되는 문제 해결
                img = ImageOps.exif_transpose(img)

                # 1. 해상도 및 크기 축소 (Resizing)
                width, height = img.size
                if width > max_long_side or height > max_long_side:
                    if width > height:
                        new_width = max_long_side
                        new_height = int(height * (max_long_side / width))
                    else:
                        new_height = max_long_side
                        new_width = int(width * (max_long_side / height))
                    
                    img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)

                # RGB로 변환 (JPEG 저장에 필요)
                if img.mode != 'RGB':
                    img = img.convert("RGB") 

                # 2. 표준 JPEG로 재압축 (메타데이터 제거 포함)
                img.save(
                    output_path,
                    format="JPEG",
                    quality=quality,
                    exif=b""  # 명시적으로 메타데이터 제거
                )
            return output_path
        except Exception as e:
            print(f"Image preprocessing failed: {e}")
            raise ValueError("이미지 전처리 중 오류가 발생했습니다.")

    image_file = request.files['image']
    title = request.form.get('title')
    content = request.form.get('content')
    category = request.form.get('category') # 카테고리 추가
    watermark_message = current_user['email']

    if image_file.filename == '':
        return jsonify({'error': '선택된 파일이 없습니다.'}), 400
    if not title or not content or not category:
        return jsonify({'error': '제목과 내용을 모두 입력해야 합니다.'}), 400

    try:
        filename = secure_filename(image_file.filename)
        unique_id = uuid.uuid4().hex
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_id}_{filename}")
        image_file.save(input_path)

        steganographer = StegoDCT()
        
        # 1. 워터마크 검증
        original_owner_email = steganographer.decrypt(input_path)

        # 추출된 메시지에서 Null Byte 제거
        if original_owner_email:
            original_owner_email = original_owner_email.rstrip('\x00')


        post = {}
        image_to_upload = input_path

        if not original_owner_email or '@' not in original_owner_email:
            # 2-1. 워터마크 없음 -> 새로 삽입
            # 메타데이터 제거 및 표준화를 위해 이미지 전처리
            preprocessed_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_id}_preprocessed.jpg")
            preprocess_image(input_path, preprocessed_path)

            output_filename = f"{unique_id}_encrypted.png"
            output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
            steganographer.encrypt(preprocessed_path, watermark_message, output_path, 'png')
            image_to_upload = output_path # 최종 업로드할 이미지는 워터마크가 삽입된 PNG
            post = { 'isViolation': False }
        
        elif current_user['email'].startswith(original_owner_email) and len(current_user['email']) - len(original_owner_email) <= 1:
            # 2-2. 자신의 워터마크 -> 정상 처리
            post = { 'isViolation': False }
        else:
            # 2-3. 타인의 워터마크 -> 저작권 위반 처리
            post = {
                'isViolation': True,
            }
            # 마지막 글자가 잘린 경우를 대비해, DB에서 원본 소유자의 전체 이메일을 찾음
            # 정규표현식을 사용하여 추출된 이메일로 시작하고, 정확히 한 글자가 더 있는 사용자를 찾음
            regex_pattern = f"^{re.escape(original_owner_email)}.$"
            found_owner = mongo.db.users.find_one({"email": {"$regex": regex_pattern}})
            
            if found_owner:
                post['originalOwnerEmail'] = found_owner['email']
            else:
                # 일치하는 사용자를 찾지 못한 경우, 추출된 그대로 저장
                post['originalOwnerEmail'] = original_owner_email

        # 3. Cloudinary에 이미지 업로드
        upload_result = cloudinary.uploader.upload(image_to_upload, folder="dct_watermark")
        
        # 4. MongoDB에 게시물 정보 저장
        post.update({
            'title': title,
            'content': content,
            'imageUrl': upload_result['secure_url'],
            'category': category, # 카테고리 저장
            'authorEmail': current_user['email'],
            'createdAt': datetime.utcnow(),
            'views': 0,
            'likes': 0,
        })

        mongo.db.posts.insert_one(post)

        return jsonify({'message': '게시물이 성공적으로 생성되었습니다.'}), 201

    except Exception as e:
        print(f"Post creation error: {e}") # 로그 추가
        return jsonify({'error': f'게시물 생성 중 오류 발생: {str(e)}'}), 500
    finally:
        # 임시 파일들 삭제
        if 'input_path' in locals() and os.path.exists(input_path):
            os.remove(input_path)
        if 'preprocessed_path' in locals() and os.path.exists(preprocessed_path):
            os.remove(preprocessed_path)
        if 'output_path' in locals() and 'output_path' in locals() and os.path.exists(output_path):
            os.remove(output_path)

@app.route('/api/posts', methods=['GET'])
def get_posts():
    sort_by = request.args.get('sort', 'createdAt')
    category = request.args.get('category')
    sort_order = -1  # 내림차순 정렬

    # 유효한 정렬 기준인지 확인
    if sort_by not in ['createdAt', 'views', 'likes']:
        sort_by = 'createdAt'

    query = {}
    if category:
        # URL 디코딩이 필요할 수 있으나, Flask가 자동으로 처리해 줌
        query['category'] = category

    posts = mongo.db.posts.find(query).sort(sort_by, sort_order)
    result = []
    for post in posts:
        post['createdAt'] = post['createdAt'].isoformat()
        post['_id'] = str(post['_id'])
        # 각 게시물에 대한 댓글 수 계산
        post['commentCount'] = mongo.db.comments.count_documents({'post_id': ObjectId(post['_id'])})
        result.append(post)
    return jsonify(result), 200

@app.route('/api/posts/<post_id>/comments', methods=['GET'])
def get_comments(post_id):
    try:
        # post_id가 유효한 ObjectId인지 확인
        if not ObjectId.is_valid(post_id):
            return jsonify([]), 200
        comments = mongo.db.comments.find({'post_id': ObjectId(post_id)}).sort('createdAt', 1)
        result = []
        for comment in comments:
            comment['_id'] = str(comment['_id'])
            comment['post_id'] = str(comment['post_id'])
            comment['createdAt'] = comment['createdAt'].isoformat()
            result.append(comment)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': f'댓글을 불러오는 중 오류 발생: {str(e)}'}), 500

@app.route('/api/posts/<post_id>/comments', methods=['POST'])
@token_required
def create_comment(current_user, post_id):
    content = request.form.get('content')
    if not content:
        return jsonify({'error': '댓글 내용이 필요합니다.'}), 400

    comment = {
        'post_id': ObjectId(post_id),
        'authorEmail': current_user['email'],
        'content': content,
        'createdAt': datetime.utcnow()
    }
    result = mongo.db.comments.insert_one(comment)
    
    # 삽입된 댓글을 반환하기 위해 다시 조회
    new_comment = mongo.db.comments.find_one({'_id': result.inserted_id})
    new_comment['_id'] = str(new_comment['_id'])
    new_comment['post_id'] = str(new_comment['post_id'])
    new_comment['createdAt'] = new_comment['createdAt'].isoformat()

    return jsonify(new_comment), 201

@app.route('/api/comments/<comment_id>', methods=['DELETE'])
@token_required
def delete_comment(current_user, comment_id):
    comment = mongo.db.comments.find_one_or_404({'_id': ObjectId(comment_id)})

    if comment['authorEmail'] != current_user['email'] and current_user.get('role') != 'admin':
        return jsonify({'error': '삭제 권한이 없습니다.'}), 403

    mongo.db.comments.delete_one({'_id': ObjectId(comment_id)})
    return '', 204

@app.route('/api/posts/<post_id>', methods=['GET'])
def get_post(post_id):
    post = mongo.db.posts.find_one_or_404({'_id': ObjectId(post_id)})
    post['createdAt'] = post['createdAt'].isoformat()
    post['_id'] = str(post['_id'])
    return jsonify(post), 200

@app.route('/api/posts/<post_id>/like', methods=['PUT'])
@token_required
def like_post(current_user, post_id):
    # TODO: 사용자가 이미 추천했는지 확인하는 로직 추가 (중복 방지)
    result = mongo.db.posts.find_one_and_update(
        {'_id': ObjectId(post_id)},
        {'$inc': {'likes': 1}},
        return_document=True
    )
    return jsonify({'message': '추천되었습니다.', 'likes': result['likes']}), 200

@app.route('/api/posts/<post_id>/like', methods=['DELETE'])
@token_required
def unlike_post(current_user, post_id):
    result = mongo.db.posts.find_one_and_update(
        {'_id': ObjectId(post_id), 'likes': {'$gt': 0}}, # 추천 수가 0보다 클 때만 감소
        {'$inc': {'likes': -1}},
        return_document=True
    )
    return jsonify({'message': '추천이 취소되었습니다.', 'likes': result['likes'] if result else 0}), 200
@app.route('/api/posts/<post_id>/view', methods=['PUT'])
def view_post(post_id):
    mongo.db.posts.update_one({'_id': ObjectId(post_id)}, {'$inc': {'views': 1}})
    return jsonify({'message': '조회수 증가'}), 200

@app.route('/api/posts/<post_id>', methods=['DELETE'])
@token_required
def delete_post(current_user, post_id):
    try:
        post = mongo.db.posts.find_one_or_404({'_id': ObjectId(post_id)})

        # 게시물 작성자이거나 관리자인 경우에만 삭제 허용
        if post['authorEmail'] != current_user['email'] and current_user.get('role') != 'admin':
            return jsonify({'error': '삭제 권한이 없습니다.'}), 403

        # Cloudinary에서 이미지 삭제
        image_url = post.get('imageUrl')
        if image_url:
            public_id_with_folder = '/'.join(image_url.split('/')[-2:])
            public_id = os.path.splitext(public_id_with_folder)[0]
            cloudinary.uploader.destroy(public_id)

        # MongoDB에서 게시물 삭제
        mongo.db.posts.delete_one({'_id': ObjectId(post_id)})
        
        return '', 204
    except Exception as e:
        print(f"Post deletion error: {e}") # 로그 추가
        return jsonify({'error': f'게시물 삭제 중 오류 발생: {str(e)}'}), 500

@app.route('/api/users/me', methods=['DELETE'])
@token_required
def delete_account(current_user):
    try:
        user_email = current_user['email']
        
        # 사용자가 저작권 위반 게시물을 가지고 있는지 확인
        has_violations = mongo.db.posts.find_one({'authorEmail': user_email, 'isViolation': True})

        if has_violations:
            # 저작권 위반 기록이 있는 경우: 위반이 아닌 게시물만 삭제
            non_violation_posts = list(mongo.db.posts.find({'authorEmail': user_email, 'isViolation': False}))
            for post in non_violation_posts:
                image_url = post.get('imageUrl')
                if image_url:
                    public_id_with_folder = '/'.join(image_url.split('/')[-2:])
                    public_id = os.path.splitext(public_id_with_folder)[0]
                    cloudinary.uploader.destroy(public_id)
            
            mongo.db.posts.delete_many({'authorEmail': user_email, 'isViolation': False})
            # 사용자 정보는 삭제하지 않음
            return jsonify({'message': '저작권 위반 기록이 있어 계정 정보는 보존되며, 위반이 아닌 게시물만 삭제되었습니다.'}), 200
        else:
            # 저작권 위반 기록이 없는 경우: 모든 게시물과 사용자 계정 삭제
            posts_to_delete = list(mongo.db.posts.find({'authorEmail': user_email}))
            for post in posts_to_delete:
                image_url = post.get('imageUrl')
                if image_url:
                    public_id_with_folder = '/'.join(image_url.split('/')[-2:])
                    public_id = os.path.splitext(public_id_with_folder)[0]
                    cloudinary.uploader.destroy(public_id)
            
            mongo.db.posts.delete_many({'authorEmail': user_email})
            mongo.db.users.delete_one({'email': user_email})
            return jsonify({'message': '회원 탈퇴가 성공적으로 처리되었습니다.'}), 200

    except Exception as e:
        print(f"Account deletion error: {e}") # 로그 추가
        return jsonify({'error': f'회원 탈퇴 중 오류 발생: {str(e)}'}), 500

@app.route('/api/admin/set-role', methods=['POST'])
@admin_required
def set_admin_role():
    email = request.form.get('email')
    if not email:
        return jsonify({'error': '이메일을 입력해주세요.'}), 400

    result = mongo.db.users.update_one({'email': email}, {'$set': {'role': 'admin'}})

    if result.matched_count == 0:
        return jsonify({'error': '해당 이메일을 가진 사용자를 찾을 수 없습니다.'}), 404

    return jsonify({'message': f'{email} 사용자에게 관리자 권한이 부여되었습니다.'}), 200

@app.route('/api/admin/violations', methods=['GET'])
@admin_required
def get_violation_posts():
    try:
        # isViolation이 true인 게시물들을 찾음
        violation_posts = list(mongo.db.posts.find({'isViolation': True}).sort('createdAt', -1))
        
        results = []
        for post in violation_posts:
            # 각 게시물의 작성자(유출자) 정보를 users 컬렉션에서 찾음
            violator_info = mongo.db.users.find_one({'email': post['authorEmail']})
            
            post_data = {
                '_id': str(post['_id']),
                'title': post['title'],
                'imageUrl': post['imageUrl'],
                'createdAt': post['createdAt'].isoformat(),
                'violator': {
                    'email': violator_info.get('email'),
                    'name': violator_info.get('name'),
                    'phone': violator_info.get('phone'),
                }
            }
            results.append(post_data)
        return jsonify(results), 200
    except Exception as e:
        print(f"Violation list fetch error: {e}") # 로그 추가
        return jsonify({'error': f'위반 게시물 조회 중 오류 발생: {str(e)}'}), 500

@app.route('/api/users/me/posts', methods=['GET'])
@token_required
def get_my_posts(current_user):
    posts = list(mongo.db.posts.find({'authorEmail': current_user['email']}).sort('createdAt', -1))
    for post in posts:
        post['_id'] = str(post['_id'])
    return jsonify(posts), 200

@app.route('/api/decrypt', methods=['POST'])
def decrypt_image():
    if 'image' not in request.files:
        return jsonify({'error': '이미지를 제공해야 합니다.'}), 400

    image_file = request.files['image']

    if image_file.filename == '':
        return jsonify({'error': '선택된 파일이 없습니다.'}), 400

    try:
        filename = secure_filename(image_file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4().hex}_{filename}")
        image_file.save(input_path)

        steganographer = StegoDCT()
        message = steganographer.decrypt(input_path)
        
        # Null Byte 제거
        if message:
            message = message.rstrip('\x00')

        # 마지막 글자가 잘렸을 가능성을 대비하여 DB에서 유추
        # 추출된 메시지로 시작하고, 정확히 한 글자만 더 긴 이메일을 찾음
        if message and '@' in message:
            regex_pattern = f"^{re.escape(message)}.$"
            found_user = mongo.db.users.find_one({"email": {"$regex": regex_pattern}})
            if found_user:
                # 일치하는 사용자를 찾으면 완전한 이메일 반환
                return jsonify({'message': found_user['email']})

        # 일치하는 사용자가 없으면 추출된 메시지 그대로 반환
        return jsonify({'message': message if message and '@' in message else "워터마크가 검출되지 않았습니다. 정상적인 저작물입니다."})

    except Exception as e:
        print(f"Decryption error: {e}") # 로그 추가
        return jsonify({'error': f'복호화 중 오류 발생: {str(e)}'}), 500
    finally:
        if 'input_path' in locals() and os.path.exists(input_path):
            os.remove(input_path)

@app.route('/api/chat/users', methods=['GET'])
@token_required
def get_chat_users(current_user):
    """채팅 가능한 사용자 목록을 반환합니다 (자기 자신 제외)."""
    try:
        users = mongo.db.users.find({'email': {'$ne': current_user['email']}}, {'_id': 0, 'email': 1, 'name': 1})
        return jsonify(list(users)), 200
    except Exception as e:
        return jsonify({'error': f'사용자 목록 조회 중 오류 발생: {str(e)}'}), 500

@app.route('/api/chat/search-user', methods=['GET'])
@token_required
def search_chat_user(current_user):
    """이메일로 채팅 사용자를 검색합니다."""
    email_query = request.args.get('email', '')
    if not email_query:
        return jsonify([]), 200
    
    try:
        # 부분 일치 검색, 대소문자 구분 없음, 자기 자신 제외
        regex = re.compile(f'.*{re.escape(email_query)}.*', re.IGNORECASE)
        users = mongo.db.users.find({'email': {'$regex': regex, '$ne': current_user['email']}}, {'_id': 0, 'email': 1, 'name': 1}).limit(10)
        return jsonify(list(users)), 200
    except Exception as e:
        return jsonify({'error': f'사용자 검색 중 오류 발생: {str(e)}'}), 500

@app.route('/api/chat/history/<receiver_email>', methods=['GET'])
@token_required
def get_chat_history(current_user, receiver_email):
    """두 사용자 간의 채팅 기록을 반환합니다."""
    try:
        sender_email = current_user['email']
        
        # 두 사용자 간의 모든 메시지를 조회
        messages = mongo.db.chats.find({
            '$or': [
                {'sender': sender_email, 'receiver': receiver_email},
                {'sender': receiver_email, 'receiver': sender_email}
            ]
        }).sort('createdAt', 1)

        result = []
        for msg in messages:
            msg['_id'] = str(msg['_id'])
            msg['createdAt'] = msg['createdAt'].isoformat()
            result.append(msg)
            
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': f'대화 기록 조회 중 오류 발생: {str(e)}'}), 500

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('join')
def handle_join(data):
    """사용자가 자신의 고유 룸에 참여합니다."""
    email = data.get('email')
    if email:
        join_room(email)
        print(f'User {email} joined room {email}')

@socketio.on('send_message')
def handle_send_message(data):
    """클라이언트로부터 메시지를 받아 처리합니다."""
    sender = data.get('sender')
    receiver = data.get('receiver')
    content = data.get('content')

    if not sender or not receiver or not content:
        return

    message = {
        'sender': sender,
        'receiver': receiver,
        'content': content,
        'createdAt': datetime.utcnow()
    }
    mongo.db.chats.insert_one(message)

    # emit할 때는 datetime 객체를 문자열로 변환해야 함
    emit_message = message.copy()
    emit_message['_id'] = str(emit_message['_id'])
    emit_message['createdAt'] = emit_message['createdAt'].isoformat()
    
    # 수신자의 룸으로 메시지 전송
    emit('receive_message', emit_message, room=receiver)
    # 송신자에게도 확인 메시지 전송 (UI 즉시 업데이트용)
    emit('receive_message', emit_message, room=sender)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    socketio.run(app, debug=True, port=port)