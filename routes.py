from flask import render_template, redirect, url_for, abort, jsonify, request, flash
from flask_login import login_required, current_user
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

@app.route('/chat/list')
@login_required
def chat_list():
    # 사용자가 참여한 모든 채팅방 조회
    chat_rooms = ChatRoom.query.filter(
        (ChatRoom.user1_id == current_user.id) | 
        (ChatRoom.user2_id == current_user.id)
    ).all()
    
    chat_data = []
    for room in chat_rooms:
        other_user = User.query.get(
            room.user2_id if room.user1_id == current_user.id else room.user1_id
        )
        last_message = ChatMessage.query.filter_by(chat_room_id=room.id).order_by(ChatMessage.created_at.desc()).first()
        unread_count = ChatMessage.query.filter_by(
            chat_room_id=room.id,
            is_read=False
        ).filter(ChatMessage.sender_id != current_user.id).count()
        
        chat_data.append({
            'room_id': room.id,
            'other_user': other_user,
            'last_message': last_message,
            'unread_count': unread_count
        })
    
    return render_template('chat/list.html', chats=chat_data)

@app.route('/chat/room/<int:room_id>')
@login_required
def chat_room(room_id):
    room = ChatRoom.query.get_or_404(room_id)
    if current_user.id not in [room.user1_id, room.user2_id]:
        abort(403)
    
    other_user = User.query.get(
        room.user2_id if room.user1_id == current_user.id else room.user1_id
    )
    messages = ChatMessage.query.filter_by(chat_room_id=room_id).order_by(ChatMessage.created_at).all()
    
    # 읽지 않은 메시지를 읽음 처리
    unread_messages = ChatMessage.query.filter_by(
        chat_room_id=room_id,
        is_read=False
    ).filter(ChatMessage.sender_id != current_user.id).all()
    
    for message in unread_messages:
        message.is_read = True
    db.session.commit()
    
    return render_template('chat/room.html', room=room, other_user=other_user, messages=messages)

@app.route('/chat/start/<int:user_id>', methods=['POST'])
@login_required
def start_chat(user_id):
    if user_id == current_user.id:
        abort(400)
    
    # 이미 존재하는 채팅방 확인
    existing_room = ChatRoom.query.filter(
        ((ChatRoom.user1_id == current_user.id) & (ChatRoom.user2_id == user_id)) |
        ((ChatRoom.user1_id == user_id) & (ChatRoom.user2_id == current_user.id))
    ).first()
    
    if existing_room:
        return redirect(url_for('chat_room', room_id=existing_room.id))
    
    # 새 채팅방 생성
    new_room = ChatRoom(user1_id=current_user.id, user2_id=user_id)
    db.session.add(new_room)
    db.session.commit()
    
    return redirect(url_for('chat_room', room_id=new_room.id))

@app.route('/api/chat/send/<int:room_id>', methods=['POST'])
@login_required
def send_message(room_id):
    room = ChatRoom.query.get_or_404(room_id)
    if current_user.id not in [room.user1_id, room.user2_id]:
        return jsonify({'error': '권한이 없습니다.'}), 403
    
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': '메시지 내용이 필요합니다.'}), 400
    
    message = ChatMessage(
        chat_room_id=room_id,
        sender_id=current_user.id,
        content=data['message']
    )
    db.session.add(message)
    db.session.commit()
    
    return jsonify({
        'id': message.id,
        'content': message.content,
        'sender_id': message.sender_id,
        'created_at': message.created_at.isoformat(),
        'is_read': message.is_read
    })

@app.route('/api/chat/messages/<int:room_id>')
@login_required
def get_messages(room_id):
    room = ChatRoom.query.get_or_404(room_id)
    if current_user.id not in [room.user1_id, room.user2_id]:
        return jsonify({'error': '권한이 없습니다.'}), 403
    
    # 마지막 메시지 ID 이후의 새 메시지만 가져오기
    last_id = request.args.get('last_id', type=int, default=0)
    messages = ChatMessage.query.filter(
        ChatMessage.chat_room_id == room_id,
        ChatMessage.id > last_id
    ).order_by(ChatMessage.created_at).all()
    
    return jsonify([{
        'id': msg.id,
        'content': msg.content,
        'sender_id': msg.sender_id,
        'created_at': msg.created_at.isoformat(),
        'is_read': msg.is_read
    } for msg in messages])

@app.route('/report/user/<username>', methods=['POST'])
@login_required
def report_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user == current_user:
        flash('자신을 신고할 수 없습니다.', 'danger')
        return redirect(url_for('profile', username=username))
    
    reason = request.form.get('reason')
    if not reason:
        flash('신고 사유를 입력해주세요.', 'danger')
        return redirect(url_for('profile', username=username))
    
    report = UserReport(
        reporter_id=current_user.id,
        reported_user_id=user.id,
        reason=reason
    )
    db.session.add(report)
    db.session.commit()
    
    flash('신고가 접수되었습니다.', 'success')
    return redirect(url_for('profile', username=username))

@app.route('/report/product/<int:product_id>', methods=['POST'])
@login_required
def report_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.seller_id == current_user.id:
        flash('자신의 상품을 신고할 수 없습니다.', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    reason = request.form.get('reason')
    if not reason:
        flash('신고 사유를 입력해주세요.', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    report = ProductReport(
        reporter_id=current_user.id,
        product_id=product.id,
        reason=reason
    )
    db.session.add(report)
    db.session.commit()
    
    flash('신고가 접수되었습니다.', 'success')
    return redirect(url_for('product', product_id=product_id)) 