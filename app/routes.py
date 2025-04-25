from flask import request, flash, redirect, url_for
from flask_login import login_required, current_user
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

@app.route('/report/user/<int:user_id>', methods=['POST'])
@login_required
def report_user(user_id):
    if current_user.id == user_id:
        flash('자신을 신고할 수 없습니다.', 'danger')
        return redirect(url_for('index'))

    reason = request.form.get('reason')
    if not reason:
        flash('신고 사유를 입력해주세요.', 'danger')
        return redirect(url_for('index'))

    reported_user = User.query.get_or_404(user_id)
    
    # 이미 신고한 경우 체크
    existing_report = UserReport.query.filter_by(
        reporter_id=current_user.id,
        reported_user_id=user_id
    ).first()
    
    if existing_report:
        flash('이미 신고한 사용자입니다.', 'warning')
        return redirect(url_for('index'))

    report = UserReport(
        reporter_id=current_user.id,
        reported_user_id=user_id,
        reason=reason,
        status='pending'
    )
    
    db.session.add(report)
    
    # 신고 횟수가 5회 이상인 경우 계정 비활성화
    report_count = UserReport.query.filter_by(reported_user_id=user_id).count()
    if report_count >= 5:
        reported_user.is_active = False
        flash('해당 사용자가 비활성화되었습니다.', 'info')
    
    db.session.commit()
    flash('신고가 접수되었습니다.', 'success')
    return redirect(url_for('index'))

@app.route('/report/product/<int:product_id>', methods=['POST'])
@login_required
def report_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.seller_id == current_user.id:
        flash('자신의 상품을 신고할 수 없습니다.', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    reason = request.form.get('reason')
    if not reason:
        flash('신고 사유를 입력해주세요.', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    report = ProductReport(
        reporter_id=current_user.id,
        product_id=product_id,
        reason=reason,
        status='pending'
    )
    db.session.add(report)
    db.session.commit()
    
    flash('신고가 접수되었습니다.', 'success')
    return redirect(url_for('product_detail', product_id=product_id)) 