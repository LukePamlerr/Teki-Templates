# app/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import Template, User
from app.forms import UploadForm, LoginForm, RegisterForm
from flask_paginate import Pagination, get_page_args
import bcrypt

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    search = request.args.get('search', '')
    templates = Template.query.filter(
        Template.name.ilike(f'%{search}%') |
        Template.category.ilike(f'%{search}%') |
        Template.tags.ilike(f'%{search}%')
    ).all()
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 9
    pagination_templates = templates[offset: offset + per_page]
    pagination = Pagination(page=page, per_page=per_page, total=len(templates), css_framework='bootstrap5')
    return render_template('index.html', templates=pagination_templates, pagination=pagination, search=search)

@bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        template = Template(
            name=form.name.data,
            description=form.description.data,
            category=form.category.data,
            tags=form.tags.data,
            code=form.code.data,
            user_id=current_user.id
        )
        db.session.add(template)
        db.session.commit()
        flash('Template uploaded successfully!', 'success')
        return redirect(url_for('main.index'))
    return render_template('upload.html', form=form)

@bp.route('/template/<int:id>')
def template_detail(id):
    template = Template.query.get_or_404(id)
    return render_template('template.html', template=template)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password):
            login_user(user)
            return redirect(url_for('main.index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
