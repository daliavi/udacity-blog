import hashlib
import hmac
import logging
import random
import string
from collections import namedtuple

from constants import SECRET
from models import User, Post, Comment, Like

# Post bundle will be used to retrieve data required to render the post page
PostBundle = namedtuple('PostBundle', 'post comments like username_dict')


class UserService(object):
    # New user sign up data validation:
    @classmethod
    def valid_username(cls, username):
        if User.USER_RE.match(username):
            return True
        else:
            return False

    @classmethod
    def valid_password(cls, password):
        if User.PSW_RE.match(password):
            return True
        else:
            return False

    @classmethod
    def valid_email(cls, email):
        if User.EMAIL_RE.match(email) or email == "":
            return True
        else:
            return False

    @classmethod
    def register(cls, username, psw, email=None):
        # hashing password
        pw_hash = SecurityService.make_pw_hash(username, psw)
        return User(username=username,
                    password=pw_hash,
                    email=email)

    @classmethod
    def validate_login(cls, username, psw):
        u = User.by_name(username)
        if u and SecurityService.valid_pw(username, psw, u.password):
            return u


class PostService(object):
    @classmethod
    def get_post_bundle(cls, post_id, user=None):
        user_id = int(user.key().id()) if user else None
        post = Post.get_by_id(post_id)
        comments = Comment.all().filter('post_id =', post_id).order('-created').fetch(limit=10)
        like = Like.all().filter('post_id =', post_id).filter('user_id =', user_id).get() if user else None

        # username dictionary, to show usernames instead of IDs
        user_ids = set([c.created_by for c in comments])
        user_ids.add(post.created_by)
        if user_id:
            user_ids.add(user_id)

        user_objects = User.get_by_id(user_ids)
        username_dict = {u.key().id(): u.username for u in user_objects}

        return PostBundle(post, comments, like, username_dict)

    @classmethod
    def update_post(cls, post_id, user_id, subject, content):
        error_msg = ''
        post = Post.get_by_id(post_id)
        if user_id == post.created_by and subject and content:
            post.content = content
            post.subject = subject
            post.put()
            post = Post.get_by_id(post_id)
        else:
            error_msg = 'The post could not be saved, please check your content'
        return post, error_msg

    @classmethod
    def delete_post(cls, post_id, user_id):
        error_msg = None
        posts = Post.all().order('-created').fetch(limit=10)
        updated_post_list = posts
        post = Post.get_by_id(post_id)
        if user_id == post.created_by:

            # delete comments of the post
            comments = Comment.all().filter('post_id =', post_id).fetch(limit=10)
            for c in comments:
                Comment.delete(c)

            # delete likes of the post
            likes = Like.all().filter('post_id =', post_id).fetch(limit=10)
            for l in likes:
                Like.delete(l)

            # delete the post
            updated_post_list = cls.update_list_on_delete(
                object_list=posts,
                object_id=post_id
            )
            Post.delete(post)

        else:
            error_msg = 'You can delete only your own posts'

        return updated_post_list, error_msg

    @classmethod
    def add_comment(cls, comment, post_id, user_id):
        if comment and post_id:
            c = Comment(content=comment, created_by=user_id, post_id=post_id)
            c.put()
            return c

    @classmethod
    def update_comment(cls, comment_id, user_id, content):
        error_msg = ''
        comment = Comment.get_by_id(comment_id)
        if user_id == comment.created_by and content:
            comment.content = content
            comment.put()
        else:
            error_msg = 'The comment could not be saved, please check your content'
        return comment, error_msg

    @classmethod
    # to deal with the race condition when saving and displaying the data, I update the post bundle and
    # render the page using it. The function bellow is used to create a sorted list of objects
    # after one (for example comment or post) was deleted.
    def update_list_on_delete(cls, object_list, object_id):
        object_dict = {i.key().id(): i for i in object_list}
        del (object_dict[object_id])
        updated_list = object_dict.values()
        updated_list.sort(key=lambda x: x.created, reverse=True)
        return updated_list

    @classmethod
    def delete_comment(cls, post_id, comment_id, user_id):
        error_msg = ''
        comments = Comment.all().filter('post_id =', post_id).order('-created').fetch(limit=10)
        comment = Comment.get_by_id(comment_id)

        if user_id == comment.created_by:
            updated_comments = cls.update_list_on_delete(
                object_list=comments,
                object_id=comment_id
            )
            Comment.delete(comment)
        else:
            error_msg = 'You can delete only your own comments'
            updated_comments = comments
        return updated_comments, error_msg

    @classmethod
    def like_update(cls, post_id, user_id):
        error_msg = ''
        post = Post.get_by_id(post_id)
        current_like = Like.all().filter('post_id =', post_id).filter('user_id =', int(user_id)).get()
        if user_id != post.created_by:
            if not current_like:  # if there is no record, adding a record with value=True
                l = Like(user_id=int(user_id), post_id=int(post_id), like_value=True)
                l.put()
                return l, error_msg

            current_like.like_value = not current_like.like_value
            current_like.put()
        else:
            error_msg = 'You cannot like your own post'
        return current_like, error_msg


class SecurityService(object):
    # Cookie methods
    @classmethod
    def make_secure_val(cls, val):
        return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())

    @classmethod
    def check_secure_val(cls, secure_val):
        try:
            val = secure_val.split('|')[0]
        except IndexError:
            logging.info("could not process cookie hash")
            return False
        if secure_val == SecurityService.make_secure_val(val):
            return val

    # hashing password
    @classmethod
    def _make_salt(cls):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    @classmethod
    def make_pw_hash(cls, username, pw, salt=None):
        salt = salt or cls._make_salt()
        h = hashlib.sha256(username + pw + salt).hexdigest()
        return '%s,%s' % (h, salt)

    @staticmethod
    def valid_pw(name, pw, h):
        try:
            salt = h.split(',')[1]
        except IndexError:
            logging.info("could not process password hash")
            return False
        if h == SecurityService.make_pw_hash(name, pw, salt):
            return True
