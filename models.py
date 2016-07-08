import re
from google.appengine.ext import db

# Creating database tables


class Post(db.Model):  # Posts table
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.IntegerProperty(required=True)


class Comment(db.Model):  # Comments table
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)


class Like(db.Model):  # Likes table
    created = db.DateTimeProperty(auto_now_add=True)
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    like_value = db.BooleanProperty(required=True)


class User(db.Model):  # Users table
    # user validation regex
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PSW_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)  # stores password hash
    email = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    @classmethod
    def by_name(cls, username):
        u = cls.all().filter('username =', username).get()
        return u

    @classmethod
    def get_id(cls):
        user_id = User.key().id()
        return user_id
