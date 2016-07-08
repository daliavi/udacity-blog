import logging
import os
import jinja2
import time

import webapp2

from models import User, Post, Comment, Like
from service import SecurityService, UserService, PostService

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = SecurityService.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s;Path=/' % (name, cookie_val))

    def read_cookie_val(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and SecurityService.check_secure_val(cookie_val)

    def login(self,user):
        self.set_secure_cookie('user_id',str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=;Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie_val('user_id')
        self.user = uid and User.by_id(int(uid))


class SignUpHandler(BlogHandler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        params = dict(username=self.username,  # dictionary for all errors
                      email=self.email)

        if not UserService.valid_username(self.username):
            params['username_error'] = 'Invalid username'
            have_error = True

        if not UserService.valid_password(self.password):
            params['password_error'] = 'Invalid password'
            have_error = True
        elif self.password != self.verify:
            params['password_mismatch_error'] = 'Passowrds do not match'
            have_error = True

        if not UserService.valid_email(self.email):
            params['email_error'] = 'Invalid email'
            have_error = True

        if have_error:
            self.render("signup.html", **params)

        else:
            u = User.by_name(self.username)
            if u:
                msg = 'The user already exists'
                self.render('signup.html', username_error=msg)
            else:
                u = UserService.register(
                    self.username,
                    self.password,
                    self.email
                )
                u.put()
                self.set_secure_cookie("user_id", str(u.key().id()))
                self.redirect("/blog")


class LoginHandler(BlogHandler):
    def write_form(self,*a, **kw):
        self.render("login.html",*a, **kw)

    def get(self):
        self.write_form()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        u = UserService.validate_login(username,password)

        if u:
            self.login(u)
            self.redirect("/blog")
        else:
            msg = "Invalid login"
            self.write_form(username_error=msg)


class LogoutHandler(BlogHandler):  # clear the cookie and redirect to the signup page
    def get(self):
        self.logout()
        self.redirect('/blog')


class MainHandler(BlogHandler):
    def render_blog(self, posts=''):
        if self.user:
            username = self.user.username
        else:
            username = ""
        posts = Post.all().order('-created').fetch(limit=10)
        self.render("blog.html",
                    posts=posts, username=username)

    def get(self):
        self.render_blog()


class ShowPostHandler(BlogHandler):
    def get(self, post_id):
        post_bundle = PostService.get_post_bundle(  # getting the data bundle required to render the page
            post_id=int(post_id),
            user=self.user)
        self.render("showpost.html",
                    **post_bundle._asdict()
                    )

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog/login')
            return

        # get all the data
        post_bundle = PostService.get_post_bundle(
            post_id=int(post_id),
            user=self.user)
        error_msg = ''

        # checking which button was pressed
        if self.request.POST.get('submit_comment'):
            comment = self.request.get('comment_content')
            if comment:
                new_comment = PostService.add_comment(
                    comment=self.request.get('comment_content'),
                    post_id=int(post_id),
                    user_id=self.user.key().id()
                )
                # updating the bundle with the new comment
                post_bundle.comments.insert(0, new_comment)
            else:
                error_msg = "Please enter a comment"

        elif self.request.POST.get('update_comment'):
            comment_id = self.request.POST.get('comment_id')
            comment_author = int(self.request.POST.get('comment_author'))
            if comment_author != self.user.key().id():
                error_msg = "You can edit only your own comments"
            else:
                self.redirect('/blog/editcomment/' + str(comment_id))

        elif self.request.POST.get('edit_post'):
            if post_bundle[0].created_by != self.user.key().id():
                error_msg = "You can edit only your own posts"
            else:
                self.redirect('/blog/editpost/' + str(post_id))

        elif self.request.POST.get('like'):
            new_like, error_msg = PostService.like_update(
                post_id=int(post_id),
                user_id=self.user.key().id()
            )
            # updating the bundle with the new like
            post_bundle = post_bundle._replace(like=new_like)

        elif self.request.POST.get('delete_comment'):
            comment_id = self.request.POST.get('comment_id')
            updated_comments, error_msg = PostService.delete_comment(
                post_id=int(post_id),
                comment_id=int(comment_id),
                user_id=self.user.key().id()

            )
            # updating the bundle updated list of comments
            post_bundle = post_bundle._replace(comments=updated_comments)

        elif self.request.POST.get('delete_post'):
            posts, error_msg = PostService.delete_post(
                post_id=int(post_id),
                user_id=self.user.key().id()
            )
            if not error_msg:
                time.sleep(0.5)
                self.redirect('/blog')
                return

        self.render('showpost.html',
                    error=error_msg,
                    **post_bundle._asdict())  # passing the bundle as dictionary
                                              # the bundle is used to update the page with the new data
                                              # because of the race condition

class NewPostHandler(BlogHandler):
    def render_new_post(self, subject="", content="", error=""):
        self.render("newpost.html",
                    subject=subject,
                    content=content,
                    error=error
                    )

    def get(self):
        self.render_new_post()

    def post(self):
        if not self.user:
            self.redirect('/blog/login')
            return

        subject = self.request.get("subject")
        content = self.request.get("content")

        if self.request.POST.get('save_post'):
            if subject and content:
                p = Post(subject=subject, content=content, created_by=self.user.key().id())
                p.put()
                self.redirect("/blog/" + str(p.key().id()))
            else:
                error = "Please enter both subject and content"
                self.render_new_post(subject, content, error)

        elif self.request.POST.get('cancel_new_post'):
            self.redirect('/blog')


class EditPostHandler(BlogHandler):
    def get(self, post_id):
        post_bundle = PostService.get_post_bundle(
            post_id=int(post_id),
            user=self.user
        )
        self.render("editpost.html",
                    error='',
                    **post_bundle._asdict()
                    )

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog/login')
            return

        if self.request.POST.get('save_post'):
            post_bundle = PostService.get_post_bundle(
                post_id=int(post_id),
                user=self.user
            )

            new_post, error_msg = PostService.update_post(
                post_id=int(post_id),
                user_id=int(self.user.key().id()),
                subject=self.request.get('subject'),
                content=self.request.get('content')
            )

            if error_msg:
                self.render('editpost.html',
                            error=error_msg,
                            **post_bundle._asdict()
                            )
                return

        self.redirect('/blog/' + post_id)


class EditCommentHandler(BlogHandler):
    def get(self, comment_id, error=''):
        comment = Comment.get_by_id(int(comment_id))
        self.render('editcomment.html',
                    content=comment.content
                    )

    def post(self, comment_id):
        if not self.user:
            self.redirect('/blog/login')
            return

        if self.request.POST.get('save_comment'):
            new_comment, error_msg = PostService.update_comment(
                comment_id=int(comment_id),
                user_id=int(self.user.key().id()),
                content=self.request.get('content')
            )

            if error_msg:
                self.render('editcomment.html',
                            error=error_msg,
                            comment_id=comment_id
                            )
            else:
                time.sleep(0.5)
                self.redirect('/blog/' + str(new_comment.post_id))
        else:
            comment = Comment.get_by_id(int(comment_id))
            self.redirect('/blog/' + str(comment.post_id))
