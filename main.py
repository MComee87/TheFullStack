# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Dependecies for tha application

import os
import webapp2
import jinja2
import re
import hmac
import hashlib
import random
import models
import time
from string import letters
from models import User, Post, Comment, Like

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Creating a security around using the secret variable
secret = 'test_security'


def make_secure_val(val):
    """
    Creates the secure value using a secret.
    """
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """
    Verification of the secure value against the secret
    """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        """
        Writes the output to client browser
        """
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """
        Renders the html template
        """
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """
        Sets a secure cookie to the browser
        """
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """
        Read the secure cookie from browser
        """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """
        Checking for user
        """
        print "Base Handler- Login Method"
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        """
        Removes login information
        """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """
        Initialize session to blog from the user session
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        print uid
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '<b><br>')
    response.out.write('post.content')


# Blogging Function

class MainPage(BaseHandler):
    def get(self):
        posts = Post.query().order(Post.created)
        self.render('front.html', posts=posts)


# Post Function
class PostPage(BaseHandler):
    def get(self, post_id):
        """
        Renders Posts to home page
        """
        key = ndb.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()
        like_obj = Like.query(Like.post == post.key)

        if not post:
            self.error(404)
            return
        self.render("permalink.html", post=post)

    def post(self, post_id):
        """
        Loops through the posts
        """
        key = ndb.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return
        self.render("post.html", posts=posts)


class NewPostPage(BaseHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('post_text')

        if subject and content:
            p = Post(parent=models.blog_key(),
                     subject=subject, content=content,
                     author=self.user.key)
            p.put()
            self.redirect('/')
            self.redirect('/blog/%s' % str(p.key.integer_id()))
        else:
            error = "Please enter Subject and Content"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error)


# Edit Post
class EditPost(BaseHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()

        if self.user:
            if post.author.id() != self.user.key.id():
                self.redirect('/blog/%s' % str(post.key.id()))
            else:
                self.render("editpost.html",
                            subject=post.subject,
                            content=post.content)
        else:
            error = 'You must login to view the post'
            self.render('login.html', error=error)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = ndb.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()
        userid = self.read_secure_cookie('user_id')
        subject = self.request.get('subject')
        content = self.request.get('post_text')

        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            time.sleep(0.1)
            self.redirect('/')
        else:
            error = "Please enter Subject and Content"
            self.render("editpost.html",
                        subject=subject,
                        content=content,
                        error=error)


# Delete Post
class DeletePost(BaseHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        if self.user:
            self.render('deletepost.html', post=post)
        else:
            error = "In order to delete post, please login into the site"
            self.render('login.html', error=error)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
        key = ndb.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()

        if post and (post.author.id() == self.user.key.id()):
            post.key.delete()
            time.sleep(0.1)
        self.redirect('/')


# Commenting
class CreateComment(BaseHandler):
    """
    Create the comment into database
    """
    def get(self, post_id):
        if self.user:
            self.render("editcomment.html")
        else:
            self.redirect('/login')

    def post(self, post_id):
        """
        Creates the new comment on single page
        """
        if not self.user:
            return self.redirect('/login')

        key = ndb.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()

        if not post:
            return self.redirect('/')

        content = self.request.get('comment')
        if content:
            c = Comment(post=post.key, content=content, author=self.user.key)
            c.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' % str(post_id))
        else:
            error = "enter valid comment"
            self.render("editcomment.html", content=content, error=error)


class EditComment(BaseHandler):
    def get(self, comment_id):
        key = ndb.Key('Comment', int(comment_id))
        comment = key.get()

        if not comment:
            self.error(404)
            return

        if self.user:
            self.render("editcomment.html", content=comment.content)
        else:
            self.redirect("/login")

    def post(self, comment_id):
        if not self.user:
            return self.redirect("/login")

        key = ndb.Key('Comment', int(comment_id))
        comment = key.get()
        content = self.request.get('comment')

        if content:
            if comment.author.id() == self.user.key.id():
                comment.content = content
                comment.put()
                time.sleep(0.1)
                self.redirect("/blog/%s" % str(comment.post.id()))
            else:
                msg = "You are not the owner of this comment"
                self.render("editcomment.html",
                            content=comment.content,
                            error=msg)
        else:
            msg = "Valid Comment please"
            self.render("editcomment.html",
                        content=comment.content,
                        error=msg)


# #Delete Comment
class DeleteComment(BaseHandler):
    def get(self, comment_id):
        content = self.request.get('comment')
        key = ndb.Key('Comment', int(comment_id))
        comment = key.get()

        if not comment:
            self.error(404)
            return

        if self.user:
            self.render("deletecomment.html", author=self.user.key)
        else:
            self.redirect("/login")

    def post(self, comment_id):
        if not self.user:
            return self.redirect("/login")

        key = ndb.Key('Comment', int(comment_id))
        comment = key.get()

        if comment and comment.author.id() == self.user.key.id():
            comment.key.delete()
            time.sleep(0.1)
        self.redirect('/')


# Like
class LikePost(BaseHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = ndb.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        like_obj = Like.query(Like.post == post.key).get()

        if post.author == self.user.key:
            self.write("You can not like your own post")
        else:
            if like_obj:
                authors = like_obj.author
                for author in authors:
                    if(author == self.user.key):
                        return self.redirect("/blog/%s" % str(post.key.id()))
                like_obj.like_count += 1
                authors.append(self.user.key)
                like_obj.put()
                self.redirect('/')
            else:
                like_obj = Like(post=post.key, like_count=1)
                like_obj.author.append(self.user.key)
                like_obj.put()
                self.redirect('/')


# Unlike Post
class UnlikePost(BaseHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        if not self.user:
            self.redirect('/login')
            return

        like_obj = Like.query(Like.post == post.key).get()

        if like_obj:
            authors = like_obj.author
            for author in authors:
                if author == self.user.key:
                    like_obj.author.remove(author)
                    flag = True
                if not flag:
                    self.redirect('/blog/%s' % str(post.key.id()))
                else:
                    self.write("user doesn't exist")
        else:
            self.write("No Like object created")

# Validation for Username, and password
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

# SignUp, Registration, Login, and Logout for User


class SignUpPage(BaseHandler):
    """
    Sign Up Page. Getting username, password, email,
    and verification of password from user input.
    """
    def get(self):
        self.render("signup.html")

    def post(self):
        signup_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "Invalid Username"
            signup_error = True

        if not valid_password(self.password):
            params['error_password'] = "Password not valid"
            signup_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            signup_error = True

        if signup_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self):
        """
        Make sure user exists
        """
        u = User.by_name(self.username)
        if u:
            msg = "User name exists"
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            key = u.put()
            usercookie = make_secure_val(str(self.username))
            self.response.headers.add_header("Set-Cookie",
                                             "u=%s; Path=/" % usercookie)
            self.login(u)
            self.redirect('/')


# User stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, pw, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, pw, salt)


# Login class
class LoginPage(BaseHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)

        if user:
            usercookie = make_secure_val(str(username))
            self.response.headers.add_header("Set-Cookie",
                                             "u=%s; Path=/" % usercookie)
            self.login(user)
            self.redirect('/')
        else:
            msg = "Login not valid"
            self.render('login.html', error=msg)


# Logout
class LogoutPage(BaseHandler):
    """Logout Class"""
    def get(self):
        self.logout()
        self.redirect('/')

app = webapp2.WSGIApplication([('/', MainPage),
                              ('/blog/([0-9]+)', PostPage),
                              ('/blog/newpost', NewPostPage),
                              ('/blog/like/([0-9]+)', LikePost),
                              ('/blog/unlike/([0-9]+)', UnlikePost),
                              ('/blog/editpost/([0-9]+)', EditPost),
                              ('/blog/deletepost/([0-9]+)', DeletePost),
                              ('/blog/newcomment/([0-9]+)', CreateComment),
                              ('/blog/editcomment/([0-9]+)', EditComment),
                              ('/blog/deletecomment/([0-9]+)', DeleteComment),
                              ('/signup', SignUpPage),
                              ('/login', LoginPage),
                              ('/logout', LogoutPage)
                               ], debug=True)
