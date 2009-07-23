#!/usr/bin/env python
#
# Copyright 2009 FriendFeed
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import base64
import binascii
import Cookie
import email.utils
import friendfeed
import functools
import hashlib
import hmac
import logging
import os
import time
import urllib2

from django.utils import simplejson
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template

# To get a FriendFeed API Consumer Token for your application,
# visit http://friendfeed.com/api/register
FRIENDFEED_API_TOKEN = dict(
    key="yourkeyhere",
    secret="yoursecrethere",
)


def authenticated(method):
    """Decorator that requires the user is logged into FriendFeed via OAuth.

    The authenticated FriendFeed session becomes available as self.friendfeed
    when this decorator is used. The username of the authenticated user is
    available as self.friendfeed_username.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        cookie_val = parse_cookie(self.request.cookies.get("FF_API_AUTH"))
        if not cookie_val:
            if self.request.method != "GET":
                self.error(403)
                return
            self.redirect("/oauth/authorize")
            return
        try:
            key, secret, username = cookie_val.split("|")
        except:
            self.redirect("/oauth/authorize")
            return
        self.friendfeed = friendfeed.FriendFeed(
            FRIENDFEED_API_TOKEN, dict(key=key, secret=secret))
        self.friendfeed_username = username
        return method(self, *args, **kwargs)
    return wrapper


class FeedHandler(webapp.RequestHandler):
    """Renders a FriendFeed feed for the authenticated user."""
    @authenticated
    def get(self, feed_id):
        if not feed_id: feed_id = "home"

        # Show collapsed comments/likes, but show all comments on entry pages
        args = dict(maxlikes="auto")
        if not feed_id.startswith("e/"):
            args.update(maxcomments="auto")
        try:
            feed = self.friendfeed.fetch_feed(feed_id, **args)
        except urllib2.HTTPError, e:
            if e.code == 401:
                self.redirect("/oauth/authorize")
                return
            raise
        feed_list = self.friendfeed.fetch_feed_list()
        path = os.path.join(os.path.dirname(__file__), "feed.html")
        self.response.out.write(template.render(path, dict(
            show_header=feed_id != "home" and not feed_id.startswith("e/"),
            show_share=feed_id == "home" or "post" in feed.get("commands", []),
            show_direct="dm" in feed.get("commands", []),
            request=self.request,
            feed_list=feed_list,
            feed=feed,
            friendfeed_username=getattr(self, "friendfeed_username", None),
        )))


class GetEntryHandler(webapp.RequestHandler):
    @authenticated
    def get(self, entry_id):
        entry = self.friendfeed.fetch_entry(entry_id)
        comments = [{"body": c["body"], "from": c["from"]} for c in
                    entry.get("comments", [])]
        self.response.out.write(simplejson.dumps({"comments": comments}))


class CommentHandler(webapp.RequestHandler):
    @authenticated
    def post(self):
        comment = self.friendfeed.post_comment(
            entry=self.request.get("entry"),
            body=self.request.get("body"))
        json = {"body": comment["body"], "from": comment["from"]}
        self.response.out.write(simplejson.dumps(json))


class LikeHandler(webapp.RequestHandler):
    @authenticated
    def post(self):
        like = self.friendfeed.post_like(self.request.get("entry"))
        self.response.out.write(simplejson.dumps({"success": True}))


class DeleteLikeHandler(webapp.RequestHandler):
    @authenticated
    def post(self):
        like = self.friendfeed.delete_like(self.request.get("entry"))
        self.response.out.write(simplejson.dumps({"success": True}))


class HideHandler(webapp.RequestHandler):
    @authenticated
    def post(self):
        entry = self.friendfeed.hide_entry(self.request.get("entry"))
        self.response.out.write(simplejson.dumps({"success": True}))


class UnhideHandler(webapp.RequestHandler):
    @authenticated
    def post(self):
        entry = self.friendfeed.unhide_entry(self.request.get("entry"))
        self.response.out.write(simplejson.dumps({"success": True}))


class EntryHandler(webapp.RequestHandler):
    @authenticated
    def post(self):
        entry = self.friendfeed.post_entry(
            body=self.request.get("body"),
            to=self.request.get("to", "me"))
        self.redirect(self.request.get("next", "/"))


class SubscribeHandler(webapp.RequestHandler):
    @authenticated
    def post(self):
        status = self.friendfeed.subscribe(self.request.get("feed"))
        self.redirect(self.request.get("next", "/"))


class UnsubscribeHandler(webapp.RequestHandler):
    @authenticated
    def post(self):
        status = self.friendfeed.unsubscribe(self.request.get("feed"))
        self.redirect(self.request.get("next", "/"))


class OAuthCallbackHandler(webapp.RequestHandler):
    """Saves the FriendFeed OAuth user data in the FF_API_AUTH cookie."""
    def get(self):
        request_key = self.request.get("oauth_token")
        cookie_val = parse_cookie(self.request.cookies.get("FF_API_REQ"))
        if not cookie_val:
            logging.warning("Missing request token cookie")
            self.redirect("/")
            return
        cookie_key, cookie_secret = cookie_val.split("|")
        if cookie_key != request_key:
            logging.warning("Request token does not match cookie")
            self.redirect("/")
            return
        req_token = dict(key=cookie_key, secret=cookie_secret)
        try:
            access_token = friendfeed.fetch_oauth_access_token(
                FRIENDFEED_API_TOKEN, req_token)
        except:
            logging.warning("Could not fetch access token for %r", request_key)
            self.redirect("/")
            return
        data = "|".join(access_token[k] for k in ["key", "secret", "username"])
        set_cookie(self.response, "FF_API_AUTH", data,
                   expires=time.time() + 30 * 86400)
        self.redirect("/")


class OAuthAuthorizeHandler(webapp.RequestHandler):
    """Redirects the user to authenticate with FriendFeed."""
    def get(self):
        # Save the Request Token in a cookie to verify upon callback to help
        # prevent http://oauth.net/advisories/2009-1
        token = friendfeed.fetch_oauth_request_token(FRIENDFEED_API_TOKEN)
        data = "|".join([token["key"], token["secret"]])
        set_cookie(self.response, "FF_API_REQ", data)
        self.redirect(friendfeed.get_oauth_authentication_url(token))


def set_cookie(response, name, value, domain=None, path="/", expires=None):
    """Generates and signs a cookie for the give name/value"""
    timestamp = str(int(time.time()))
    value = base64.b64encode(value)
    signature = cookie_signature(value, timestamp)
    cookie = Cookie.BaseCookie()
    cookie[name] = "|".join([value, timestamp, signature])
    cookie[name]["path"] = path
    if domain: cookie[name]["domain"] = domain
    if expires:
        cookie[name]["expires"] = email.utils.formatdate(
            expires, localtime=False, usegmt=True)
    response.headers._headers.append(("Set-Cookie", cookie.output()[12:]))


def parse_cookie(value):
    """Parses and verifies a cookie value from set_cookie"""
    if not value: return None
    parts = value.split("|")
    if len(parts) != 3: return None
    if cookie_signature(parts[0], parts[1]) != parts[2]:
        logging.warning("Invalid cookie signature %r", value)
        return None
    timestamp = int(parts[1])
    if timestamp < time.time() - 30 * 86400:
        logging.warning("Expired cookie %r", value)
        return None
    try:
        return base64.b64decode(parts[0]).strip()
    except:
        return None


def cookie_signature(*parts):
    """Generates a cookie signature.

    We use the FriendFeed API token since it is different for every app (so
    people using this example don't accidentally all use the same secret).
    """
    hash = hmac.new(FRIENDFEED_API_TOKEN["secret"], digestmod=hashlib.sha1)
    for part in parts: hash.update(part)
    return hash.hexdigest()


application = webapp.WSGIApplication([
    (r"/oauth/callback", OAuthCallbackHandler),
    (r"/oauth/authorize", OAuthAuthorizeHandler),
    (r"/a/entry/(.*)", GetEntryHandler),
    (r"/a/comment", CommentHandler),
    (r"/a/like", LikeHandler),
    (r"/a/like/delete", DeleteLikeHandler),
    (r"/a/hide", HideHandler),
    (r"/a/unhide", UnhideHandler),
    (r"/a/entry", EntryHandler),
    (r"/a/subscribe", SubscribeHandler),
    (r"/a/unsubscribe", UnsubscribeHandler),
    (r"/(.*)", FeedHandler),
])

def main():
    import google.appengine.ext.webapp.util
    google.appengine.ext.webapp.util.run_wsgi_app(application)


if __name__ == "__main__":
  main()
