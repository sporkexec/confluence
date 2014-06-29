from __future__ import absolute_import
from confluence.config import config

AUTH_REQUIRED = 1
AUTH_SUCCESS = 2

from twisted.web.resource import Resource
class RequestAuthenticationResource(Resource):
	def render(self, request):
		from twisted.web import http
		request.setHeader('WWW-Authenticate', 'Basic realm="{0}"'.format(config.auth_realm))
		request.setResponseCode(http.UNAUTHORIZED)
		return ''

class PurgeAuthCredentials(Resource):
	def render(self, request):
		#TODO Redirect to root with active:active@host auth to purge creds
		#     Then have *that* redirect to normal root (clientside somehow, I guess) so url looks normal
		return ''

from twisted.web.server import Site
class AuthSite(Site):
	"""
	Handles HTTP authentication mechanism. Users navigate to this resource and
	authenticate with basic auth (over TLS), receiving a session cookie on
	success. We use this cookie to auth to the application websocket because
	basic auth headers are not forwarded to websocket connections, but cookies
	are (go figure).

	Upon successful authentication, a session cookie is given and the client is
	redirected to an intermediate request which sets the basic auth headers to
	a safe value, and then redirected to the root of the application.

	Upon logout, the client is redirected to a request which sets the basic
	auth headers to a known "deauthenticated" value, which lets this resource
	know to resume requesting credentials rather than sending the client to the
	application root.

	These steps let us authenticate without exposing credentials to javascript
	and also work around 
	"""
	safe_credential = 'active' # Used to purge browser HTTP auth cache after valid login
	logout_credential = 'deauth' # Used to indicate user has deauthed, auth will be requested

	def __init__(self, auth_manager, root):
		Site.__init__(self, root)
		self.auth_manager = auth_manager

	def getResourceFor(self, request):
		userpass = self.check_userpass_auth(self, request)
		if userpass == AUTH_SUCCESS:
			return PurgeAuthCredentials()

		cookie = self.check_cookie_auth(self, request)
		if cookie == AUTH_SUCCESS:
			return Site.getResourceFor(self, request)

		return RequestAuthenticationResource()


	def check_userpass_auth(self, request):
		username = request.getUser()
		password = request.getPassword()

		if username == self.dummy_credential and password == self.dummy_credential:
			# HTTP auth cache has been purged, neutral state
			return AUTH_REQUIRED

		if username == '' and password == '':
			# No attempt yet, request auth
			return AUTH_REQUIRED

		if username == self.logout_credential and password == self.logout_credential:
			# User is requesting logout
			#TODO lookup and purge session
			return AUTH_REQUIRED

		#TODO: Rate-limit before processing anything
		valid = self.auth_manager.is_valid_credentials(username, password)
		if not valid:
			#TODO: Record failure for rate-limiting/ip-banning/etc
			return AUTH_REQUIRED

		# Authentication succeeded
		session = self.auth_manager.create_session(request, username)
		self.set_session(request, session) #FIXME: Use twisted Sessions
		return AUTH_SUCCESS

	def set_session(self, request, session):
		#XXX: twisted.web.http.Request.addCookie could use an httponly flag
		request.addCookie('CONFLUENCEID', session.token+'; HttpOnly', secure=True)

class AuthManager:
	"""
	Handles creation, storage, and checking of all authentication-related state.
	"""
	def __init__(self):
		self._create_safe_compare()
		# Store of active sessions
		self._active_sessions = {}
		# Hashed with session tokens to create unpredictable dict keys
		self._session_salt = self._generate_session_token()

	def _create_safe_compare(self):
		"""
		Creates a constant-time string comparison function on
		AuthFactory.safe_compare. Python 2.7.7 and later has hmac.compare_digest
		for this, for older Pythons we roll our own, which leaks length and
		possibly character information with a timing attack on the CPython int
		cache.
		"""
		try:
			# >= 2.7.7
			from hmac import compare_digest as safe_compare
		except ImportError:
			# hmac.compare_digest is new to Python 2.7.7, we need a fallback
			print('[auth] hmac.compare_digest missing, falling back to python implementation')
			def safe_compare(a, b):
				if len(a) != len(b):
					return False
				result = 0
				for x, y in zip(a, b):
					result |= ord(x) ^ ord(y)
				return result == 0
		self.safe_compare = safe_compare

	def _generate_session_token(self):
		from base64 import b64encode
		from os import urandom
		# Pull many random bytes then base64 then toss out funny chars for
		# transport. OWASP recommends minimum 16B session IDs, I'm being
		# generous with this because I'm uncertain how much entropy can be
		# tossed out with funny chars in the worst case. After all this
		# transformation I've seen final lengths of anywhere from 70-86 in
		# testing.
		return b64encode(urandom(64)).translate(None, '=/+')

	def is_valid_credentials(self, given_username, given_password):
		"""
		Returns whether login credentials are valid.
		"""
		# Attempts to be constant-time.
		import bcrypt
		valid_creds = config.auth_credentials
		for (valid_user, valid_hash) in valid_creds.items():
			iter_hash = bcrypt.hashpw(given_password, valid_hash)
			user_matches = self.safe_compare(given_username, valid_user)
			pass_matches = self.safe_compare(iter_hash, valid_hash)
			if int(user_matches) + int(pass_matches) == 2:
				return True
		return False

	def create_session(self, request, username):
		"""
		Given a request object and the authenticated username, returns a new
		AuthSession object.
		"""
		from datetime import datetime
		from hashlib import sha256
		session = AuthSession()
		session.ip_address = request.getClientIP()
		session.username = username
		session.time_created = datetime.now()
		session.time_active = datetime.now()
		session.token = self._generate_session_token()
		# Creates unpredictable hash for dict, user-supplied token comes first
		# to prevent simple length-extension attacks. 
		session_hash = sha256(session.token + ':' + self._session_salt).hexdigest()
		self._active_sessions[session_hash] = session
		return session

from confluence.util import AttrDict
class AuthSession(AttrDict): pass #TODO: Add normal fields here once we suss out requirements
