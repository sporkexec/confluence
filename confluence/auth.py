from autobahn.twisted.websocket import WebSocketServerProtocol
class AuthProtocol(WebSocketServerProtocol):
	"""
	Exposes only functionality necessary to authenticate users and assign
	session tokens. Every message will have a response. Clients should not send
	concurrent messages, as no attempt is made to pair requests to their
	responses.
	"""
	allowed_commands = ('login',)

	def onConnect(self, request):
		print("[auth] Client connecting: {0}".format(request.peer))
	def onClose(self, wasClean, code, reason):
		print("[auth] Connection closed: {0}".format(reason))

	def onMessage(self, payload, isBinary):
		# Deny binary messages
		if isBinary:
			self.sendMessage("ignored:invalid content")
			return

		args = payload.split(':')
		command = args[0]
		args = args[1:]

		# Whitelist command and handoff to method
		if command not in self.allowed_commands:
			self.sendMessage("ignored:invalid command")
			return
		getattr(self, command)(args)

	def login(self, args):
		#FIXME: Rate-limit before processing anything
		if len(args) != 2:
			self.sendMessage("ignored:invalid argument count")
			return

		username = args[0]

		# For obscurity and allowing special chars, this is over TLS already
		import base64
		try:
			password = base64.b64decode(args[1])
		except TypeError:
			self.sendMessage("ignored:invalid argument type")
			return

		valid = self.factory.is_valid_credentials(username, password)
		if not valid:
			#FIXME: Record failure for rate-limiting/ip-banning/etc
			self.sendMessage("failure:Invalid username or password.")
			return

		# Authentication succeeded
		session = self.factory.create_session(self, username)
		self.sendMessage("success:{0}:{1}".format(username, session.token))

from autobahn.twisted.websocket import WebSocketServerFactory
class AuthFactory(WebSocketServerFactory):
	protocol = AuthProtocol
	def __init__(self, *args, **kwargs):
		WebSocketServerFactory.__init__(self, *args, **kwargs)
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
		from config import config
		valid_creds = config.auth_credentials
		for (valid_user, valid_hash) in valid_creds.items():
			iter_hash = bcrypt.hashpw(given_password, valid_hash)
			user_matches = self.safe_compare(given_username, valid_user)
			pass_matches = self.safe_compare(iter_hash, valid_hash)
			if int(user_matches) + int(pass_matches) == 2:
				return True
		return False

	def create_session(self, protocol, username):
		"""
		Given a protocol object and the authenticated username, returns a new
		AuthSession object.
		"""
		from datetime import datetime
		from hashlib import sha256
		session = AuthSession()
		session.peer = protocol.peer
		session.username = username
		session.time_created = datetime.now()
		session.time_active = datetime.now()
		session.token = self._generate_session_token()
		# Creates unpredictable hash for dict, user-supplied token comes first
		# to prevent simple length-extension attacks. 
		session_hash = sha256(session.token + ':' + self._session_salt).hexdigest()
		self._active_sessions[session_hash] = session
		return session

from util import AttrDict
class AuthSession(AttrDict): pass #TODO: Add normal fields here once we suss out requirements
