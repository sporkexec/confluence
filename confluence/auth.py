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
			self.sendMessage("ignored:invalid arguments")
			return

		username = args[0]

		# For obscurity and allowing special chars, this is over TLS already
		import base64
		password = base64.decodestring(args[1])

		valid = self.factory.is_valid_credentials(username, password)
		if not valid:
			#FIXME: Record failure for rate-limiting/ip-banning/etc
			self.sendMessage("failure:Invalid username or password.")
			return
		# Success
		self.sendMessage("success:TODO")

from autobahn.twisted.websocket import WebSocketServerFactory
class AuthFactory(WebSocketServerFactory):
	protocol = AuthProtocol
	def __init__(self, *args, **kwargs):
		WebSocketServerFactory.__init__(self, *args, **kwargs)
		#super(AuthFactory, self).__init__(*args, **kwargs)
		self._create_safe_compare()

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

	def is_valid_credentials(self, given_username, given_password):
		# Attempts to be constant-time.
		import bcrypt
		from config import config
		valid_creds = config.auth_credentials
		is_valid = 0
		for (valid_user, valid_hash) in valid_creds.items():
			iter_hash = bcrypt.hashpw(given_password, valid_hash)
			user_matches = self.safe_compare(given_username, valid_user)
			pass_matches = self.safe_compare(iter_hash, valid_hash)
			is_valid += (int(user_matches) + int(pass_matches)) / 2
		return is_valid > 0

