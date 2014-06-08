import bcrypt #XXX see below

# Allows accessing values via attributes in addition to keys
class AttrDict(dict):
	def __init__(self, *args, **kwargs):
		super(AttrDict, self).__init__(*args, **kwargs)
		self.__dict__ = self

config = AttrDict({
	'server_host': '127.0.0.1',
	'server_port': 8080,
	'server_ssl_enabled': True,
	'server_ssl_key_file': 'confluence/ssl/snakeoil.key', #FIXME handle paths smarter
	'server_ssl_cert_file': 'confluence/ssl/snakeoil.crt', #FIXME handle paths smarter

	'app_static_webroot': 'confluence/web', #FIXME handle paths smarter
	'app_websocket_path': 'ws', # Hardcoded in web, do not change

	'auth_websocket_path': 'auth', # Hardcoded in web, do not change
	'auth_credentials': { #XXX insecure
		'root': bcrypt.hashpw('hunter2', bcrypt.gensalt()),
	},
})

