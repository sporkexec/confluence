# Allows accessing values via attributes in addition to keys
class AttrDict(dict):
	def __init__(self, *args, **kwargs):
		super(AttrDict, self).__init__(*args, **kwargs)
		self.__dict__ = self

config = AttrDict({
	'websocket_realm': 'confluence', # Hardcoded in web, do not change
	'websocket_path': 'ws', # Hardcoded in web, do not change
	'static_webroot': 'confluence/web', #FIXME handle paths smarter

	'server_host': '127.0.0.1',
	'server_port': 8080, # Hardcoded in web, do not change
	'server_ssl_enabled': True,
	'server_ssl_key_file': 'confluence/ssl/snakeoil.key', #FIXME handle paths smarter
	'server_ssl_cert_file': 'confluence/ssl/snakeoil.crt', #FIXME handle paths smarter
})

