from __future__ import absolute_import

from twisted.python import log
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks

from twisted.web.server import Site
from twisted.web.static import File
from twisted.internet.ssl import DefaultOpenSSLContextFactory

from autobahn.twisted.resource import WebSocketResource
from autobahn.twisted.websocket import WebSocketServerProtocol, WebSocketServerFactory
from autobahn.websocket.protocol import createWsUrl

from confluence.config import config
from confluence.auth import AuthFactory


class MyServerProtocol(WebSocketServerProtocol):
	def onConnect(self, request):
		print("Client connecting: {0}".format(request.peer))
		print(request.headers)
	def onOpen(self):
		print("WebSocket connection open.")
	def onMessage(self, payload, isBinary):
		if isBinary:
			print("Binary message received: {0} bytes".format(len(payload)))
		else:
			print("Text message received: {0}".format(payload.decode('utf8')))
		self.sendMessage(payload, isBinary)
	def onClose(self, wasClean, code, reason):
		print("WebSocket connection closed: {0}".format(reason))

if __name__ == '__main__':
	import sys
	log.startLogging(sys.stdout)

	# Setup app websocket protocol
	server_url = createWsUrl(config.server_host, port=config.server_port,
	                         isSecure=config.server_ssl_enabled)
	app_ws_factory = WebSocketServerFactory(server_url, debug=False)
	app_ws_factory.protocol = MyServerProtocol
	app_ws_resource = WebSocketResource(app_ws_factory)

	# Setup auth websocket protocol
	auth_ws_factory = AuthFactory(server_url, debug=False)
	auth_ws_resource = WebSocketResource(auth_ws_factory)

	# Setup static resource as server root, route in websockets
	root = File(config.app_static_webroot)
	root.putChild(config.app_websocket_path, app_ws_resource)
	root.putChild(config.auth_websocket_path, auth_ws_resource)

	site = Site(root)
	if config.server_ssl_enabled:
		ssl_context = DefaultOpenSSLContextFactory(config.server_ssl_key_file, config.server_ssl_cert_file)
		reactor.listenSSL(config.server_port, site, ssl_context)
	else:
		reactor.listenTCP(config.server_port, site)

	reactor.run()

