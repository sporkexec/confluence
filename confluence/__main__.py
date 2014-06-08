import sys
import datetime

from twisted.python import log
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks

from twisted.web.server import Site
from twisted.web.static import File
from twisted.internet.ssl import DefaultOpenSSLContextFactory

from autobahn.twisted.resource import WebSocketResource
from autobahn.twisted.websocket import WebSocketServerProtocol, WebSocketServerFactory

from config import config


class MyServerProtocol(WebSocketServerProtocol):
	def onConnect(self, request):
		print("Client connecting: {0}".format(request.peer))
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

def make_server_url():
	if config.server_ssl_enabled:
		protocol = 'wss://'
	else:
		protocol = 'ws://'
	host = config.server_host
	port = config.server_port
	url = protocol + host + ':' + str(port)
	return url

if __name__ == '__main__':
	log.startLogging(sys.stdout)

	# Setup websocket protocol
	server_url = make_server_url()
	ws_factory = WebSocketServerFactory(server_url, debug=False)
	ws_factory.protocol = MyServerProtocol
	ws_resource = WebSocketResource(ws_factory)

	# Setup static resource as server root, route in websocket
	root = File(config.static_webroot)
	root.putChild(config.websocket_path, ws_resource)

	site = Site(root)
	if config.server_ssl_enabled:
		ssl_context = DefaultOpenSSLContextFactory(config.server_ssl_key_file, config.server_ssl_cert_file)
		reactor.listenSSL(config.server_port, site, ssl_context)
	else:
		reactor.listenTCP(config.server_port, site)

	reactor.run()

