import sys
import datetime

from twisted.python import log
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import serverFromString

from twisted.web.server import Site
from twisted.web.static import File

from autobahn.wamp import router
from autobahn.twisted.util import sleep
from autobahn.twisted.resource import WebSocketResource
from autobahn.twisted import wamp, websocket

class MyBackendComponent(wamp.ApplicationSession):
	"""
	Application code goes here. This is an example component that provides
	a simple procedure which can be called remotely from any WAMP peer.
	It also publishes an event every second to some topic.
	"""
	def onConnect(self):
		self.join('confluence')

	@inlineCallbacks
	def onJoin(self, details):

		## register a procedure for remote calling
		##
		def utcnow():
			print("Someone is calling me;)")
			now = datetime.datetime.utcnow()
			return now.strftime("%Y-%m-%dT%H:%M:%SZ")

		reg = yield self.register(utcnow, u'com.timeservice.now')
		print("Registered procedure with ID {}".format(reg.id))

		## publish events to a topic
		##
		counter = 0
		while False:
			self.publish(u'com.myapp.topic1', counter)
			print("Published event.")
			counter += 1
			yield sleep(1)

if __name__ == '__main__':
	log.startLogging(sys.stdout)

	# Setup websocket resource
	router_factory = router.RouterFactory()
	session_factory = wamp.RouterSessionFactory(router_factory)
	session_factory.add(MyBackendComponent())
	transport_factory = websocket.WampWebSocketServerFactory(session_factory, 'ws://localhost:8080', debug = False, debug_wamp = False)
	ws_resource = WebSocketResource(transport_factory)

	# Setup static resource as server root, route in websocket
	root = File('/home/user/dev/confluence/confluence/web')
	root.putChild('ws', ws_resource)

	site = Site(root)
	reactor.listenTCP(8080, site)
	reactor.run()

