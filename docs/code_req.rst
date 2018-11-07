.. _code_req_label:

Code Requirements
==================
All code modification must comply with `PEP-8`_. Currently we are in
process of adding PEP-8 checks to our testing however you can run tools such as
pycodestyle_ to manually check.

All modules, functions and methods must include a detailed documentation.
It must also adhere to `PEP-257`_ rules. You can check compliance using pydocstyle_
tool.

If you are adding a new command line argument you must add proper documentation
in the README file located in project root folder.

.. _`PEP-8`: https://www.python.org/dev/peps/pep-0008/
.. _pycodestyle: https://github.com/PyCQA/pycodestyle
.. _`PEP-257`: https://www.python.org/dev/peps/pep-0257/
.. _pydocstyle: https://github.com/PyCQA/pydocstyle