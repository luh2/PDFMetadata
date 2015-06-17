# PDF Metadata Burp Extension

The PDF Metadata Burp Extension provides an additional passive Scanner check for metadata in PDF files.

## License
This software is released under [GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Limitations
* The plugin uses the [PyPDF2](https://pypi.python.org/pypi/PyPDF2) library, which 
> retrieves the PDF file's document information dictionary, if it exists. 
> Note that some PDF files use metadata streams instead of docinfo dictionaries, and these metadata streams will not be accessed by this function.

This plugin requires Jython and PyPDF2. See heading [Python Environment](http://portswigger.net/burp/help/extender.html) in the official documentation of Burp.

Some default installations of Python don't install PyPDF2. In that case you need to download it from the [official site](https://pypi.python.org/pypi/PyPDF2) and specify its location in Burp->Extender->Options->Python Environment "Folder for loading modules".

The extension has been tested with the most current version of Burp (1.6.18), Jython 2.7rc1 and PyPDF2 1.24.

If you test under Windows or use a different Burp version, please share if you experience problems.

If you want to improve the extension, please send me a pull request or leave a comment.