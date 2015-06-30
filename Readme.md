# PDF Metadata Burp Extension

The PDF Metadata Burp Extension provides an additional passive Scanner check for metadata in PDF files.

## License
This software is released under [GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Various
This plugin requires Jython and [pdfminer](http://www.unixuser.org/~euske/python/pdfminer/). See heading [Python Environment](http://portswigger.net/burp/help/extender.html) in the official documentation of Burp. 

Some default installations of Python might not install pdfminer. In that case you need to download it from the [official site](http://www.unixuser.org/~euske/python/pdfminer/) and specify its location in Burp->Extender->Options->Python Environment "Folder for loading modules".

The extension has been tested with Kali Linux, Burp version 1.6.18 and newer, Jython installation (not stand-alone) 2.7rc1.

If you test under Windows or use a different Burp version, please share if you experience problems.

If you want to improve the extension, please send me a pull request or leave a comment.