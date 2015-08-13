# PDF Metadata Burp Extension

The PDF Metadata Burp Extension provides an additional passive Scanner check for metadata in PDF files.

## License
This software is released under [GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Requirements
This plugin requires Jython, [pdfminer](http://www.unixuser.org/~euske/python/pdfminer/) and [chardet](https://pypi.python.org/pypi/chardet). See heading [Python Environment](http://portswigger.net/burp/help/extender.html) in the official documentation of Burp. 

Some default installations of Python might not install pdfminer or chardet. In that case you need to download them from the official sites and specify their location in Burp->Extender->Options->Python Environment "Folder for loading modules". 

To be able to parse the XMP Metadata, the extension uses SAX which Jython doesn't include through the python modules, but through [xerces](https://xerces.apache.org/). You need to download the jar-file and specify it in the classpath when starting:

    java -classpath /path/to/xercesImpl.jar:/path/to/burp.jar burp.StartBurp

## Config Options
You can chose between fast and thorough scanning. Thorough is very strongly ressource consuming, so I recommend you only use it when you've noticed that the web app you are testing is generating PDF files that do not contain ".pdf" in the URL. I also recommend you do it once you are done testing for the day. By default the option is set to fast. In this mode it will only analyze the response if ".pdf" was part of the requested URL.

![Config Option](https://github.com/luh2/PDFMetadata/blob/master/screenshots/pdf_metadaten_screenshot_config.png)

### Kali
Usually Kali comes with a default installation of both chardet and pdfminer. If they are not installed use:

    apt-get install python-pdfminer python-chardet

Their location needs to be specified anyway though.

Kali also comes with a packaged version of Xerces, which can be installed with

    apt-get install libxerces2-java

## Screenshot
![screenshot of version 0.4](https://github.com/luh2/PDFMetadata/blob/master/screenshots/screenshotv04.png)

## Various
The extension has been tested with Kali Linux, Burp version 1.6.18 and newer, Jython installation (not stand-alone) 2.7rc1.

If you test under Windows or use a different Burp version, please share if you experience problems.

If you want to improve the extension, please send me a pull request or leave a comment.