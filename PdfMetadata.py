# Burp PDF Metadata Extension
# Copyright (c) 2015, Veit Hailperin (scip AG)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IExtensionStateListener
from burp import IExtensionHelpers
from burp import ITab
from javax import swing
import StringIO
from pdfminer.pdfparser import PDFParser, PDFSyntaxError, PSEOF
from pdfminer.pdfdocument import PDFDocument, PDFEncryptionError, PDFTypeError
from pdfminer.pdftypes import resolve1
import chardet
import re

VERSION = "0.5"
# Start xmp.py
"""
    xmp.py
    ~~~~~~

    Parses XMP metadata from PDF files.

    By Matt Swain. Released under the MIT license.
"""

from collections import defaultdict
from xml.etree import ElementTree as ET

RDF_NS = '{http://www.w3.org/1999/02/22-rdf-syntax-ns#}'
XML_NS = '{http://www.w3.org/XML/1998/namespace}'
NS_MAP = {
    'http://www.w3.org/1999/02/22-rdf-syntax-ns#'    : 'rdf',
    'http://purl.org/dc/elements/1.1/'               : 'dc',
    'http://ns.adobe.com/xap/1.0/'                   : 'xap',
    'http://ns.adobe.com/pdf/1.3/'                   : 'pdf',
    'http://ns.adobe.com/xap/1.0/mm/'                : 'xapmm',
    'http://ns.adobe.com/pdfx/1.3/'                  : 'pdfx',
    'http://prismstandard.org/namespaces/basic/2.0/' : 'prism',
    'http://crossref.org/crossmark/1.0/'             : 'crossmark',
    'http://ns.adobe.com/xap/1.0/rights/'            : 'rights',
    'http://www.w3.org/XML/1998/namespace'           : 'xml'
}

class XmpParser(object):
    """
    Parses an XMP string into a dictionary.

    Usage:

        parser = XmpParser(xmpstring)
        meta = parser.meta
    """

    def __init__(self, xmp):
        self.tree = ET.XML(xmp)
        self.rdftree = self.tree.find(RDF_NS+'RDF')

    @property
    def meta(self):
        """ A dictionary of all the parsed metadata. """
        meta = defaultdict(dict)
        for desc in self.rdftree.findall(RDF_NS+'Description'):
            for el in desc.getchildren():
                ns, tag =  self._parse_tag(el)
                value = self._parse_value(el)
                meta[ns][tag] = value
        return dict(meta)

    def _parse_tag(self, el):
        """ Extract the namespace and tag from an element. """
        ns = None
        tag = el.tag
        if tag[0] == "{":
            ns, tag = tag[1:].split('}', 1)
            if ns in NS_MAP:
                ns = NS_MAP[ns]
        return ns, tag

    def _parse_value(self, el):
        """ Extract the metadata value from an element. """
        if el.find(RDF_NS+'Bag') is not None:
            value = []
            for li in el.findall(RDF_NS+'Bag/'+RDF_NS+'li'):
                value.append(li.text)
        elif el.find(RDF_NS+'Seq') is not None:
            value = []
            for li in el.findall(RDF_NS+'Seq/'+RDF_NS+'li'):
                value.append(li.text)
        elif el.find(RDF_NS+'Alt') is not None:
            value = {}
            for li in el.findall(RDF_NS+'Alt/'+RDF_NS+'li'):
                value[li.get(XML_NS+'lang')] = li.text
        else:
            value = el.text
        return value

def xmp_to_dict(xmp):
    """Shorthand function for parsing an XMP string into a python dictionary."""
    return XmpParser(xmp).meta


# End xmp.py



class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener, ITab):

    def	registerExtenderCallbacks(self, callbacks):

        print "Loading..."

        self._callbacks = callbacks
        self._callbacks.setExtensionName("PDF Metadata")
        
        self.rbFast = self.defineRadioButton("Scan Fast - Will miss PDF files that don't have their name in the request")
        self.rbThorough = self.defineRadioButton("Scan Thoroughly - Will be slow, but won't miss PDF files", False)
        self.fast = True
        self.btnSave = swing.JButton("Save", actionPerformed=self.saveConfig)
        self.btnGroup = swing.ButtonGroup()
        self.btnGroup.add(self.rbFast)
        self.btnGroup.add(self.rbThorough)

        self.tab = swing.JPanel()
        layout = swing.GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(
            layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup()
                      .addComponent(self.rbFast)
                      .addComponent(self.rbThorough)
                      .addComponent(self.btnSave)
            )
        )
        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.rbFast)
            .addComponent(self.rbThorough)
            .addComponent(self.btnSave)
            
        )
        self.restoreConfig()
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)
        self._helpers = callbacks.getHelpers()
        self._callbacks.addSuiteTab(self)
            
        self.initGui()

        # Variable to keep a browsable structure of the issues find on each host
        # later used in the export function.
        self.global_issues = {}

        print "Loaded PDF Metadata v"+VERSION+"!"
        return

    def getTabCaption(self):
        return("PDF Metadata")

    def getUiComponent(self):
        return self.tab
    
    def saveConfig(self, e=None):
        if self.rbThorough.isSelected():
            self.fast = False
        else:
            self.fast = True
        self._callbacks.saveExtensionSetting("config", str(self.fast))

    def restoreConfig(self, e=None):
        if self._callbacks.loadExtensionSetting("config") == 'True' or self._callbacks.loadExtensionSetting("config") == None:
            self.rbFast.setSelected(True)
        else:
            self.rbThorough.setSelected(True)
            
    def defineRadioButton(self, caption, selected=True):
        radioButton = swing.JRadioButton(caption, selected)
        return radioButton
    
    def initGui(self):
        self.logsTA = swing.JTextArea()
        self.jScrollPane2 = swing.JScrollPane()
        self.logsTA.setColumns(20)
        self.logsTA.setRows(7)
        self.jScrollPane2.setViewportView(self.logsTA)


    def extensionUnloaded(self):
        print "Unloaded"
        return

    # Burp Scanner invokes this method for each base request/response that is
    # passively scanned
    def doPassiveScan(self, baseRequestResponse):
        self._requestResponse = baseRequestResponse

        scan_issues = []
        scan_issues = self.findMetadata()

        # doPassiveScan needs to return a list of scan issues, if any, and None
        # otherwise
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    # Just so the scanner doesn't return a "method not implemented error"
    def doActiveScan(self):
        return None

    def findMetadata(self):
        self._helpers = self._callbacks.getHelpers()
        self.scan_issues = []

        request = self._requestResponse.getRequest()
        pdfFilename = request.tostring().split()[1]

        if (".pdf" in pdfFilename and self.fast) or not self.fast:
            host = self._requestResponse.getHttpService().getHost()
            response = self._requestResponse.getResponse()
            responseInfo = self._helpers.analyzeResponse(response)
            bodyOffset = responseInfo.getBodyOffset()
            pdffile = StringIO.StringIO()
            pdffile.write ( response.tostring()[bodyOffset:] )
            parser = PDFParser(pdffile)
            try:
                doc = PDFDocument(parser)
                xmp_m = {}
                # If host hasn't been scanned before, add to global_issues
                if host not in self.global_issues:
                    self.global_issues[host] = {}
                    self.global_issues[host]["Interesting"] = []
                if 'Metadata' in doc.catalog:
                    xmp_metadata = resolve1(doc.catalog['Metadata']).get_data()
                    try:
                        xmp_m = xmp_to_dict(xmp_metadata)
                    except:
                        print """WARNING: The plugin found metadata, but it seems like you haven't loaded Burp with the necessary library to parse the data."""
                        print """Please try starting Burp with java -classpath /path/to/xerces.jar:burp.jar burp.StartBurp"""
                self.readMetadata(host, pdfFilename, doc.info[0], xmp_m)
            except PDFSyntaxError:
                print "ERROR: Corrupt PDF file: "+host+pdfFilename
            except PSEOF:
                print "ERROR: Unexpected EOF: "+host+pdfFilename
            except PDFEncryptionError:
                print "ERROR: Unknown algorithm: "+host+pdfFilename
            except PDFTypeError:
                print "ERROR: Unknown type: "+host+pdfFilename
            except IndexError:
                print "No Metadata Found in "+host+pdfFilename

            del pdffile
        return (self.scan_issues)

    def readMetadata(self, host, pdfFilename, metadata, xmp):
        issuename = "Metadata in PDF File(s)"
        issuelevel = "Low"
        issuedetail = """<p>PDF Metadata can contain compromising information
                      about employees, software and more. This may provide
                      information leading to specific and targeted technical
                      and social engineering attacks. The PDF file includes the
                      following potentially interesting metadata:</p><p><b>
                      Document Information</b></p><ul>"""
        log = "[+] Metadata found: " + host + "\n"
        issueremediation = """Metadata containing sensitive information should
                           be stripped from the file."""
        found = 0
        if metadata.keys():
            print ""
            print host+pdfFilename
            for key in metadata.keys():
                if metadata[key] and not str(metadata[key]).isspace():
                    # hope they did not chose a funky encoding
                    try:
                        print key+":"+metadata[key]
                        current_metadata = metadata[key]
                    except UnicodeDecodeError:
                    # trying to cope with a funky encoding
                        current_metadata = metadata[key].decode(chardet.detect(metadata[key])['encoding'])
                        print key+":",
                        print current_metadata.encode('utf-8')
                    except TypeError:
                    # somehow sometimes metadata[key] is returned as PSLiteral
                        current_metadata = str(metadata[key])
                        print key+":",
                        print current_metadata.encode('utf-8')

                    regex = "^D:[0-9]{14}-[0-9]{2}'[0-9]{2}'$"
                    if re.match(regex, current_metadata):
                        year = current_metadata[2:6]
                        month = current_metadata[6:8]
                        day = current_metadata[8:10]
                        hours = current_metadata[10:12]
                        minutes = current_metadata[12:14]
                        seconds = current_metadata[14:16]
                        o = current_metadata[16:17]
                        utc_offset = current_metadata[17:19]
                        value = year+"/"+month+"/"+day+" "+hours+":"+minutes+":"+seconds+" UTC"+o+utc_offset
                    else:
                        value = current_metadata
                    issuedetail += "<li>Parameter: <b>" + key + "</b>. Value: <b>"+ value + "</b></li>"
                    log += "    Parameter name:" + key + " Value:" + current_metadata  + "\n"
                    report = key + ":" + current_metadata
                    if report not in self.global_issues[host]:
                        self.global_issues[host]["Interesting"].append(report)

                    found += 1
            issuedetail += "</ul>"

        if xmp.keys():
            issuedetail += "<p><b>XMP Metadata</b></p><ul>"
            for key in xmp.keys():
                print key
                issuedetail += "<li>Schema: <b>"+key+"</b></li><ul>"
                print str(xmp[key])
                for prop in xmp[key].keys():
                    if xmp[key][prop] and not str(xmp[key][prop]).isspace():
                        issuedetail += "<li>Property: <b>"+prop+"</b>. Value: <b>"+ str(xmp[key][prop]) + "</b></li>"
                issuedetail += "</ul>"
                found += 1
            issuedetail += "</ul>"


        if found > 0:
            # Create a ScanIssue object and append it to our list of issues
            self.scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                                              self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                                              issuename, issuelevel, issuedetail, issueremediation))
            self.logsTA.append(log)

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getUrl() == newIssue.getUrl() and \
                existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
        else:
            return 0

# Implementation of the IScanIssue interface with simple constructor and getter methods
class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, name, severity, detailmsg, remediationmsg):
        self._url = url
        self._httpservice = httpservice
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg
        self._remediationmsg = remediationmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return None

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return self._remediationmsg

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"
