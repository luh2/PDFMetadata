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
from javax import swing
import StringIO
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdftypes import resolve1
import chardet



class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener):

    def	registerExtenderCallbacks(self, callbacks):
        
        print "Loading..."

        self._callbacks = callbacks
        self._callbacks.setExtensionName("PDF Metadata")
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)
        self._helpers = callbacks.getHelpers()

        
        self.initGui()
      
        # Variable to keep a browsable structure of the issues find on each host
        # later used in the export function.
        self.global_issues = {} 

        
        print "Loaded!"

        return

    def initGui(self):
        self.logsTA = swing.JTextArea()

        self.jScrollPane2 = swing.JScrollPane()        
        self.logsTA.setColumns(20)
        self.logsTA.setRows(7)
        self.jScrollPane2.setViewportView(self.logsTA)


    def extensionUnloaded(self):
        print "Unloaded"
        return

    # Burp Scanner invokes this method for each base request/response that is passively scanned
    def doPassiveScan(self, baseRequestResponse):       
        self._requestResponse = baseRequestResponse
        
        scan_issues = []
        scan_issues = self.findMetadata()

        # doPassiveScan needs to return a list of scan issues, if any, and None otherwise
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

        # Not checking content-type. Content-Type stated in too many ways.
        # Check filename extension
        # Not super clean either, but better than nothing.
        if pdfFilename[-3:] == "pdf":
            host = self._requestResponse.getHttpService().getHost()
            response = self._requestResponse.getResponse()
            responseInfo = self._helpers.analyzeResponse(response)
            bodyOffset = responseInfo.getBodyOffset()
            pdffile = StringIO.StringIO()
            pdffile.write ( response.tostring()[bodyOffset:] )
            parser = PDFParser(pdffile)
            doc = PDFDocument(parser)
            # If host hasn't been scanned before, add to global_issues
            if host not in self.global_issues:
                self.global_issues[host] = {}
                self.global_issues[host]["Interesting"] = []
            self.readMetadata(host, pdfFilename, doc.info[0])
            del pdffile
        return (self.scan_issues)

    def readMetadata(self, host, pdfFilename, metadata):
        issuename = "Metadata in PDF File(s)"
        issuelevel = "Low"
        issuedetail = "<p>PDF Metadata can contain compromising information about employees, software and more. This may provide information leading to specific and targeted technical and social engineering attacks. The PDF file includes the following potentially interesting metadata:</p><ul>"
        log = "[+] Interesting Headers found: " + host + "\n"
        issueremediation = "Metadata containing sensitive information should be stripped from the file."
        found = 0
        print host+pdfFilename
        for key in metadata.keys():
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
            issuedetail += "<li>Parameter: <b>" + key + "</b>. Value: <b>"+ current_metadata + "</b></li>"
            log += "    Parameter name:" + key + " Value:" + current_metadata  + "\n"
            report = key + ":" + current_metadata
            if report not in self.global_issues[host]:
                self.global_issues[host]["Interesting"].append(report)

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
