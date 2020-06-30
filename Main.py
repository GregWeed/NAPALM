'''
Network Analysis, Parsing and Logging Machine (NAPALM)
Author: weed12@live.marshall.edu
Napalm reads TCP Dumps that are exported from Wireshark and analyzes network traffic percentages,
FTP communication, ARP requests, and also provides an Ip address lookup to determine incoming traffic
from external ip's.  A GUI is provided requiring PyQt5 and Python3.6, as well as a terminal application if chosen
when running from the Terminal.

To ensure that your dump file is formatted appropriately,
follow these steps when exporting from Wireshark.
File > Export Packet Dissections > As Plain Text...
Under Packet Format, deselect 'Include Column Headings' and 'Details'.
Here is an example on how your file should be formatted:
    1   0.000000 31.205.0.166 -> 10.200.59.77 TCP 54 51244 > ssh [ACK] Seq=1 Ack=1 Win=253 Len=0
    2   0.011787 31.205.0.166 -> 10.200.59.77 TCP 54 51244 > ssh [ACK] Seq=1 Ack=205 Win=252 Len=0
    3   2.734561 31.205.0.166 -> 10.200.59.77 SSH 106 Encrypted request packet len=52
    4   2.734791 10.200.59.77 -> 31.205.0.166 SSH 106 Encrypted response packet len=52
    5   2.735376 10.200.59.77 -> 31.205.0.166 SSH 186 Encrypted response packet len=132
    6   2.836870 31.205.0.166 -> 10.200.59.77 TCP 54 51244 > ssh [ACK] Seq=53 Ack=389 Win=252 Len=0
    7   6.664772 31.205.0.166 -> 10.200.59.77 SSH 106 Encrypted request packet len=52
    .
    .
    .
    n
'''

from PyQt5.QtCore import pyqtSlot, Qt
from PyQt5.QtWidgets import (QApplication, QDialog, QGridLayout, QHBoxLayout, QLineEdit, QPushButton, QTabWidget,
                             QWidget, QFileDialog, QListWidget, QMessageBox)


"""
Holds the packets read from a Wireshark dump."""
class packet:
    def __init__(self, lineNumber, time, source, destination, protocol, length, packetInfo):
        self.lineNumber = lineNumber
        self.time = time
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.length = length
        self.packetInfo = packetInfo

    # Prints a packet object to the console
    def toString(self):
        return self.lineNumber + "\t" + self.time + "\t" + self.source + "\t" + self.destination + "\t" + self.protocol + "\t" + self.length + "\t" + self.packetInfo

"""
The User class is used to store FTP communication information.
"""
class user:
    def __init__(self, userIP, userName, password, ftpServer):
        self.userIP = userIP
        self.userName = userName
        self.password = password
        self.ftpServer = ftpServer
    # Prints a user object to the console
    def toString(self):
        return '{: <30}  {: <30}  {: <30}  {: <30}'.format(self.userIP, self.userName, self.password, self.ftpServer)


"""
Reads a TCP dump file and adds it to a dictionary.  The line numbers are the keys, where the values contain the entire packets
information.  The object format is stored in a dictionary as such:
lineNumber : {'lineNumber', 'time', 'source', 'destination', 'protocol', 'length(bytes)', 'packetInformation'}
Refer to the docstring above for information on file formatting.
"""
def readFile(filePath):
    dictionary = {}
    file = open(filePath, "r")
    for i in file:
        # Removes leading and trailing whitespace
        i = i.strip()
        string = i.split(" ")
        # Removes empty indices and any arrows from split string
        string = [string for string in string if string != ""]
        string = [string for string in string if string != "->"]
        # Combines the back half of the split array, which contains the packet information
        combineString = [' '.join(string[6: len(string)])]
        string[7: len(string)] = combineString
        # Creates a packet object and adds it to the dictionary
        tcpPacket = packet(string[0], string[1], string[2], string[3], string[4], string[5], string[7])
        dictionary[tcpPacket.lineNumber] = tcpPacket

    return dictionary


"""
Displays every protocol in the Wireshark Dump and gives a percentage of the network traffic based on said protocol. 
Also returns the sorted list containing each protocol and its count in the tcpDump that was passed through it, 
not the percentage!  If you are messing with this method and returning a list of the protocols and want a percentage,
you have to perform the calculation in the code you are writing.
"""
def trafficProtocolStats(tcpDictionary):
    packetLength = len(tcpDictionary)
    protocolDictionary = {}

    # Iterates the TCP Dump and adds each protocol to a protocolDictionary
    for i in tcpDictionary:
        protocolDictionary[tcpDictionary.get(i).protocol] = 0

    # Increments the occurance of each protocol in the protocolDictionary
    for i in tcpDictionary:
        if (tcpDictionary.get(i).protocol in protocolDictionary.keys()):
            protocolDictionary[tcpDictionary.get(i).protocol] += 1

    # Sorts the protocolDictionary into a list of tuples so that the values can be printed in order
    sortedList = sorted(protocolDictionary.items(), key=lambda x: x[1])

    # Printes each tuple from the sorted list
    for i in reversed(sortedList):
        # .ljust adjust the columns and the spacing in between, .format iterates each tuple contained in the sorted list.
        # str(round(((i[1] / packetLength) * 100), 2))) changes the count of each protocol to a percentage of the
        # network traffic.
        print('{: <30}  {}'.format(i[0].ljust(10), str(round(((i[1] / packetLength) * 100), 2))) + " %")
    return sortedList


"""
Takes in a string that is a destination in the Wireshark Dump.  If the ip address isn't contained within the 
dump a notification will be printed to the terminal console, if you are in the gui then you will get a blank screen.
If the destination ip is found, the all sources that are sending packets said destination ip(which is input by the user) 
are displayed in the console.  Returns a dictionary of ip's that are sending incoming packets to 
the specified ip address.
"""
def incomingTrafficSearch(receivingIPAddr, tcpDictionary):
    destinationIpDict = {}

    for i in tcpDictionary:
        # Finds every instance where the destination ip matches the users input.
        if (tcpDictionary.get(i).destination == receivingIPAddr):
            ## Adds the source ip to the dictionary above. These are the devices communicating with the
            # user entered ip.
            destinationIpDict[tcpDictionary.get(i).source] = 0
    for key in destinationIpDict:
        print(key)
    return destinationIpDict


"""
Pulls all FTP username's and passwords from the TCP Dump.
"""
def getFTPUserData(tcpDictionary):
    # Stores the string values of each user
    userStrings = []
    # Holds the user objects taken from userStrings
    users = []

    for i in tcpDictionary:
        # Checks each FTP packet for USERs and creates a userString that is added to the UserStrings list as a space
        # separated string.  Note that the server in communication is also stored.
        if (tcpDictionary.get(i).protocol == "FTP" and "Request: USER" in tcpDictionary.get(i).packetInfo):
            userIp = tcpDictionary.get(i).source
            userString = tcpDictionary.get(i).packetInfo.split(" ")
            userName = userString[len(userString) - 1]
            password = "Password not in dump. "
            ftpServer = tcpDictionary.get(i).destination
            ftpUser = userIp + " " + userName + " " + ftpServer

            # If the userStrings list does not contain the current string in ftpUser, then it is added to the list.
            # This eliminates any duplicates. A user object is then created storing userIP, userName, and the server that
            # is communicating.  The password field remains empty until authentication is detected.
            if ftpUser not in userStrings:
                userStrings.append(ftpUser)
                users.append(user(userIp, userName, password, ftpServer))

    successPassword = ""
    successIP = ""
    for i in tcpDictionary:
        # Checks each packet for a password attempt and stores any attempted passwords in password below as well as the
        # corresponding ip address in successIP
        if ("PASS" in tcpDictionary.get(i).packetInfo):
            password = tcpDictionary.get(i).packetInfo.split(" ")
            successPassword = password[len(password) - 1]
            successIP = tcpDictionary.get(i).source

        # If Login Successful is found in packet info, then the ip for that password is located in the users
        # list and stored.
        if ("Login successful" in tcpDictionary.get(i).packetInfo and tcpDictionary.get(i).destination == successIP):
            for i in range(0, len(users)):
                if (users[i].userIP == successIP):
                    users[i].password = successPassword

    for i in users:
        print(i.toString())
    return users


"""
Gets all ARP transactions and displays ip/mac address pairs.
"""
def getDeviceIDs(tcpDictionary):
    macIPList = []
    for i in tcpDictionary:
        # Looks for the substring "is at"
        if (tcpDictionary.get(i).protocol == "ARP" and "is at" in tcpDictionary.get(i).packetInfo):
            # If found, adds that packets info to the mac ip list.
            # 10.0.0.1 is at ff:ff:ff:ff:ff:ff <- in this format
            if (tcpDictionary.get(i).packetInfo not in macIPList):
                macIPList.append(tcpDictionary.get(i).packetInfo)
    for i in range(0, len(macIPList)):
        print(macIPList[i])
    return macIPList

"""
Runs the terminal application.
"""
def terminalApplication():
    dictionary = None
    running = 1;
    while (running == 1):
        print("Menu Options:")
        print("a.) Load TCP Dump File.")
        print("b.) Display network traffic and percentages.")
        print("c.) Determine communication to a specified ip address.")
        print("d.) Display all FTP credentials and server ip's.")
        print("e.) Display ARP MAC addresses and their corresponding ip addresses.")
        print("x.) Exit")
        userInput = input(">>> ")
        print("")

        if userInput == "a":
            print("Enter the filepath of the tcp dump: ")
            filePath = input(">>> ")
            try:
                dictionary = readFile(filePath)
                print("File loaded successfully")
            except:
                print("File not found!")
            print("")

        if userInput == "b":
            print("")
            print("Network Traffic:")
            print('{: <30}  {}'.format("Protocol", "%"))
            try:
                trafficProtocolStats(dictionary)
            except:
                print("Error loading terminalApplication >>> trafficProtocolStats...")
            print("")
            print("")

        if userInput == "c":
            print("")
            print("Enter an ip address to determine its incoming traffic addresses.")
            userInput = input(">>> ")
            print("")
            print("Receiving packets from: ")
            incomingTrafficSearch(userInput, dictionary)
            print("")

        if userInput == "d":
            print('{: <30}  {: <30}  {: <30}  {: <30}'.format("User IP", "UserName", "Password",
                                                              "FTP Server") + "(Fields will be blank if FTP is not present.)")
            getFTPUserData(dictionary)
            print("")

        if userInput == "e":
            print("Devices (If ARP is present):")
            getDeviceIDs(dictionary)
            print("")

        if userInput == "x":
            print("Terminating...")
            exit(0)

"""
This function calls the gui application.
"""
def userInterface():
    class WidgetGallery(QDialog):
        """ Main Application initialization"""
        def __init__(self, parent=None):
            super(WidgetGallery, self).__init__(parent)
            # Holds all packets.
            self.dictionary = ""
            # Initial open file dialog
            self.openFileNameDialog()

            # Creates IP Lookup Button
            self.button = QPushButton("Ip Lookup")
            self.button.setFixedWidth(115)
            self.button.setFixedHeight(30)
            self.button.clicked.connect(self.on_click)

            # Creates IP Lookup Button
            self.button2 = QPushButton("Load Dump File")
            self.button2.setFixedWidth(115)
            self.button2.setFixedHeight(30)
            self.button2.clicked.connect(self.load_click)

            # Creates textbox for ip search
            self.textbox = QLineEdit(self)
            self.textbox.setFixedWidth(100)
            self.textbox.setFixedHeight(19)

            # Creates the protocol tab
            self.TabWidget = QTabWidget()
            self.protocolsWidget = QWidget()
            # Displays the list of protocols in the gui
            self.protocolsList = QListWidget()
            # Method call that processes the network traffic. Notice that the percentage calculation is
            # performed here and not in the function.
            self.traffic = trafficProtocolStats(self.dictionary)
            for i in range(0, len(self.traffic)):
                self.protocolsList.insertItem(i,
                                              self.traffic[i][0] + "\t" + str(
                                             round(((self.traffic[i][1] / len(self.dictionary)) * 100), 2)) + "%")
            self.protocolTab = QHBoxLayout()
            self.protocolTab.setContentsMargins(5, 5, 5, 5)
            self.protocolTab.addWidget(self.protocolsList)
            self.protocolsWidget.setLayout(self.protocolTab)
            # Adds widget
            self.TabWidget.addTab(self.protocolsWidget, "Network Traffic")

            # Creates the ftp tab
            self.ftpWidget = QWidget()
            self.ftpTextEdit = QListWidget()
            self.ftp = getFTPUserData(self.dictionary)
            self.ftpTextEdit.insertItem(0,
                                        '{: <10}  {: <10}  {: <10}  {: <10}'.format("User IP", "UserName", "Password",
                                                                                    "FTP Server") + "(Fields will be blank if FTP is not present.)")
            for i in range(0, len(self.ftp)):
                self.ftpTextEdit.insertItem(i + 1, self.ftp[i].toString())
            self.ftpTab = QHBoxLayout()
            self.ftpTab.setContentsMargins(5, 5, 5, 5)
            self.ftpTab.addWidget(self.ftpTextEdit)
            self.ftpWidget.setLayout(self.ftpTab)
            # Adds widget
            self.TabWidget.addTab(self.ftpWidget, "FTP")

            # Creates the ARP tab
            self.arpWidget = QWidget()
            self.arpList = QListWidget()
            self.arp = getDeviceIDs(self.dictionary)
            for i in range(0, len(self.arp)):
                self.arpList.insertItem(i + 1, self.arp[i])
            self.arpLayout = QHBoxLayout()
            self.arpLayout.setContentsMargins(5, 5, 5, 5)
            self.arpLayout.addWidget(self.arpList)
            self.arpWidget.setLayout(self.arpLayout)
            # Adds widget
            self.TabWidget.addTab(self.arpWidget, "ARP")

            # Creates the main layout
            mainLayout = QGridLayout()
            # Adds a menu space above the tab widget
            layout = QHBoxLayout()
            # Adds the Tabwidget to the main layout
            mainLayout.addWidget(self.TabWidget, 3, 0)
            # Adds buttons and text boxes to the menu area
            layout.addWidget(self.textbox, stretch=Qt.AlignLeft)
            layout.addSpacing(10)
            layout.addWidget(self.button, stretch=Qt.AlignLeft)
            layout.addSpacing(10)
            layout.addWidget(self.button2, stretch=Qt.AlignLeft, alignment=Qt.AlignLeft)
            layout.setAlignment(Qt.AlignLeft)
            # Adds layout to the mainLayout
            mainLayout.addItem(layout, 0, 0)
            # Sets main layout
            self.setLayout(mainLayout)
            self.setWindowTitle("Network Analyzer")
            self.resize(1000, 300)

        """
        Function for open file dialog.
        """
        def openFileNameDialog(self):
            options = QFileDialog.Options()
            options |= QFileDialog.DontUseNativeDialog
            fileName, _ = QFileDialog.getOpenFileName(self, "Load a TCP Dump File", "",
                                                      "All Files (*);;Python Files (*.py)", options=options)
            if fileName:
                try:
                    self.dictionary = readFile(fileName)
                except:
                    print("Error loading file in: openFileNameDialog()")
                    QMessageBox.question(self, 'Extract!', "Error loading file.  Ensure that the dump file is properly formatted.", QMessageBox.Ok)


        """
        Load file button action.  Opens file dialog and reads in the the selected file.
        """
        @pyqtSlot()
        def load_click(self):

            # Removes the current communication tab
            self.TabWidget.removeTab(3)
            # Clears all lists inside of the tab widget.
            self.arpList.clear()
            self.ftpTextEdit.clear()
            self.protocolsList.clear()
            # Clears packet dictionary
            self.dictionary = ""
            # File selection dialog called
            self.openFileNameDialog()
            # Updates all lists in tab widget.
            self.arpWidget.update()
            self.arpList.update()
            self.ftpTextEdit.update()
            self.protocolsList.update()
            # Below this comment is the same information from app initialization in
            # regards to loading each list with data.
            # Updates arp tab
            self.arp = getDeviceIDs(self.dictionary)
            for i in range(0, len(self.arp)):
                self.arpList.insertItem(i + 1, self.arp[i])
            self.arpLayout.setContentsMargins(5, 5, 5, 5)
            # Updates the ftp tab
            self.ftp = getFTPUserData(self.dictionary)
            self.ftpTextEdit.insertItem(0,
                                        "%s" % "UserIp:" + "%s" % "UserName:" + "%s" % "Password:" + "%s" % "FTPServer")
            for i in range(0, len(self.ftp)):
                self.ftpTextEdit.insertItem(i + 1, ("%s" % self.ftp[i].userIP) + ":%s" % self.ftp[i].userName + ":%s" %
                                            self.ftp[i].password + ":%s" % self.ftp[i].ftpServer)
            self.ftpTab.setContentsMargins(5, 5, 5, 5)
            # Updates network traffic tab
            self.traffic = trafficProtocolStats(self.dictionary)
            for i in range(0, len(self.traffic)):
                self.protocolsList.insertItem(i, self.traffic[i][0] + "\t" + str(
                    round(((self.traffic[i][1] / len(self.dictionary)) * 100), 2)) + "%")
            self.protocolTab.setContentsMargins(5, 5, 5, 5)


        """
        On_click performs a search on a specified ip for incoming communication.
        """
        # Aids in the removal of the communications tab when searching for additional Ips
        removeTab = 0
        @pyqtSlot()
        def on_click(self):
            if self.removeTab == 1:
               # Removes current communications tab.
                self.TabWidget.removeTab(3)

            # New list and tab are created below.
            self.list = QListWidget()
            textboxValue = self.textbox.text()
            # Search for ip
            traffic = incomingTrafficSearch(textboxValue, self.dictionary)
            qList = QListWidget()
            ipLayout = QHBoxLayout()
            ipTab = QWidget()
            # Inserts communicating ip's to the list
            for i in traffic.keys():
                qList.insertItem(0, i)
            if self.textbox.text() != "":
                qList.insertItem(0, ("IP's currently communicating with %s" % self.textbox.text()))
                self.textbox.setText("")
                ipLayout.setContentsMargins(5, 5, 5, 5)
                ipLayout.addWidget(qList)
                ipTab.setLayout(ipLayout)
                self.TabWidget.addTab(ipTab, "Communicating Ip's")
                self.TabWidget.setCurrentIndex(3)
                self.removeTab = 1

    if __name__ == '__main__':
        import sys
        app = QApplication(sys.argv)
        gallery = WidgetGallery()
        gallery.show()
        sys.exit(app.exec_())

"""
Below is the dialog for selecting between a TUI and GUI when running this application from the terminal.
"""
### Main ###
while True:
    print("Menu options: ")
    print("t: TUI")
    print("g: GUI (Requires PyQt5 and Python3.6)")
    print("x: Exit Application")
    userInput = input(">>> ")
    if userInput == "t":
        terminalApplication()
    if userInput == "g":
        print("Starting user interface...")
        userInterface()
    if userInput == "x":
        exit(0)
        print("Application terminated...")


