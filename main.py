#!/bin/sh
# Polyglot hack to ensure we execute the correct Python.
''':'
pythons='python2.7 python2 python'
for p in $pythons; do
    hash $p 2>/dev/null && exec $p "$0" "$@"
done
echo >&2 "None of $pythons found"
exit 1
#'''

import re
import sys
import json
import os.path
from PyQt4.QtCore import Qt
from PyQt4.QtGui import (
    QWidget, QTextBrowser, QVBoxLayout, QHBoxLayout, QPushButton,
    QMessageBox, QLineEdit, QTabWidget, QDesktopWidget, QApplication,
    QFileDialog, QColor
    )
from PyQt4.QtNetwork import QTcpServer, QTcpSocket

CENTRAL_ADDR = '166.111.180.60'
CENTRAL_PORT = 8000
PEER_PORT = 4242

TEXT_ENCODING = 'utf8'


def urepr(u):
    """
    repr() of a unicode, minus the leading 'u'.
    """
    return repr(unicode(u))[1:]


class TextBrowser(QTextBrowser):
    def __init__(self, addr_s=None):
        super(TextBrowser, self).__init__()
        self.addr_s = addr_s

    def append_colored(self, msg, colorname):
        self.setTextColor(QColor(colorname))
        self.append(msg)
        self.setTextColor(QColor())

    def info(self, msg):
        self.append_colored(msg, 'green')

    def error(self, msg):
        self.append_colored(msg, 'red')

    def feed(self, qbytes):
        self.append(bool(self.addr_s) * (u'%s: ' % self.addr_s) +
                    str(qbytes).decode(TEXT_ENCODING).rstrip(u'\n'))


class ChatException(Exception):
    pass


class ChatWindow(QWidget):
    def __init__(self, socket, addr):
        super(ChatWindow, self).__init__()

        self.socket = socket
        self.addr = addr
        self.setupSocket()
        self.createUi()

    def setupSocket(self):
        self.socket.disconnected.connect(self.onDisconnected)
        self.socket.error.connect(self.onError)

    def createUi(self):
        vbox = QVBoxLayout()
        self.buf = TextBrowser(self.addr.toString())
        self.buf.setFontFamily('Monospace')
        self.buf.setFocusPolicy(Qt.NoFocus)
        vbox.addWidget(self.buf, 1)
        hbox_send = QHBoxLayout()
        self.send_text = QLineEdit()
        hbox_send.addWidget(self.send_text, 1)
        self.send_button = QPushButton("Send")
        self.send_file_button = QPushButton("Send File")
        hbox_send.addWidget(self.send_button)
        hbox_send.addWidget(self.send_file_button)
        vbox.addLayout(hbox_send)
        self.setLayout(vbox)

        self.send_text.returnPressed.connect(self.onSend)
        self.send_button.clicked.connect(self.onSend)
        self.send_file_button.clicked.connect(self.onSendFile)

    def onSend(self):
        text = unicode(self.send_text.text())
        encoded = text.encode(TEXT_ENCODING)
        header = 'T%d ' % len(encoded)
        payload = header + encoded
        if self.socket.write(payload) < len(payload):
            self.buf.error('Failed to send message %s' % urepr(text))
        self.send_text.clear()

    sendFileBufSize = 1024

    def onSendFile(self):
        path = str(QFileDialog.getOpenFileName())

        if not os.path.exists(path):
            if len(path) == 0:
                self.buf.info('File sending cancelled.')
            else:
                self.buf.error("File %s doesn't exist." % path)
            return

        size = os.path.getsize(path)
        bname = os.path.basename(path)[:512]
        header = 'F%d %s/' % (size, bname)
        if len(header) > self.sendFileBufSize:
            raise ChatException("Header too long, give up")

        with open(path, 'rb') as f:
            buf = header + f.read(self.sendFileBufSize - len(header))
            while len(buf) > 0:
                if self.socket.write(buf) < len(buf):
                    self.buf.error('Failed to send file %s' % bname)
                    break
                buf = f.read(self.sendFileBufSize)

    def onConnected(self):
        self.buf.info('Connected to peer %s.' % unicode(self.peer.toString()))

    def onDisconnected(self):
        self.buf.info('Peer went offline.')

    def onError(self):
        self.buf.error('Something went wrong with the connection.')


COMMANDS_HELP = '''Supported commands are:
/talk <peer>
    Initialize a talk with <peer>. <peer> may be an IP address or the name of
    a friend.
/query [<peer>]
    Query the server about the status of <peer>. If <peer> is ommitted, all
    friends are queried.
/login <name> <passwd>
    Log in as <name> with <passwd>.
/logout
    Log out.
/help
    This help.'''


class MainWindow(QWidget):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.createServer()
        self.configureWindow()
        self.createUi()
        self.readConfig()
        self.loginName = ''

        for cmd in self.config['autorun']:
            self.evalCmd(cmd)

    def configureWindow(self):
        self.setWindowTitle('Simple Chat Program')
        self.resize(700, 600)
        self.center()

    def readConfig(self):
        self.config = {
            'friends': [],
            'autorun': [],
            'receiveDirectory': 'received',
        }
        path = os.path.join(mydir, 'config.json')
        try:
            with open(path, 'r') as f:
                self.config.update(json.load(f))
        except IOError:
            self.buf.error('Cannot read configuration file %s.' % path)
        except ValueError:
            self.buf.error('Configuration file %s contains errors.' % path)

        rdir = self.config['receiveDirectory']
        if os.path.isabs(rdir):
            self.receiveDirectory = rdir
        else:
            self.receiveDirectory = os.path.join(mydir, rdir)

    def createUi(self):
        main = QHBoxLayout()

        console = QVBoxLayout()
        self.buf = TextBrowser()
        self.buf.setFontFamily('monospace')
        self.buf.setFocusPolicy(Qt.NoFocus)
        console.addWidget(self.buf)
        self.command_line = QLineEdit()
        console.addWidget(self.command_line)

        main.addLayout(console, 1)
        self.tab = QTabWidget()
        self.tab.setTabsClosable(True)
        self.peers = {}
        main.addWidget(self.tab, 3)

        self.setLayout(main)

        self.command_line.returnPressed.connect(self.onCommand)
        self.tab.tabCloseRequested.connect(self.onTabCloseRequested)

    def createServer(self):
        self.server = QTcpServer()
        if not self.server.listen(port=PEER_PORT):
            QMessageBox.critical(
                self, "Server Error",
                "Cannot start server. Port %d seems in use." % PEER_PORT)
            sys.exit(1)
        self.server.newConnection.connect(self.onNewConnection)

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def addPage(self, socket):
        addr = socket.peerAddress()
        page = ChatWindow(socket, addr)
        self.peers[addr] = page
        self.tab.addTab(page, addr.toString())

    def newActive(self, peer, resolve=True):
        if resolve and peer in self.config['friends']:
            self.buf.info('%s is in friends list, querying...' % peer)

            def cb(res):
                if res == 'n':
                    self.buf.error('%s is offline' % peer)
                elif res[0].isdigit():
                    self.buf.info('%s has IP address %s' % (peer, res))
                    self.newActive(res, False)
                else:
                    self.buf.error('status of %s is unknown' % peer)
            self.talkToCentral('q%s' % peer, u'query', r'', cb, False)
            return

        socket = QTcpSocket()
        socket.connectToHost(peer, PEER_PORT)

        def onConnected():
            self.buf.info('Connected to %s' % peer)
            self.addPage(socket)

        def onError():
            self.buf.error('Error communicating with %s: %s' % (
                peer, socket.errorString()))
        socket.connected.connect(onConnected)
        socket.error.connect(onError)

        self.buf.info('Reaching out to %s...' % peer)

    def talkToCentral(self, msg, name, pattern, cb=None, successMsg=True):
        Name = name.title()
        socket = QTcpSocket()
        socket.connectToHost(CENTRAL_ADDR, CENTRAL_PORT)

        def onConnected():
            socket.write(msg)

            def onReadyRead():
                response = str(socket.readAll())
                if re.match(pattern, response):
                    if successMsg:
                        self.buf.info(u'%s successful.' % Name)
                    if cb:
                        cb(response)
                else:
                    self.buf.error(u'%s failed, server said %s.' %
                        (Name, repr(response)))
                socket.close()
            socket.readyRead.connect(onReadyRead)

        def onError():
            self.buf.error(u'Error %s: %s' %
                (name, urepr(socket.errorString())))

        socket.connected.connect(onConnected)
        socket.error.connect(onError)

    def login(self, obj):
        name, sep, passwd = obj.partition(' ')

        def cb(res):
            self.loginName = name
        self.talkToCentral('%s_%s' % (name, passwd), u'login', r'^lol$', cb)

    def logout(self):
        if not self.loginName:
            self.buf.error(u'Not logged in')
            return

        def cb(res):
            self.loginName = ''

        self.talkToCentral('logout%s' % self.loginName,
                           u'logout', r'^loo$', cb)

    def queryOne(self, p):
        def cb(res):
            if res == 'n':
                self.buf.info('%s: offline' % p)
            elif res[0].isdigit():
                self.buf.info('%s: online, %s' % (p, res))
            else:
                self.buf.info('%s: unknown' % p)
        self.talkToCentral('q%s' % p, u'query', r'', cb, False)

    def query(self, obj):
        if obj:
            self.queryOne(obj)
        else:
            for p in self.config['friends']:
                self.queryOne(p)

    def evalCmd(self, command):
        if len(command) == 0:
            return

        if command[0] != u'/':
            self.buf.info(u"%s taken as implicit /talk" % urepr(command))
            command = u'/talk ' + command

        verb, sep, obj = command[1:].partition(' ')
        if verb in (u't', u'talk'):
            self.newActive(obj)
        elif verb in (u'h', u'help'):
            self.buf.info(COMMANDS_HELP)
        elif verb == u'login':
            self.login(obj)
        elif verb == u'logout':
            self.logout()
        elif verb in (u'q', u'query'):
            self.query(obj)
        else:
            self.buf.error(u'Unknown command %s.' % urepr(verb))

    def onCommand(self):
        self.evalCmd(unicode(self.command_line.text()))
        self.command_line.clear()

    readBufSize = 1024
    text_msg_pattern = re.compile(r'^T(\d+) (.*)$', re.S)
    file_msg_pattern = re.compile(r'^F(\d+) ([^/]+)/(.*)$', re.S)

    def onNewConnection(self):
        socket = self.server.nextPendingConnection()

        def onReadyRead():
            addr = socket.peerAddress()
            if addr not in self.peers:
                self.addPage(socket)

            addr_s = addr.toString()
            payload = str(socket.read(self.readBufSize))

            if payload[0] == 'T':
                payload_m = re.match(self.text_msg_pattern, payload)
                if not payload_m:
                    self.buf.error('Bad text message from %s' % addr_s)
                    return

                size = int(payload_m.group(1))
                segments = [payload_m.group(2)]

                remain = size - len(segments[0])
                while remain > 0:
                    payload = str(socket.read(remain))
                    if len(payload) <= 0:
                        self.buf.error('Incomplete text message from %s'
                                       ' - need %d more bytes' %
                                       (addr_s, remain))
                        break
                    segments.append(payload)
                    remain -= len(payload)
                self.peers[addr].buf.feed(''.join(segments))

            elif payload[0] == 'F':
                payload_m = re.match(self.file_msg_pattern, payload)
                if not payload_m:
                    self.buf.error('Bad file message from %s: %s' % (addr_s,
                        repr(payload)))
                    return

                size = int(payload_m.group(1))
                bname = payload_m.group(2)
                rdir = self.receiveDirectory
                path = os.path.join(rdir, bname)

                with open(path, 'wb') as f:
                    segment = payload_m.group(3)
                    f.write(segment)
                    remain = size - len(segment)
                    while remain > 0:
                        segment = str(socket.read(
                            min(remain, self.readBufSize)))
                        if len(segment) <= 0:
                            self.buf.error('Incomplete file message from %s'
                                           ' - need %d more bytes' %
                                           (addr_s, remain))
                            break
                        f.write(segment)
                        remain -= len(segment)
                self.buf.info('File %s from %s saved at %s' %
                    (repr(bname), addr_s, rdir))

            else:
                self.buf.error('Bad message from %s: unknown type '
                               '"%s"' % (addr.toString(), payload[0]))

        socket.readyRead.connect(onReadyRead)

    def onTabCloseRequested(self, idx):
        page = self.tab.widget(idx)
        self.tab.removeTab(idx)
        page.close()
        page.deleteLater()


def main():
    global mydir
    mydir = os.path.dirname(__file__)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
