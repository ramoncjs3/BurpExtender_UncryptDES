# -*- coding: utf-8 -*-
# Author: Ramoncjs
# Time: 2020/4/16

import java.lang as lang
import base64
from javax import swing
from java.awt import Color
from java.awt import Font
from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import ITab
from pyDes import des, PAD_PKCS5, ECB

param = 'Null'
secret_key = 'Null'
iv = 'Null'


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Des Decrypt")
        # 初始化UI
        self.TabUI()
        self._callbacks.addSuiteTab(self)
        callbacks.registerMessageEditorTabFactory(self)

    # 实现IMessageEditorTabFactory方法
    # Burp 将会对每一个 HTTP 消息编辑器调用一次此方法，此工厂必须返回一个新的 IMessageEditorTab 对象
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return DataInputTab(self, controller, editable)

    # 实现Itab接口
    def getTabCaption(self):
        return 'Des Decrypt'

    def getUiComponent(self):
        return self.tab

    # 实现新窗口功能与UI
    def TabUI(self):
        self.tab = swing.JPanel()
        layout = swing.GroupLayout(self.tab)
        self.tab.setLayout(layout)

        self.titleLabel = swing.JLabel("DES Plugin")
        self.titleLabel.setFont(Font("Tahoma", 1, 16))
        self.titleLabel.setForeground(Color(135, 206, 250))

        self.infoLabel = swing.JLabel("Please enter the parameters to be decrypted and DES's Key and IV.")
        self.infoLabel.setFont(Font("Tahoma", 0, 12))

        self.keyLabel = swing.JLabel("Des Plugin Params")
        self.keyLabel.setFont(Font("Tahoma", 1, 12))

        self.setKeyTextArea = swing.JTextArea("")
        self.setIVTextArea = swing.JTextArea("")
        self.setParamTextArea = swing.JTextArea("")

        self.setkeyButton = swing.JButton("  setKey   ", actionPerformed=self.setKey)
        self.setIVButton = swing.JButton("   setIV    ", actionPerformed=self.setIV)
        self.setParamButton = swing.JButton("setParam", actionPerformed=self.setParam)

        self.logLabel = swing.JLabel("Log")
        self.logLabel.setFont(Font("Tahoma", 1, 12))

        self.logPane = swing.JScrollPane()
        self.logArea = swing.JTextArea("Logs.\n")
        self.logArea.setLineWrap(True)
        self.logPane.setViewportView(self.logArea)

        self.logClearButton = swing.JButton("   Clear    ", actionPerformed=self.logClear)
        self.getParamsButton = swing.JButton("getParams", actionPerformed=self.getParams)

        self.bar = swing.JSeparator(swing.SwingConstants.HORIZONTAL)
        self.bar2 = swing.JSeparator(swing.SwingConstants.HORIZONTAL)

        # 设置水平布局
        # .addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                          .addGap(15)
                          .addGroup(layout.createParallelGroup()
                                    .addComponent(self.titleLabel)
                                    .addComponent(self.infoLabel)
                                    .addComponent(self.bar)
                                    .addComponent(self.keyLabel)
                                    .addGroup(layout.createSequentialGroup()
                                              .addGroup(layout.createParallelGroup()
                                                        .addComponent(self.setkeyButton)
                                                        .addComponent(self.setIVButton)
                                                        .addComponent(self.setParamButton))
                                              .addGroup(layout.createParallelGroup()
                                                        .addComponent(self.setKeyTextArea,
                                                                      swing.GroupLayout.PREFERRED_SIZE, 300,
                                                                      swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(self.setIVTextArea,
                                                                      swing.GroupLayout.PREFERRED_SIZE, 300,
                                                                      swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(self.setParamTextArea,
                                                                      swing.GroupLayout.PREFERRED_SIZE, 300,
                                                                      swing.GroupLayout.PREFERRED_SIZE))
                                              )
                                    .addComponent(self.bar2)
                                    .addComponent(self.logLabel)
                                    .addGroup(layout.createSequentialGroup()
                                              .addGroup(layout.createParallelGroup()
                                                        .addComponent(self.logClearButton)
                                                        .addComponent(self.getParamsButton)
                                                        )
                                              .addGroup(layout.createParallelGroup()
                                                        .addComponent(self.logPane, swing.GroupLayout.PREFERRED_SIZE,
                                                                      300, swing.GroupLayout.PREFERRED_SIZE)))
                                    ))

        )

        # 设置垂直布局
        layout.setVerticalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                          .addGap(15)
                          .addComponent(self.titleLabel)
                          .addGap(10)
                          .addComponent(self.infoLabel)
                          .addGap(30)
                          .addComponent(self.bar)
                          .addGap(10)
                          .addComponent(self.keyLabel)
                          .addGap(20)
                          .addGroup(layout.createSequentialGroup()
                                    .addGroup(layout.createParallelGroup()
                                              .addGroup(layout.createParallelGroup()
                                                        .addGroup(layout.createSequentialGroup()
                                                                  .addComponent(self.setkeyButton)
                                                                  .addGap(20)
                                                                  .addComponent(self.setIVButton)
                                                                  .addGap(20)
                                                                  .addComponent(self.setParamButton))
                                                        )
                                              .addGroup(layout.createParallelGroup()
                                                        .addGroup(layout.createSequentialGroup()
                                                                  .addComponent(self.setKeyTextArea,
                                                                                swing.GroupLayout.PREFERRED_SIZE, 30,
                                                                                swing.GroupLayout.PREFERRED_SIZE)
                                                                  .addGap(20)
                                                                  .addComponent(self.setIVTextArea,
                                                                                swing.GroupLayout.PREFERRED_SIZE, 30,
                                                                                swing.GroupLayout.PREFERRED_SIZE)
                                                                  .addGap(20)
                                                                  .addComponent(self.setParamTextArea,
                                                                                swing.GroupLayout.PREFERRED_SIZE, 30,
                                                                                swing.GroupLayout.PREFERRED_SIZE))
                                                        )
                                              )
                                    )
                          .addGap(40)
                          .addComponent(self.bar2)
                          .addGap(10)
                          .addComponent(self.logLabel)
                          .addGap(10)
                          .addGroup(layout.createParallelGroup()
                                    .addGroup(layout.createSequentialGroup()
                                              .addComponent(self.getParamsButton)
                                              .addGap(20)
                                              .addComponent(self.logClearButton)

                                              )
                                    .addComponent(self.logPane, swing.GroupLayout.PREFERRED_SIZE, 500,
                                                  swing.GroupLayout.PREFERRED_SIZE))
                          )
        )

    def setKey(self, key):
        global secret_key
        pubText = self.setKeyTextArea.getText().strip('\n')
        if pubText != None and len(pubText) > 0:
            status = False
            try:
                secret_key = str((pubText).encode("utf-8"))
                status = True
            except:
                pass
            self.logPrint(status,'secret_key:' + secret_key)

    def setIV(self, setiv):
        global iv
        pubText = self.setIVTextArea.getText().strip('\n')
        if pubText != None and len(pubText) > 0:
            status = False
            try:
                iv = str((pubText).encode("utf-8"))
                status = True
            except:
                pass
            self.logPrint(status,'iv:' + iv)

    def setParam(self, setparam):
        global param
        pubText = self.setParamTextArea.getText().strip('\n')
        if pubText != None and len(pubText) > 0:
            status = False
            try:
                param = str((pubText).encode("utf-8"))
                status = True
            except:
                pass
            self.logPrint(status,'param:' + param)

    def logClear(self, log):
        self.logArea.setText("")

    def getParams(self,params):
        status = True
        try:
            self.logPrint(status,'secret_key:' + secret_key)
            self.logPrint(status,'iv:' + iv)
            self.logPrint(status,'param:' + param)
        except:
            pass


    def logPrint(self, status, data):
        statusList = ["[!] Failure: ", "[+] Success: "]
        message = statusList[status] + data
        self.logArea.append(message+'\n')


# 实现 IMessageEditorTab
class DataInputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._helpers = extender._helpers
        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)

    # 此方法用于获取自定义标签的标题文本
    def getTabCaption(self):
        return "unCrypto"

    # 调用此方法获取自定义标签页显示的组件
    def getUiComponent(self):
        return self._txtInput.getComponent()

    # 在显示一个新的 HTTP 消息时，启用自定义的标签页
    def isEnabled(self, content, isRequest):
        r = self._helpers.analyzeResponse(content)
        msg = content[r.getBodyOffset():].tostring()
        # enable this tab for requests containing a data parameter
        if isRequest:
            return (isRequest and not self._extender._helpers.getRequestParameter(content, "%s" % (param)) is None)
        elif not isRequest:
            return (not isRequest and not msg is None)

    # 此方法用于将一个 HTTP 消息显示在编辑器中
    def setMessage(self, content, isRequest):
        r = self._helpers.analyzeResponse(content)
        msg = content[r.getBodyOffset():].tostring()
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        else:
            if isRequest:
                parameter = self._extender._helpers.getRequestParameter(content, "%s" % (param))
                a = self._extender._helpers.urlDecode(parameter.getValue())
                b = des_crypto().des_de(a)
                self._txtInput.setText(b)
                self._txtInput.setEditable(self._editable)
            elif not isRequest:
                c = des_crypto().des_de(msg)
                self._txtInput.setText(c)
                self._txtInput.setEditable(self._editable)
        self._currentMessage = content

    # 此方法用于获取当前已显示的消息，此消息可能已被用户修改
    def getMessage(self):
        # 用户是否修改编辑器内容
        if self._txtInput.isTextModified():
            # reserialize the data
            text = self._txtInput.getText()
            # 输入字符串默认转换成burp数组格式,加密需进行格式转换,注意:byte转换成string后无需再次转换回去
            a = self._extender._helpers.bytesToString(text)
            b = des_crypto().des_en(str(a.encode("utf-8")))
            input = self._extender._helpers.urlEncode(b)
            # update the request with the new parameter value
            return self._extender._helpers.updateParameter(self._currentMessage,
                                                           self._extender._helpers.buildParameter("%s" % (param), input,
                                                                                                  IParameter.PARAM_BODY))

        else:
            return self._currentMessage

    # 此方法用于指示用户是否对编辑器的内容做了修改
    def isModified(self):
        return self._txtInput.isTextModified()

    # 直接返回 iTextEditor 中选中的文本
    def getSelectedData(self):
        return self._txtInput.getSelectedText()


# DES加解密脚本
class des_crypto():
    def des_en(self, msg):
        key = des(secret_key, ECB, iv, pad=None, padmode=PAD_PKCS5)
        entrymsg = key.encrypt(msg, padmode=PAD_PKCS5)
        return base64.b64encode(entrymsg).decode('utf-8')

    def des_de(self, msg):
        key = des(secret_key, ECB, iv, pad=None, padmode=PAD_PKCS5)
        desmsg = key.decrypt((base64.b64decode(msg)), padmode=PAD_PKCS5)
        return desmsg.decode('utf-8')
