# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import ITab
from pyDes import des, PAD_PKCS5, ECB
import java.lang as lang
import base64
from javax import swing
from java.awt import Color
from java.awt import Font

# 请求体中待解密参数名称
param = 'name'
# Des加密算法  key,IV
secret_key = 'IuFWKUut'
iv = 'IuFWKUut'


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("unCryptoTest")
        # 初始化UI
        self.TabUI()
        self._callbacks.addSuiteTab(self)

        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

    # 实现IMessageEditorTabFactory方法
    # Burp 将会对每一个 HTTP 消息编辑器调用一次此方法，此工厂必须返回一个新的 IMessageEditorTab 对象
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return DataInputTab(self, controller, editable)

    # 实现Itab接口
    def getTabCaption(self):
        return 'SetName'

    def getUiComponent(self):
        return self.tab

    # 实现新窗口功能与UI
    def TabUI(self):
        self.tab = swing.JPanel()
        self.layout = swing.GroupLayout(self.tab)
        self.tab.setLayout(self.layout)

        self.bar = swing.JSeparator(swing.SwingConstants.HORIZONTAL)

        self.titleLabel = swing.JLabel("DES Plugin")
        self.titleLabel.setFont(Font("Tahoma", 1, 16))
        self.titleLabel.setForeground(Color(235, 136, 0))

        self.infoLabel = swing.JLabel("Please enter the parameters to be decrypted and DES's Key and IV.")
        self.infoLabel.setFont(Font("Tahoma", 0, 12))

        self.keyLabel = swing.JLabel("RSA keys")
        self.keyLabel.setFont(Font("Tahoma", 1, 12))

        self.setkeyButton = swing.JButton("  setKey   ", actionPerformed=self.setKey)
        self.setIVButton = swing.JButton("   setIV    ", actionPerformed=self.setIV)
        self.setParamButton = swing.JButton("setParam", actionPerformed=self.setParam)

        self.setKeyTextArea = swing.JTextArea("")
        self.setIVTextArea = swing.JTextArea("")
        self.setParamTextArea = swing.JTextArea("")

        # 设置水平组
        self.hGroup = self.layout.createSequentialGroup()
        self.hGroup.addGap(15)
        self.hGroup.addGroup(self.layout.createParallelGroup()
                                       .addComponent(self.titleLabel)
                                       .addComponent(self.infoLabel)
                                       .addComponent(self.keyLabel)
                             )
        self.hGroup.addGroup(self.layout.createParallelGroup()
                             .addComponent(self.setkeyButton)
                             .addComponent(self.setIVButton)
                             .addComponent(self.setParamButton)
                             )
        self.hGroup.addGap(100)
        self.hGroup.addGroup(self.layout.createParallelGroup()
                             .addComponent(self.setKeyTextArea, swing.GroupLayout.PREFERRED_SIZE, 200,
                                           swing.GroupLayout.PREFERRED_SIZE)
                             .addComponent(self.setIVTextArea, swing.GroupLayout.PREFERRED_SIZE, 200,
                                           swing.GroupLayout.PREFERRED_SIZE)
                             .addComponent(self.setParamTextArea, swing.GroupLayout.PREFERRED_SIZE, 200,
                                           swing.GroupLayout.PREFERRED_SIZE)
                             .addGap(15)
                             )
        self.layout.setHorizontalGroup(self.hGroup)

        # 设置垂直组
        self.vGroup = self.layout.createSequentialGroup()
        self.vGroup.addGap(15)

        self.vGroup.addGroup(self.layout.createParallelGroup()
                             .addComponent(self.titleLabel)
                             )
        self.vGroup.addGap(15)
        self.vGroup.addGroup(self.layout.createParallelGroup()
                             .addComponent(self.infoLabel)
                             )
        self.vGroup.addGap(15)
        self.vGroup.addGroup(self.layout.createParallelGroup()
                             .addComponent(self.keyLabel)
                             )

        self.vGroup.addGap(15)
        self.vGroup.addGroup(self.layout.createParallelGroup()
                             .addComponent(self.setkeyButton)
                             .addComponent(self.setKeyTextArea, swing.GroupLayout.PREFERRED_SIZE, 40,
                                           swing.GroupLayout.PREFERRED_SIZE)
                             )
        self.vGroup.addGap(15)
        self.vGroup.addGroup(self.layout.createParallelGroup()
                             .addComponent(self.setIVButton)
                             .addComponent(self.setIVTextArea, swing.GroupLayout.PREFERRED_SIZE, 40,
                                           swing.GroupLayout.PREFERRED_SIZE)
                             )
        self.vGroup.addGap(15)
        self.vGroup.addGroup(self.layout.createParallelGroup()
                             .addComponent(self.setParamButton)
                             .addComponent(self.setParamTextArea, swing.GroupLayout.PREFERRED_SIZE, 40,
                                           swing.GroupLayout.PREFERRED_SIZE)
                             )
        self.vGroup.addGap(15)
        self.layout.setVerticalGroup(self.vGroup)

    def setKey(self):
        pass

    def setIV(self):
        pass

    def setParam(self):
        pass


#
# 实现 IMessageEditorTab
#
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
