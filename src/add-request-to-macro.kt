package burp

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Klaxon
import com.beust.klaxon.Parser
import java.awt.Frame
import java.net.URL
import javax.swing.JMenuItem
import javax.swing.JOptionPane


class BurpExtender : IBurpExtender, IContextMenuFactory {
    companion object {
        lateinit var cb: IBurpExtenderCallbacks
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        cb = callbacks
        callbacks.setExtensionName("Add Request to Macro")
        callbacks.registerContextMenuFactory(this)
    }

    override fun createMenuItems(invocation: IContextMenuInvocation): List<JMenuItem> {
        if(invocation.selectedMessages.orEmpty().isEmpty()) {
            return emptyList()
        }
        return arrayListOf(JMenuItem("Add request to macro").apply {
            addActionListener({
                try {
                    val selectMacroDialog = SelectMacroDialog(getBurpFrame(), true, invocation)
                    selectMacroDialog.setLocationRelativeTo(getBurpFrame())
                    if(selectMacroDialog.listModel.isEmpty) {
                        JOptionPane.showMessageDialog(getBurpFrame(), "There are no macros defined.", "Add Request to Macro", JOptionPane.WARNING_MESSAGE)
                    }
                    else {
                        selectMacroDialog.isVisible = true
                    }
                }
                catch(ex: Exception) {
                    cb.printError(ex.toString())
                }
            })
        })
    }
}


class Macro(var description: String,
            val serial_number: Long,
            val items: MutableList<MacroItem>)

class MacroItem(val request: String,
                val method: String,
                val response: String,
                val custom_parameters: List<String>,
                val request_parameters: List<String>,
                val url: String,
                val status_code: Int)


fun listMacros(): List<Macro> {
    var configString = BurpExtender.cb.saveConfigAsJson("project_options.sessions.macros.macros")
    var configJson = Parser().parse(StringBuilder(configString)) as JsonObject
    var macrosString = configJson.obj("project_options")?.obj("sessions")?.obj("macros")?.array<JsonObject>("macros")!!.toJsonString()
    return Klaxon().parseArray<Macro>(macrosString) .orEmpty()
}


fun addMacro(invocation: IContextMenuInvocation, macroName: String?) {
    try {
        val macros = listMacros()
        for (macro in macros) {
            if (macro.description == macroName) {
                val msg = invocation.selectedMessages?.get(0)!!
                val requestInfo = BurpExtender.cb.helpers.analyzeRequest(msg.request)
                val path = requestInfo.headers[0].split(" ")[1]
                val url = with(msg.httpService) { URL(protocol, host, port, path) }
                val responseInfo = BurpExtender.cb.helpers.analyzeResponse(msg.response!!)
                macro.items.add(MacroItem(
                        String(msg.request, Charsets.ISO_8859_1),
                        requestInfo.method,
                        String(msg.response!!, Charsets.ISO_8859_1),
                        emptyList(),
                        emptyList(),
                        url.toExternalForm(),
                        responseInfo.statusCode.toInt()))
            }
        }
        val configString = "{\"project_options\":{\"sessions\":{\"macros\":{\"macros\": ${Klaxon().toJsonString(macros)} }}}}"
        BurpExtender.cb.printOutput(configString)
        BurpExtender.cb.loadConfigFromJson(configString)
    }
    catch(ex: Exception) {
        BurpExtender.cb.printError(ex.toString())
    }
}


fun getBurpFrame(): Frame? {
    return Frame.getFrames().firstOrNull { it.isVisible && it.title.startsWith("Burp Suite") }
}
