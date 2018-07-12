package burp

import org.json.JSONObject
import org.json.JSONTokener
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


fun listMacros(): List<String> {
    val configString = BurpExtender.cb.saveConfigAsJson("project_options.sessions.macros.macros")
    val root = JSONObject(JSONTokener(configString))
    val macros = root.getJSONObject("project_options")
            .getJSONObject("sessions")
            .getJSONObject("macros")
            .getJSONArray("macros")

    val rc = mutableListOf<String>()
    for(i in 0 until macros.length()) {
        rc.add(macros.getJSONObject(i).getString("description"))
    }

    return rc
}


fun addMacro(invocation: IContextMenuInvocation, macroName: String?) {
    try {
        var configString = BurpExtender.cb.saveConfigAsJson("project_options.sessions.macros.macros")
        val root = JSONObject(JSONTokener(configString))
        val macros = root.getJSONObject("project_options")
                .getJSONObject("sessions")
                .getJSONObject("macros")
                .getJSONArray("macros")

        for(i in 0 until macros.length()) {
            val macro = macros.getJSONObject(i)

            if (macro.getString("description") == macroName) {
                val msg = invocation.selectedMessages?.get(0)!!
                val requestInfo = BurpExtender.cb.helpers.analyzeRequest(msg.request)
                val path = requestInfo.headers[0].split(" ")[1]
                val url = with(msg.httpService) { URL(protocol, host, port, path) }
                val responseInfo = BurpExtender.cb.helpers.analyzeResponse(msg.response!!)

                val macroItem = JSONObject()
                macroItem.put("request", String(msg.request, Charsets.ISO_8859_1))
                macroItem.put("method", requestInfo.method)
                macroItem.put("response", String(msg.response!!, Charsets.ISO_8859_1))
                macroItem.put("url", url.toExternalForm())
                macroItem.put("status_code", responseInfo.statusCode.toInt())

                macro.getJSONArray("items").put(macroItem)
            }
        }

        BurpExtender.cb.loadConfigFromJson(root.toString(4))
    }
    catch(ex: Exception) {
        BurpExtender.cb.printError(ex.toString())
    }
}


fun getBurpFrame(): Frame? {
    return Frame.getFrames().firstOrNull { it.isVisible && it.title.startsWith("Burp Suite") }
}
