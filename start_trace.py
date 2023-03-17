import frida
import os
import sys



def read_agent_js_source():
    with open("_agent.js", "r") as f:
        return f.read()

def on_message(message, data):
    print(message)
    pass

def build_agent_js():
    _agent_path = "_agent.js"
    if os.path.exists(_agent_path):
        os.remove(_agent_path)
    os.system("npm run build")
    
    if not os.path.exists(_agent_path):
        raise RuntimeError('frida-compile agent.js error')

def remove_agent_js():
    _agent_path = "_agent.js"
    if os.path.exists(_agent_path):
        os.remove(_agent_path)

if __name__ == "__main__":
    build_agent_js()

    curdir = os.path.dirname(os.path.abspath(sys.argv[0]))
    libQBDI = os.path.join(curdir, "QBDI/libQBDI.so")
    frida_qbdi_js = os.path.join(curdir, "QBDI/frida-qbdi.js")

    device: frida.core.Device = frida.get_usb_device()
    pid = device.get_frontmost_application().pid
    session: frida.core.Session = device.attach(pid)

    script = session.create_script(read_agent_js_source())

    script.on('message', on_message)
    script.load()

    filesdir = script.exports_sync.getfilesdir()
    target_so_path = os.path.join(filesdir, "libQBDI.so")
    if not script.exports_sync.checksoexist(target_so_path):
        with open(libQBDI, "rb") as f:
            so_buffer = f.read()
            script.exports_sync.writelibqbdiso(target_so_path,  list(so_buffer))

    log_path = os.path.join(filesdir, "trace.log")
    script.exports_sync.vmrun(log_path)

    remove_agent_js()