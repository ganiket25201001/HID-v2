from PySide6.QtWidgets import QApplication
import sys
from ui.main_window import HIDShieldMainWindow
from core.event_bus import event_bus
from core.usb_monitor import USBEventEmitter
import time
from PySide6.QtCore import QTimer

app = QApplication(sys.argv)

monitor = USBEventEmitter()
monitor.start()

window = HIDShieldMainWindow()
window.show()

print('MainWindow launched — cyberpunk theme applied')
print('Waiting 12 seconds for fake USB event...')

start_time = time.time()
while time.time() - start_time < 12:
    app.processEvents()
    time.sleep(0.05)

monitor.stop()
print('Test finished. Close the window when done.')
QTimer.singleShot(500, app.quit)
sys.exit(app.exec())
